package main

import (
	"fmt"
	"log"
	"strconv"
)

type tproxySysctl struct {
	name  string
	value string
}

var xrayTProxyExcludedCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

func setupXrayTProxy(wgIface string, port, mark, table int) (func(), error) {
	if !commandExists("iptables") || !commandExists("ip") {
		return func() {}, fmt.Errorf("Xray TProxy requires iptables and ip commands")
	}
	extIface := getDefaultInterface()
	sysctls := []tproxySysctl{
		{name: "net.ipv4.ip_forward"},
		{name: "net.ipv4.conf.all.src_valid_mark"},
		{name: "net.ipv4.conf." + wgIface + ".rp_filter"},
	}
	for i := range sysctls {
		value, err := runCmd("sysctl", "-n", sysctls[i].name)
		if err != nil {
			_ = setupFullConeNAT(wgIface)
			return func() {}, fmt.Errorf("read sysctl %s: %w", sysctls[i].name, err)
		}
		sysctls[i].value = value
	}
	if _, err := runCmd("iptables", "-t", "mangle", "-N", tproxyChainName(mark)); err != nil {
		return func() {}, fmt.Errorf("create managed TProxy chain: %w", err)
	}
	for _, setting := range []string{
		"net.ipv4.ip_forward=1",
		"net.ipv4.conf.all.src_valid_mark=1",
		"net.ipv4.conf." + wgIface + ".rp_filter=0",
	} {
		if _, err := runCmd("sysctl", "-w", setting); err != nil {
			removeXrayTProxyChain(tproxyChainName(mark))
			restoreTProxySysctls(sysctls)
			_ = setupFullConeNAT(wgIface)
			return func() {}, fmt.Errorf("set sysctl %s: %w", setting, err)
		}
	}

	markValue := strconv.Itoa(mark)
	markMask := markValue + "/0xffff"
	tableValue := strconv.Itoa(table)
	chain := tproxyChainName(mark)
	removeManagedWGNAT(extIface)
	if _, err := runCmd("ip", "rule", "add", "fwmark", markMask, "table", tableValue); err != nil {
		removeXrayTProxyChain(chain)
		restoreTProxySysctls(sysctls)
		_ = setupFullConeNAT(wgIface)
		return func() {}, fmt.Errorf("add TProxy policy rule: %w", err)
	}
	if _, err := runCmd("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", tableValue); err != nil {
		_ = runCmdSilent("ip", "rule", "del", "fwmark", markMask, "table", tableValue)
		removeXrayTProxyChain(chain)
		restoreTProxySysctls(sysctls)
		_ = setupFullConeNAT(wgIface)
		return func() {}, fmt.Errorf("add TProxy local route: %w", err)
	}

	for _, cidr := range append(append([]string(nil), xrayTProxyExcludedCIDRs...), wgServerCIDR) {
		if _, err := runCmd("iptables", "-t", "mangle", "-A", chain, "-d", cidr, "-j", "RETURN"); err != nil {
			cleanupXrayTProxy(wgIface, chain, markMask, tableValue, sysctls, extIface)
			return func() {}, fmt.Errorf("add TProxy network exclusion %s: %w", cidr, err)
		}
	}
	for _, protocol := range []string{"tcp", "udp"} {
		args := []string{"-t", "mangle", "-A", chain, "-p", protocol, "-j", "TPROXY", "--on-port", strconv.Itoa(port), "--tproxy-mark", markMask}
		if _, err := runCmd("iptables", args...); err != nil {
			cleanupXrayTProxy(wgIface, chain, markMask, tableValue, sysctls, extIface)
			return func() {}, fmt.Errorf("add TProxy %s rule: %w", protocol, err)
		}
	}
	if _, err := runCmd("iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-i", wgIface, "-j", chain); err != nil {
		cleanupXrayTProxy(wgIface, chain, markMask, tableValue, sysctls, extIface)
		return func() {}, fmt.Errorf("attach TProxy chain: %w", err)
	}

	log.Printf("[XRAY] TProxy: %s -> 127.0.0.1:%d, mark=%s, table=%s", wgIface, port, markValue, tableValue)
	return func() {
		cleanupXrayTProxy(wgIface, chain, markMask, tableValue, sysctls, extIface)
	}, nil
}

func cleanupXrayTProxy(wgIface, chain, markMask, tableValue string, sysctls []tproxySysctl, extIface string) {
	_ = runCmdSilent("iptables", "-t", "mangle", "-D", "PREROUTING", "-i", wgIface, "-j", chain)
	removeXrayTProxyChain(chain)
	_ = runCmdSilent("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", tableValue)
	_ = runCmdSilent("ip", "rule", "del", "fwmark", markMask, "table", tableValue)
	restoreTProxySysctls(sysctls)
	if extIface != "" {
		_ = setupFullConeNAT(wgIface)
	}
}

func removeXrayTProxyChain(chain string) {
	_ = runCmdSilent("iptables", "-t", "mangle", "-F", chain)
	_ = runCmdSilent("iptables", "-t", "mangle", "-X", chain)
}

func tproxyChainName(mark int) string {
	return fmt.Sprintf("QWDT_XRAY_%X", mark)
}

func restoreTProxySysctls(sysctls []tproxySysctl) {
	for _, sysctl := range sysctls {
		if sysctl.value != "" {
			_ = runCmdSilent("sysctl", "-w", sysctl.name+"="+sysctl.value)
		}
	}
}
