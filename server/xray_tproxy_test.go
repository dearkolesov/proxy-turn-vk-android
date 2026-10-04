package main

import (
	"reflect"
	"testing"
)

func TestTProxyChainName(t *testing.T) {
	if got, want := tproxyChainName(1), "QWDT_XRAY_1"; got != want {
		t.Fatalf("chain name = %q, want %q", got, want)
	}
}

func TestTProxyExcludesNonPublicDestinations(t *testing.T) {
	want := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
		"224.0.0.0/4", "240.0.0.0/4",
	}
	if !reflect.DeepEqual(xrayTProxyExcludedCIDRs, want) {
		t.Fatalf("excluded CIDRs = %#v", xrayTProxyExcludedCIDRs)
	}
}
