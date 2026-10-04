package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ==================== Статистика ====================

var (
	totalBytesFromClient int64
	totalBytesToClient   int64
	activeConns          int32
	totalConns           int64
	natType              string = "Инициализация..."
	serverStartTime             = time.Now()
	lastWGStats                 = make(map[string]struct{ rx, tx int64 })
)

// rawDeviceTraffic — per-device счётчики трафика raw-режима, копятся в
// памяти atomic'ами на горячем пути (каждый uplink/downlink пакет) и
// периодически сбрасываются в db.Devices/db.Passwords в statsLoop под
// dbMutex — так же, как updateTrafficFromWG делает для WireGuard. Прямая
// запись в БД на каждый пакет была бы недопустимо дорогой (db-мьютекс на
// тысячи pps от 380+ клиентов), а глобальные totalBytesFromClient/
// totalBytesToClient раньше не разбивались по устройствам вообще — Raw-
// трафик не попадал ни в бота, ни в /api/profile/status.
type rawTrafficCounter struct {
	up   int64
	down int64
}

var (
	rawDeviceTrafficMu sync.Mutex
	rawDeviceTraffic   = make(map[string]*rawTrafficCounter)
)

func addRawUplinkBytes(deviceID string, n int64) {
	if deviceID == "" || deviceID == "unknown" {
		return
	}
	rawDeviceTrafficMu.Lock()
	c := rawDeviceTraffic[deviceID]
	if c == nil {
		c = &rawTrafficCounter{}
		rawDeviceTraffic[deviceID] = c
	}
	c.up += n
	rawDeviceTrafficMu.Unlock()
}

func addRawDownlinkBytes(deviceID string, n int64) {
	if deviceID == "" || deviceID == "unknown" {
		return
	}
	rawDeviceTrafficMu.Lock()
	c := rawDeviceTraffic[deviceID]
	if c == nil {
		c = &rawTrafficCounter{}
		rawDeviceTraffic[deviceID] = c
	}
	c.down += n
	rawDeviceTrafficMu.Unlock()
}

func trafficLimitReached(entry *PasswordEntry) bool {
	return entry != nil && entry.TrafficLimit > 0 && entry.UpBytes+entry.DownBytes >= entry.TrafficLimit
}

func limitedPasswordsLocked() []string {
	limited := make([]string, 0)
	for password, entry := range db.Passwords {
		if trafficLimitReached(entry) {
			limited = append(limited, password)
		}
	}
	return limited
}

func resetRawTrafficCounters(deviceIDs []string) {
	set := make(map[string]struct{}, len(deviceIDs))
	for _, deviceID := range deviceIDs {
		set[deviceID] = struct{}{}
	}
	rawDeviceTrafficMu.Lock()
	for deviceID := range set {
		delete(rawDeviceTraffic, deviceID)
	}
	rawDeviceTrafficMu.Unlock()
}

func resetWGTrafficBaselinesLocked(deviceIDs []string) {
	if globalWgDev == nil {
		return
	}
	set := make(map[string]struct{}, len(deviceIDs))
	for _, deviceID := range deviceIDs {
		set[deviceID] = struct{}{}
	}
	devicesByPublicKey := make(map[string]string, len(set))
	for deviceID := range set {
		if device := db.Devices[deviceID]; device != nil {
			if publicKey, err := b64ToHex(device.PubKey); err == nil {
				devicesByPublicKey[publicKey] = deviceID
			}
		}
	}
	ipcOut, err := globalWgDev.IpcGet()
	if err != nil {
		return
	}
	var publicKey string
	var rx, tx int64
	for _, line := range strings.Split(ipcOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "public_key=") {
			if _, ok := devicesByPublicKey[publicKey]; ok {
				lastWGStats[publicKey] = struct{ rx, tx int64 }{rx, tx}
			}
			publicKey = strings.TrimPrefix(line, "public_key=")
			rx, tx = 0, 0
		} else if strings.HasPrefix(line, "rx_bytes=") {
			fmt.Sscanf(line, "rx_bytes=%d", &rx)
		} else if strings.HasPrefix(line, "tx_bytes=") {
			fmt.Sscanf(line, "tx_bytes=%d", &tx)
		}
	}
	if _, ok := devicesByPublicKey[publicKey]; ok {
		lastWGStats[publicKey] = struct{ rx, tx int64 }{rx, tx}
	}
}

// flushRawDeviceTraffic переносит накопленные с прошлого вызова байты в
// db.Devices/db.Passwords (вызывающий должен держать dbMutex — см. вызов в
// statsLoop, тот же паттерн, что updateTrafficFromWG под тем же локом).
func flushRawDeviceTrafficLocked() {
	rawDeviceTrafficMu.Lock()
	if len(rawDeviceTraffic) == 0 {
		rawDeviceTrafficMu.Unlock()
		return
	}
	snapshot := rawDeviceTraffic
	rawDeviceTraffic = make(map[string]*rawTrafficCounter)
	rawDeviceTrafficMu.Unlock()

	for deviceID, c := range snapshot {
		if c.up == 0 && c.down == 0 {
			continue
		}
		if dev, ok := db.Devices[deviceID]; ok {
			dev.UpBytes += c.up
			dev.DownBytes += c.down
			if entry := generatedOwnerEntryLocked(dev, deviceID); entry != nil {
				entry.UpBytes += c.up
				entry.DownBytes += c.down
			}
		}
	}
}

func updateTrafficFromWG() {
	if globalWgDev == nil {
		return
	}
	ipcOut, err := globalWgDev.IpcGet()
	if err != nil {
		return
	}

	dbMutex.Lock()
	defer dbMutex.Unlock()

	type peerDevice struct {
		id     string
		device *ClientDevice
	}
	devicesByPublicKey := make(map[string]peerDevice, len(db.Devices))
	for devID, dev := range db.Devices {
		pub, decodeErr := b64ToHex(dev.PubKey)
		if decodeErr == nil {
			devicesByPublicKey[pub] = peerDevice{id: devID, device: dev}
		}
	}
	seenPeers := make(map[string]struct{}, len(lastWGStats))

	var currentPub string
	var rx, tx int64

	processPeer := func(pub string, currentRx, currentTx int64) {
		if pub == "" {
			return
		}
		seenPeers[pub] = struct{}{}
		last := lastWGStats[pub]
		deltaRx := currentRx - last.rx
		deltaTx := currentTx - last.tx
		if deltaRx < 0 || deltaTx < 0 {
			deltaRx = currentRx
			deltaTx = currentTx
		}
		lastWGStats[pub] = struct{ rx, tx int64 }{currentRx, currentTx}

		if deltaRx == 0 && deltaTx == 0 {
			return
		}

		target, exists := devicesByPublicKey[pub]
		if !exists {
			return
		}
		target.device.UpBytes += deltaRx
		target.device.DownBytes += deltaTx
		entry := generatedOwnerEntryLocked(target.device, target.id)
		if entry != nil {
			entry.UpBytes += deltaRx
			entry.DownBytes += deltaTx
		}

		if entry == nil {
			atomic.AddInt64(&mainPassUp, deltaRx)
			atomic.AddInt64(&mainPassDown, deltaTx)
		}
	}

	for _, line := range strings.Split(ipcOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "public_key=") {
			processPeer(currentPub, rx, tx)
			currentPub = strings.TrimPrefix(line, "public_key=")
			rx, tx = 0, 0
		} else if strings.HasPrefix(line, "rx_bytes=") {
			fmt.Sscanf(line, "rx_bytes=%d", &rx)
		} else if strings.HasPrefix(line, "tx_bytes=") {
			fmt.Sscanf(line, "tx_bytes=%d", &tx)
		}
	}
	processPeer(currentPub, rx, tx)
	for pub := range lastWGStats {
		if _, exists := seenPeers[pub]; !exists {
			delete(lastWGStats, pub)
		}
	}
}

func statsLoop(ctx context.Context, configDir string) {
	statsFile := filepath.Join(configDir, "server.log")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	saveTicks := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updateTrafficFromWG()
			fromC := atomic.LoadInt64(&totalBytesFromClient)
			toC := atomic.LoadInt64(&totalBytesToClient)
			active := atomic.LoadInt32(&activeConns)
			total := atomic.LoadInt64(&totalConns)
			uptime := time.Since(serverStartTime)

			log.Printf("[СТАТ] Активных: %d | Всего: %d | NAT: %s | ↑%.2f МБ | ↓%.2f МБ",
				active, total, natType,
				float64(fromC)/1024/1024,
				float64(toC)/1024/1024,
			)

			// Пишем server.log и периодически сохраняем БД на диск
			dbMutex.Lock()
			flushRawDeviceTrafficLocked()
			numPasswords := len(db.Passwords)
			numDevices := len(db.Devices)
			limited := limitedPasswordsLocked()
			saveTicks++
			if saveTicks >= 6 { // 6 * 10 секунд = 60 секунд
				saveTicks = 0
				saveDB()
			}
			dbMutex.Unlock()
			for _, password := range limited {
				disconnectCredentialConnections(password)
			}

			uptimeStr := formatUptime(uptime)
			downGB := float64(toC) / (1024 * 1024 * 1024)
			upGB := float64(fromC) / (1024 * 1024 * 1024)

			statsJSON, _ := json.Marshal(map[string]interface{}{
				"active":    active,
				"total":     total,
				"nat":       natType,
				"uptime":    uptimeStr,
				"down_gb":   fmt.Sprintf("%.2f", downGB),
				"up_gb":     fmt.Sprintf("%.2f", upGB),
				"passwords": numPasswords,
				"devices":   numDevices,
				"timestamp": time.Now().Unix(),
			})
			os.WriteFile(statsFile, statsJSON, 0644)
		}
	}
}

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dд %dч %dм", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dч %dм", hours, mins)
	}
	return fmt.Sprintf("%dм", mins)
}
