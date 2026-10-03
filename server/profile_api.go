package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// ==================== HTTP Control API ====================

func unbindDevices(entry *PasswordEntry, targetDeviceID string) {
	if targetDeviceID == "" {
		if entry.DeviceID != "" {
			removeDeviceFromSystem(entry.DeviceID)
			entry.DeviceID = ""
		}
		for _, id := range entry.DeviceIDs {
			removeDeviceFromSystem(id)
		}
		entry.DeviceIDs = nil
	} else {
		if entry.DeviceID == targetDeviceID {
			removeDeviceFromSystem(targetDeviceID)
			entry.DeviceID = ""
		}
		newIDs := []string{}
		for _, id := range entry.DeviceIDs {
			if id == targetDeviceID {
				removeDeviceFromSystem(id)
			} else {
				newIDs = append(newIDs, id)
			}
		}
		entry.DeviceIDs = newIDs
		if len(entry.DeviceIDs) == 1 {
			entry.DeviceID = entry.DeviceIDs[0]
		} else if len(entry.DeviceIDs) > 1 {
			entry.DeviceID = "multi"
		}
	}
}

func removeDeviceFromSystem(devID string) {
	dev, exists := db.Devices[devID]
	if !exists {
		return
	}
	delete(db.Devices, devID)
	if globalWgDev != nil {
		pubHex, _ := b64ToHex(dev.PubKey)
		globalWgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
	}
}

var profileChallenges = struct {
	sync.Mutex
	items   map[string]time.Time
	buckets map[string]profileChallengeBucket
}{items: make(map[string]time.Time), buckets: make(map[string]profileChallengeBucket)}

const (
	profileChallengeRatePerSecond = 250
	profileChallengeBurst         = 1000
	profileChallengeMaxEntries    = 32768
	profileChallengeMaxBuckets    = 65536
	profileChallengeTTL           = time.Minute
	profileChallengeBucketTTL     = 2 * time.Minute
)

type profileChallengeBucket struct {
	tokens    float64
	updatedAt time.Time
}

func allowProfileChallenge(host string, now time.Time) bool {
	if host == "" {
		host = "unknown"
	}

	profileChallenges.Lock()
	defer profileChallenges.Unlock()

	bucket, exists := profileChallenges.buckets[host]
	if !exists {
		if len(profileChallenges.buckets) >= profileChallengeMaxBuckets {
			for staleHost, staleBucket := range profileChallenges.buckets {
				if now.Sub(staleBucket.updatedAt) > profileChallengeBucketTTL {
					delete(profileChallenges.buckets, staleHost)
				}
			}
			if len(profileChallenges.buckets) >= profileChallengeMaxBuckets {
				return false
			}
		}
		bucket = profileChallengeBucket{tokens: profileChallengeBurst, updatedAt: now}
	} else {
		elapsed := now.Sub(bucket.updatedAt).Seconds()
		if elapsed > 0 {
			bucket.tokens = min(float64(profileChallengeBurst), bucket.tokens+elapsed*profileChallengeRatePerSecond)
		}
		bucket.updatedAt = now
	}

	if bucket.tokens < 1 {
		profileChallenges.buckets[host] = bucket
		return false
	}
	bucket.tokens--
	profileChallenges.buckets[host] = bucket
	return true
}

func cleanupProfileChallengeState(now time.Time) {
	profileChallenges.Lock()
	for nonce, expires := range profileChallenges.items {
		if !expires.After(now) {
			delete(profileChallenges.items, nonce)
		}
	}
	for host, bucket := range profileChallenges.buckets {
		if now.Sub(bucket.updatedAt) > profileChallengeBucketTTL {
			delete(profileChallenges.buckets, host)
		}
	}
	profileChallenges.Unlock()
}

func profileChallengeJanitor(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			cleanupProfileChallengeState(now)
		}
	}
}

func handleAPIProfileChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := time.Now()
	if !allowProfileChallenge(host, now) {
		http.Error(w, `{"error":"Too many requests"}`, http.StatusTooManyRequests)
		return
	}
	profileChallenges.Lock()
	if len(profileChallenges.items) >= profileChallengeMaxEntries {
		profileChallenges.Unlock()
		http.Error(w, `{"error":"Too many requests"}`, http.StatusTooManyRequests)
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		profileChallenges.Unlock()
		http.Error(w, `{"error":"Internal error"}`, http.StatusInternalServerError)
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)
	profileChallenges.items[nonce] = now.Add(profileChallengeTTL)
	profileChallenges.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})
}

func profileKeyID(password string) string {
	sum := sha256.Sum256([]byte("WDTT-PROFILE-ID-v1\x00" + password))
	return hex.EncodeToString(sum[:])
}

func authenticateProfileRequest(r *http.Request, action string) (string, string, bool) {
	deviceID := r.FormValue("device_id")
	nonce := r.FormValue("nonce")
	keyID := r.FormValue("key_id")
	proof, err := hex.DecodeString(r.FormValue("proof"))
	if (deviceID == "" && action != "unbind") || nonce == "" || keyID == "" || err != nil || len(proof) != sha256.Size {
		return "", "", false
	}
	now := time.Now()
	profileChallenges.Lock()
	expires, exists := profileChallenges.items[nonce]
	profileChallenges.Unlock()
	if !exists || !expires.After(now) {
		return "", "", false
	}
	password, indexed := serverWrapKeys.ProfilePassword(keyID)
	if !indexed {
		return "", "", false
	}

	dbMutex.Lock()
	defer dbMutex.Unlock()
	entry, exists := db.Passwords[password]
	if !exists || isPasswordExpired(entry) || entry.IsDeactivated {
		return "", "", false
	}
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte(action + "\n" + deviceID + "\n" + nonce))
	if !hmac.Equal(proof, mac.Sum(nil)) {
		return "", "", false
	}
	profileChallenges.Lock()
	currentExpiry, stillExists := profileChallenges.items[nonce]
	if stillExists && currentExpiry.After(time.Now()) {
		delete(profileChallenges.items, nonce)
	}
	profileChallenges.Unlock()
	if !stillExists || !currentExpiry.After(time.Now()) {
		return "", "", false
	}
	return password, deviceID, true
}

func handleAPIProfileStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	password, deviceID, valid := authenticateProfileRequest(r, "status")
	if !valid {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	dbMutex.Lock()
	defer dbMutex.Unlock()
	entry, exists := db.Passwords[password]
	if !exists || isPasswordExpired(entry) || entry.IsDeactivated {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	maxDevs := entry.MaxDevices
	if maxDevs <= 0 {
		maxDevs = 1
	}

	boundDevices := len(entry.DeviceIDs)
	if boundDevices == 0 && entry.DeviceID != "" {
		boundDevices = 1
	}

	isCurrentBound := false

	activeCount := 0
	activeDevicesMu.Lock()
	if len(entry.DeviceIDs) == 0 && entry.DeviceID != "" {
		if entry.DeviceID == deviceID {
			isCurrentBound = true
		}
		if count := activeDevices[entry.DeviceID]; count > 0 {
			activeCount = 1
		}
	} else {
		for _, id := range entry.DeviceIDs {
			if id == deviceID {
				isCurrentBound = true
			}
			if count := activeDevices[id]; count > 0 {
				activeCount++
			}
		}
	}
	activeDevicesMu.Unlock()

	resp := map[string]interface{}{
		"max_devices":      maxDevs,
		"bound_devices":    boundDevices,
		"active_devices":   activeCount,
		"is_current_bound": isCurrentBound,
		"expires_at":       entry.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleAPIProfileUnbind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	password, deviceID, valid := authenticateProfileRequest(r, "unbind")
	if !valid {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	dbMutex.Lock()
	defer dbMutex.Unlock()
	entry, exists := db.Passwords[password]
	if !exists || isPasswordExpired(entry) || entry.IsDeactivated {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	entryBefore := clonePasswordEntry(entry)
	deviceIDsBefore := entryDeviceIDs(entry)
	removedDevices := make(map[string]*ClientDevice)
	for _, id := range deviceIDsBefore {
		if deviceID == "" || id == deviceID {
			if dev, exists := db.Devices[id]; exists {
				removedDevices[id] = dev
			}
		}
	}
	unbindDevices(entry, deviceID)
	if err := saveDB(); err != nil {
		*entry = *entryBefore
		for id, dev := range removedDevices {
			db.Devices[id] = dev
			upsertPeerInWG(globalWgDev, dev)
		}
		http.Error(w, `{"error":"Failed to persist device unbind"}`, http.StatusInternalServerError)
		return
	}
	disconnectCredentialDeviceConnections(password, deviceID)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}
