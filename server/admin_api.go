package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

type createPasswordFingerprint struct {
	VkHash       string `json:"vk_hash"`
	Days         int    `json:"days"`
	MaxDevices   int    `json:"max_devices"`
	TrafficLimit int64  `json:"traffic_limit_bytes"`
	Ports        string `json:"ports"`
	Label        string `json:"label"`
}

func parseTrafficLimit(value string) (int64, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	limit, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || limit < 0 {
		return 0, fmt.Errorf("traffic_limit_bytes must be a non-negative integer")
	}
	return limit, nil
}

func fingerprintCreatePassword(request createPasswordFingerprint) string {
	data, _ := json.Marshal(request)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:])
}

func passwordFingerprint(password string) string {
	hash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", hash[:])
}

func splitVKHashes(value string) []string {
	linkMatches := vkJoinLinkPattern.FindAllStringSubmatch(value, -1)
	if len(linkMatches) > 0 {
		seen := make(map[string]struct{}, len(linkMatches))
		hashes := make([]string, 0, len(linkMatches))
		for _, match := range linkMatches {
			if len(match) < 2 || match[1] == "" {
				continue
			}
			if _, exists := seen[match[1]]; exists {
				continue
			}
			seen[match[1]] = struct{}{}
			hashes = append(hashes, match[1])
		}
		return hashes
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	seen := make(map[string]struct{}, len(parts))
	hashes := make([]string, 0, len(parts))
	for _, part := range parts {
		hash := strings.TrimSpace(part)
		if hash == "" {
			continue
		}
		if _, exists := seen[hash]; exists {
			continue
		}
		seen[hash] = struct{}{}
		hashes = append(hashes, hash)
	}
	return hashes
}

var vkJoinLinkPattern = regexp.MustCompile(`(?i)(?:https?://)?(?:www\.|m\.)?(?:vk\.com|vk\.ru)/call/join/([A-Za-z0-9_-]+)`)

func mergeVKHashes(existing []string, additions []string) []string {
	merged := splitVKHashes(strings.Join(existing, ","))
	seen := make(map[string]struct{}, len(merged)+len(additions))
	for _, hash := range merged {
		seen[hash] = struct{}{}
	}
	for _, hash := range additions {
		if hash == "" {
			continue
		}
		if _, exists := seen[hash]; exists {
			continue
		}
		seen[hash] = struct{}{}
		merged = append(merged, hash)
	}
	return merged
}

func cleanupCreateRequestsLocked(now time.Time) {
	for key, record := range db.CreateRequests {
		if now.Sub(time.Unix(record.CreatedAt, 0)) > createRequestRetention {
			delete(db.CreateRequests, key)
		}
	}
}

var adminTokenHash [32]byte
var adminTokenReady bool
var adminTokenMu sync.RWMutex

type adminAuthAttempt struct {
	count       int
	windowStart time.Time
	blockedTill time.Time
}

var adminAuthMu sync.Mutex
var adminAuthAttempts = map[string]adminAuthAttempt{}

func setAdminAPIToken(token string) {
	adminTokenMu.Lock()
	adminTokenHash = sha256.Sum256([]byte(token))
	adminTokenReady = token != ""
	adminTokenMu.Unlock()
}

func adminAuthorized(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := time.Now()
	adminAuthMu.Lock()
	attempt := adminAuthAttempts[host]
	if now.Before(attempt.blockedTill) {
		adminAuthMu.Unlock()
		return false
	}
	adminAuthMu.Unlock()

	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		recordAdminAuthFailure(host, now)
		return false
	}
	tokenHash := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))))
	adminTokenMu.RLock()
	ready := adminTokenReady
	expected := adminTokenHash
	adminTokenMu.RUnlock()
	if !ready || subtle.ConstantTimeCompare(tokenHash[:], expected[:]) != 1 {
		recordAdminAuthFailure(host, now)
		return false
	}
	adminAuthMu.Lock()
	delete(adminAuthAttempts, host)
	adminAuthMu.Unlock()
	return true
}

func recordAdminAuthFailure(host string, now time.Time) {
	adminAuthMu.Lock()
	for address, existing := range adminAuthAttempts {
		if now.Sub(existing.windowStart) > 10*time.Minute && now.After(existing.blockedTill) {
			delete(adminAuthAttempts, address)
		}
	}
	attempt := adminAuthAttempts[host]
	if attempt.windowStart.IsZero() || now.Sub(attempt.windowStart) > time.Minute {
		attempt = adminAuthAttempt{windowStart: now}
	}
	attempt.count++
	if attempt.count >= 5 {
		attempt.blockedTill = now.Add(5 * time.Minute)
	}
	adminAuthAttempts[host] = attempt
	adminAuthMu.Unlock()
}

func writeAdminJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	writeAdminJSON(w, status, map[string]string{"error": msg})
}

func setAdminCORSHeaders(w http.ResponseWriter, methods string) {
	w.Header().Set("Access-Control-Allow-Methods", methods+", OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Idempotency-Key")
	w.Header().Set("Cache-Control", "no-store")
}

type adminPasswordView struct {
	Password      string   `json:"password"`
	Label         string   `json:"label"`
	VkHash        string   `json:"vk_hash"`
	Ports         string   `json:"ports"`
	MaxDevices    int      `json:"max_devices"`
	DeviceIDs     []string `json:"device_ids"`
	ExpiresAt     int64    `json:"expires_at"`
	IsDeactivated bool     `json:"is_deactivated"`
	DownBytes     int64    `json:"down_bytes"`
	UpBytes       int64    `json:"up_bytes"`
	TrafficLimit  int64    `json:"traffic_limit_bytes,omitempty"`
	ActiveDevices int      `json:"active_devices"`
}

func toAdminPasswordView(pass string, entry *PasswordEntry) adminPasswordView {
	view := buildAdminPasswordView(pass, entry)
	active, err := countActiveDevices(view.DeviceIDs)
	if err != nil {
		log.Printf("[ADMIN API] Failed to read active-device count: %v", err)
		active = 0
	}
	view.ActiveDevices = active
	return view
}

func buildAdminPasswordView(pass string, entry *PasswordEntry) adminPasswordView {
	deviceIDs := entry.DeviceIDs
	if len(deviceIDs) == 0 && entry.DeviceID != "" {
		deviceIDs = []string{entry.DeviceID}
	} else {
		deviceIDs = append([]string(nil), deviceIDs...)
	}
	maxDevs := entry.MaxDevices
	if maxDevs <= 0 {
		maxDevs = 1
	}

	return adminPasswordView{
		Password:      pass,
		Label:         entry.Label,
		VkHash:        entry.VkHash,
		Ports:         entry.Ports,
		MaxDevices:    maxDevs,
		DeviceIDs:     deviceIDs,
		ExpiresAt:     entry.ExpiresAt,
		IsDeactivated: entry.IsDeactivated,
		DownBytes:     entry.DownBytes,
		UpBytes:       entry.UpBytes,
		TrafficLimit:  entry.TrafficLimit,
		ActiveDevices: 0,
	}
}

func toAdminPasswordViewWithActiveSet(pass string, entry *PasswordEntry, activeSet map[string]struct{}) adminPasswordView {
	view := buildAdminPasswordView(pass, entry)
	view.ActiveDevices = 0
	for _, id := range view.DeviceIDs {
		if _, active := activeSet[id]; active {
			view.ActiveDevices++
		}
	}
	return view
}

// GET /admin/passwords — список всех сгенерированных паролей
func handleAdminListPasswords(w http.ResponseWriter, r *http.Request) {
	setAdminCORSHeaders(w, "GET")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	dbMutex.Lock()
	if globalWgDev != nil && cleanupExpiredPasswordsLocked(globalWgDev) > 0 {
		if err := saveDB(); err != nil {
			dbMutex.Unlock()
			writeAdminError(w, http.StatusInternalServerError, "failed to persist expired-password cleanup")
			return
		}
	}
	views := make([]adminPasswordView, 0, len(db.Passwords))
	allDeviceIDs := make([]string, 0, len(db.Devices))
	for pass, entry := range db.Passwords {
		if entry == nil {
			continue
		}
		deviceIDs := entryDeviceIDs(entry)
		allDeviceIDs = append(allDeviceIDs, deviceIDs...)
		views = append(views, toAdminPasswordViewWithActiveSet(pass, entry, nil))
	}
	dbMutex.Unlock()
	activeSet, err := activeDeviceSet(allDeviceIDs)
	if err != nil {
		writeAdminError(w, http.StatusServiceUnavailable, "active-device status unavailable")
		return
	}
	for i := range views {
		views[i].ActiveDevices = 0
		for _, deviceID := range views[i].DeviceIDs {
			if _, active := activeSet[deviceID]; active {
				views[i].ActiveDevices++
			}
		}
	}

	writeAdminJSON(w, http.StatusOK, map[string]interface{}{"passwords": views})
}

// POST /admin/passwords — создать новый пароль
// Form: vk_hash (required), days (optional, default 30), max_devices (optional, default 1),
// traffic_limit_bytes (optional, 0 = unlimited), ports (optional), label (optional).
func handleAdminCreatePassword(w http.ResponseWriter, r *http.Request) {
	setAdminCORSHeaders(w, "POST")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	vkHash := r.FormValue("vk_hash")
	if vkHash == "" {
		writeAdminError(w, http.StatusBadRequest, "vk_hash is required")
		return
	}
	days := 30
	if v := r.FormValue("days"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 1 || parsed > 365 {
			writeAdminError(w, http.StatusBadRequest, "days must be between 1 and 365")
			return
		}
		days = parsed
	}
	maxDevices := 1
	if v := r.FormValue("max_devices"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 1 {
			writeAdminError(w, http.StatusBadRequest, "max_devices must be a positive number")
			return
		}
		maxDevices = parsed
	}
	trafficLimit, err := parseTrafficLimit(r.FormValue("traffic_limit_bytes"))
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, err.Error())
		return
	}
	ports := r.FormValue("ports")
	label := r.FormValue("label")
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if len(idempotencyKey) > 200 {
		writeAdminError(w, http.StatusBadRequest, "Idempotency-Key must be at most 200 bytes")
		return
	}
	requestHash := fingerprintCreatePassword(createPasswordFingerprint{
		VkHash:       vkHash,
		Days:         days,
		MaxDevices:   maxDevices,
		TrafficLimit: trafficLimit,
		Ports:        ports,
		Label:        label,
	})
	idempotencyHash := ""
	if idempotencyKey != "" {
		hash := sha256.Sum256([]byte(idempotencyKey))
		idempotencyHash = fmt.Sprintf("%x", hash[:])
	}

	dbMutex.Lock()
	if cleanupExpiredPasswordsLocked(globalWgDev) > 0 {
		if err := saveDB(); err != nil {
			dbMutex.Unlock()
			writeAdminError(w, http.StatusInternalServerError, "failed to persist expired-password cleanup")
			return
		}
	}
	if db.CreateRequests == nil {
		db.CreateRequests = make(map[string]CreateRequestRecord)
	}
	if idempotencyHash != "" {
		cleanupCreateRequestsLocked(time.Now())
		if record, exists := db.CreateRequests[idempotencyHash]; exists {
			if record.RequestHash != requestHash {
				dbMutex.Unlock()
				writeAdminError(w, http.StatusConflict, "Idempotency-Key was already used with a different request")
				return
			}
			password := ""
			var entry *PasswordEntry
			for candidate, candidateEntry := range db.Passwords {
				if passwordFingerprint(candidate) == record.PasswordHash {
					password = candidate
					entry = candidateEntry
					break
				}
			}
			if password == "" || entry == nil {
				dbMutex.Unlock()
				writeAdminError(w, http.StatusConflict, "Idempotency-Key belongs to an expired or deleted password")
				return
			}
			view := toAdminPasswordView(password, entry)
			dbMutex.Unlock()
			writeAdminJSON(w, http.StatusOK, view)
			return
		}
	}

	newPass := ""
	for i := 0; i < 10; i++ {
		candidate, generateErr := generatePassword()
		if generateErr != nil {
			break
		}
		if _, exists := db.Passwords[candidate]; !exists {
			newPass = candidate
			break
		}
	}
	if newPass == "" {
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to generate a unique password")
		return
	}
	if err := serverWrapKeys.AddPassword(newPass); err != nil {
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to create WRAP key")
		return
	}

	if label == "" {
		label = nextPasswordLabel()
	}
	entry := &PasswordEntry{
		Label:        label,
		ExpiresAt:    time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix(),
		MaxDevices:   maxDevices,
		TrafficLimit: trafficLimit,
		VkHash:       vkHash,
		Ports:        ports,
	}
	db.Passwords[newPass] = entry
	if idempotencyHash != "" {
		db.CreateRequests[idempotencyHash] = CreateRequestRecord{
			RequestHash:  requestHash,
			PasswordHash: passwordFingerprint(newPass),
			CreatedAt:    time.Now().Unix(),
		}
	}
	if err := saveDB(); err != nil {
		delete(db.Passwords, newPass)
		delete(db.CreateRequests, idempotencyHash)
		serverWrapKeys.RemovePassword(newPass)
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to persist new password")
		return
	}
	view := toAdminPasswordView(newPass, entry)
	dbMutex.Unlock()

	writeAdminJSON(w, http.StatusOK, view)
}

// POST /admin/passwords/update — редактирование уже существующего пароля.
// Form: password (required), label/vk_hash/max_devices/days/traffic_limit_bytes — любые из них,
// только присланные поля меняются, остальные остаются как были. days, если
// передан, пересчитывает expires_at от текущего момента (как /new в боте).
func handleAdminUpdatePassword(w http.ResponseWriter, r *http.Request) {
	setAdminCORSHeaders(w, "POST")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid form data")
		return
	}
	if r.Form.Has("vk_hash") && r.FormValue("vk_hash") == "" {
		writeAdminError(w, http.StatusBadRequest, "vk_hash cannot be empty")
		return
	}
	maxDevices := 0
	if r.Form.Has("max_devices") {
		parsed, err := strconv.Atoi(r.FormValue("max_devices"))
		if err != nil || parsed < 1 {
			writeAdminError(w, http.StatusBadRequest, "max_devices must be a positive number")
			return
		}
		maxDevices = parsed
	}
	days := 0
	if r.Form.Has("days") {
		parsed, err := strconv.Atoi(r.FormValue("days"))
		if err != nil || parsed < 1 || parsed > 365 {
			writeAdminError(w, http.StatusBadRequest, "days must be between 1 and 365")
			return
		}
		days = parsed
	}
	trafficLimit := int64(-1)
	_, hasTrafficLimit := r.Form["traffic_limit_bytes"]
	if hasTrafficLimit {
		parsed, err := parseTrafficLimit(r.FormValue("traffic_limit_bytes"))
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, err.Error())
			return
		}
		trafficLimit = parsed
	}

	pass := r.FormValue("password")
	if pass == "" {
		writeAdminError(w, http.StatusBadRequest, "password is required")
		return
	}

	dbMutex.Lock()
	entry, exists := db.Passwords[pass]
	if !exists || entry == nil {
		dbMutex.Unlock()
		writeAdminError(w, http.StatusNotFound, "password not found")
		return
	}

	entryBefore := clonePasswordEntry(entry)
	if r.Form.Has("label") {
		entry.Label = r.FormValue("label")
	}
	if r.Form.Has("vk_hash") {
		entry.VkHash = r.FormValue("vk_hash")
	}
	if r.Form.Has("max_devices") {
		entry.MaxDevices = maxDevices
	}
	if r.Form.Has("days") {
		entry.ExpiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
	}
	if hasTrafficLimit {
		entry.TrafficLimit = trafficLimit
	}

	if err := saveDB(); err != nil {
		*entry = *entryBefore
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to persist password changes")
		return
	}
	view := toAdminPasswordView(pass, entry)
	dbMutex.Unlock()

	writeAdminJSON(w, http.StatusOK, view)
}

// POST /admin/passwords/deactivate — Form: password
func handleAdminDeactivatePassword(w http.ResponseWriter, r *http.Request) {
	setAdminCORSHeaders(w, "POST")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	pass := r.FormValue("password")
	if pass == "" {
		writeAdminError(w, http.StatusBadRequest, "password is required")
		return
	}

	dbMutex.Lock()
	entry, exists := db.Passwords[pass]
	if !exists || entry == nil {
		dbMutex.Unlock()
		writeAdminError(w, http.StatusNotFound, "password not found")
		return
	}
	wasDeactivated := entry.IsDeactivated
	entry.IsDeactivated = true
	if err := saveDB(); err != nil {
		entry.IsDeactivated = wasDeactivated
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to persist password deactivation")
		return
	}
	disconnectCredentialConnections(pass)
	serverWrapKeys.RemovePassword(pass)
	disconnectPasswordDevicesLocked(entry)
	view := toAdminPasswordView(pass, entry)
	dbMutex.Unlock()

	writeAdminJSON(w, http.StatusOK, view)
}

// POST /admin/passwords/activate — Form: password
func handleAdminActivatePassword(w http.ResponseWriter, r *http.Request) {
	setAdminCORSHeaders(w, "POST")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	pass := r.FormValue("password")
	if pass == "" {
		writeAdminError(w, http.StatusBadRequest, "password is required")
		return
	}

	dbMutex.Lock()
	entry, exists := db.Passwords[pass]
	if !exists || entry == nil {
		dbMutex.Unlock()
		writeAdminError(w, http.StatusNotFound, "password not found")
		return
	}
	wasDeactivated := entry.IsDeactivated
	if err := serverWrapKeys.AddPassword(pass); err != nil {
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to activate password")
		return
	}
	entry.IsDeactivated = false
	if err := saveDB(); err != nil {
		entry.IsDeactivated = wasDeactivated
		if wasDeactivated {
			serverWrapKeys.RemovePassword(pass)
		}
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to persist password activation")
		return
	}
	view := toAdminPasswordView(pass, entry)
	dbMutex.Unlock()

	writeAdminJSON(w, http.StatusOK, view)
}

// POST /admin/passwords/delete — Form: password
func handleAdminDeletePassword(w http.ResponseWriter, r *http.Request) {
	setAdminCORSHeaders(w, "POST")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	pass := r.FormValue("password")
	if pass == "" {
		writeAdminError(w, http.StatusBadRequest, "password is required")
		return
	}

	dbMutex.Lock()
	entry, exists := db.Passwords[pass]
	if !exists || entry == nil {
		dbMutex.Unlock()
		writeAdminError(w, http.StatusNotFound, "password not found")
		return
	}
	deviceIDs := entryDeviceIDs(entry)
	removedDevices := make(map[string]*ClientDevice, len(deviceIDs))
	for _, id := range deviceIDs {
		if dev, devExists := db.Devices[id]; devExists {
			removedDevices[id] = dev
			delete(db.Devices, id)
		}
	}
	delete(db.Passwords, pass)
	if err := saveDB(); err != nil {
		db.Passwords[pass] = entry
		for id, dev := range removedDevices {
			db.Devices[id] = dev
		}
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to persist password deletion")
		return
	}
	disconnectCredentialConnections(pass)
	serverWrapKeys.RemovePassword(pass)
	for _, dev := range removedDevices {
		removePeerFromWG(globalWgDev, dev)
	}
	dbMutex.Unlock()

	writeAdminJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// POST /admin/passwords/reset-traffic — Form: password
func handleAdminResetTraffic(w http.ResponseWriter, r *http.Request) {
	setAdminCORSHeaders(w, "POST")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pass := r.FormValue("password")
	if pass == "" {
		writeAdminError(w, http.StatusBadRequest, "password is required")
		return
	}
	dbMutex.Lock()
	entry, exists := db.Passwords[pass]
	if !exists || entry == nil {
		dbMutex.Unlock()
		writeAdminError(w, http.StatusNotFound, "password not found")
		return
	}
	entryBefore := clonePasswordEntry(entry)
	devicesBefore := make(map[string]*ClientDevice)
	for _, deviceID := range entryDeviceIDs(entry) {
		if device := db.Devices[deviceID]; device != nil {
			devicesBefore[deviceID] = cloneClientDevice(device)
			device.UpBytes = 0
			device.DownBytes = 0
		}
	}
	entry.UpBytes = 0
	entry.DownBytes = 0
	resetWGTrafficBaselinesLocked(entryDeviceIDs(entry))
	resetRawTrafficCounters(entryDeviceIDs(entry))
	if err := saveDB(); err != nil {
		*entry = *entryBefore
		for deviceID, device := range devicesBefore {
			db.Devices[deviceID] = device
		}
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to persist traffic reset")
		return
	}
	view := toAdminPasswordView(pass, entry)
	dbMutex.Unlock()
	writeAdminJSON(w, http.StatusOK, view)
}

// disconnectPasswordDevicesLocked отключает от WG все устройства, привязанные
// к паролю (используется при деактивации). Вызывающий должен уже держать
// dbMutex.
func disconnectPasswordDevicesLocked(entry *PasswordEntry) {
	if globalWgDev == nil {
		return
	}
	deviceIDs := entry.DeviceIDs
	if len(deviceIDs) == 0 && entry.DeviceID != "" {
		deviceIDs = []string{entry.DeviceID}
	}
	for _, id := range deviceIDs {
		dev, devExists := db.Devices[id]
		if !devExists {
			continue
		}
		pubHex, err := b64ToHex(dev.PubKey)
		if err != nil {
			continue
		}
		globalWgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
	}
}

// POST /admin/passwords/unbind-device — открепить одно устройство от пароля
// (снимает WG-пир и слот занятого устройства, не трогая сам пароль).
// Form: password (required), device_id (required).
func handleAdminUnbindDevice(w http.ResponseWriter, r *http.Request) {
	setAdminCORSHeaders(w, "POST")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	pass := r.FormValue("password")
	if pass == "" {
		writeAdminError(w, http.StatusBadRequest, "password is required")
		return
	}
	deviceID := r.FormValue("device_id")

	dbMutex.Lock()
	entry, exists := db.Passwords[pass]
	if !exists || entry == nil {
		dbMutex.Unlock()
		writeAdminError(w, http.StatusNotFound, "password not found")
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
		dbMutex.Unlock()
		writeAdminError(w, http.StatusInternalServerError, "failed to persist device unbind")
		return
	}
	disconnectCredentialDeviceConnections(pass, deviceID)
	view := toAdminPasswordView(pass, entry)
	dbMutex.Unlock()

	writeAdminJSON(w, http.StatusOK, view)
}

func handleAdminQRCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid form data")
		return
	}
	payload := r.FormValue("payload")
	if payload == "" || len(payload) > 3000 {
		writeAdminError(w, http.StatusBadRequest, "payload is required and must be at most 3000 bytes")
		return
	}
	png, err := qrcode.Encode(payload, qrcode.Medium, 600)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "payload cannot be encoded as a QR code")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(png)
}

func handleAdminPublicAddress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get("https://api.ipify.org")
	if err != nil {
		writeAdminError(w, http.StatusBadGateway, "failed to determine public address")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		writeAdminError(w, http.StatusBadGateway, "public address service returned an error")
		return
	}
	addressBytes, err := io.ReadAll(io.LimitReader(response.Body, 64))
	if err != nil {
		writeAdminError(w, http.StatusBadGateway, "failed to read public address")
		return
	}
	address := strings.TrimSpace(string(addressBytes))
	if net.ParseIP(address) == nil {
		writeAdminError(w, http.StatusBadGateway, "public address service returned an invalid address")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]string{"address": address})
}

func handleAdminVKHashLibrary(w http.ResponseWriter, r *http.Request) {
	setAdminCORSHeaders(w, "GET, POST, DELETE")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		dbMutex.Lock()
		hashes := append([]string(nil), db.VKHashLibrary...)
		dbMutex.Unlock()
		writeAdminJSON(w, http.StatusOK, map[string]interface{}{"hashes": hashes})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid form data")
			return
		}
		additions := splitVKHashes(r.FormValue("hashes"))
		if len(additions) == 0 {
			writeAdminError(w, http.StatusBadRequest, "hashes is required")
			return
		}
		dbMutex.Lock()
		before := append([]string(nil), db.VKHashLibrary...)
		db.VKHashLibrary = mergeVKHashes(db.VKHashLibrary, additions)
		if err := saveDB(); err != nil {
			db.VKHashLibrary = before
			dbMutex.Unlock()
			writeAdminError(w, http.StatusInternalServerError, "failed to persist VK hash library")
			return
		}
		hashes := append([]string(nil), db.VKHashLibrary...)
		dbMutex.Unlock()
		writeAdminJSON(w, http.StatusOK, map[string]interface{}{"hashes": hashes})
	case http.MethodDelete:
		dbMutex.Lock()
		before := append([]string(nil), db.VKHashLibrary...)
		db.VKHashLibrary = nil
		if err := saveDB(); err != nil {
			db.VKHashLibrary = before
			dbMutex.Unlock()
			writeAdminError(w, http.StatusInternalServerError, "failed to clear VK hash library")
			return
		}
		dbMutex.Unlock()
		writeAdminJSON(w, http.StatusOK, map[string]interface{}{"hashes": []string{}})
	default:
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func registerAdminAPIRoutes(mux *http.ServeMux) {
	registerAdminUI(mux)
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/metrics", handlePrometheusMetrics)
	mux.HandleFunc("/admin/passwords", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAdminListPasswords(w, r)
		case http.MethodPost:
			handleAdminCreatePassword(w, r)
		case http.MethodOptions:
			setAdminCORSHeaders(w, "GET, POST")
			w.WriteHeader(http.StatusOK)
		default:
			writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
	mux.HandleFunc("/admin/passwords/deactivate", handleAdminDeactivatePassword)
	mux.HandleFunc("/admin/passwords/activate", handleAdminActivatePassword)
	mux.HandleFunc("/admin/passwords/delete", handleAdminDeletePassword)
	mux.HandleFunc("/admin/passwords/reset-traffic", handleAdminResetTraffic)
	mux.HandleFunc("/admin/passwords/update", handleAdminUpdatePassword)
	mux.HandleFunc("/admin/passwords/unbind-device", handleAdminUnbindDevice)
	mux.HandleFunc("/admin/qrcode", handleAdminQRCode)
	mux.HandleFunc("/admin/public-address", handleAdminPublicAddress)
	mux.HandleFunc("/admin/vk-hash-library", handleAdminVKHashLibrary)
}
