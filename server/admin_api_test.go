package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/device"
)

func setupAdminCreateTest(t *testing.T) func() {
	t.Helper()
	previousDB := db
	previousDBFile := dbFile
	previousKeyStore := serverWrapKeys
	previousWGDevice := globalWgDev
	adminTokenMu.RLock()
	previousTokenHash := adminTokenHash
	previousTokenReady := adminTokenReady
	adminTokenMu.RUnlock()
	adminAuthMu.Lock()
	previousAttempts := adminAuthAttempts
	adminAuthAttempts = make(map[string]adminAuthAttempt)
	adminAuthMu.Unlock()

	db = &Database{
		Passwords:      make(map[string]*PasswordEntry),
		Devices:        make(map[string]*ClientDevice),
		CreateRequests: make(map[string]CreateRequestRecord),
	}
	dbFile = filepath.Join(t.TempDir(), "passwords.json")
	serverWrapKeys = newWrapKeyStore()
	globalWgDev = nil
	setAdminAPIToken("admin-api-test-token")

	return func() {
		db = previousDB
		dbFile = previousDBFile
		serverWrapKeys = previousKeyStore
		globalWgDev = previousWGDevice
		adminTokenMu.Lock()
		adminTokenHash = previousTokenHash
		adminTokenReady = previousTokenReady
		adminTokenMu.Unlock()
		adminAuthMu.Lock()
		adminAuthAttempts = previousAttempts
		adminAuthMu.Unlock()
	}
}

func postAdminForm(path, key string, form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Authorization", "Bearer admin-api-test-token")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	response := httptest.NewRecorder()
	switch path {
	case "/admin/passwords":
		handleAdminCreatePassword(response, request)
	case "/admin/passwords/update":
		handleAdminUpdatePassword(response, request)
	case "/admin/passwords/deactivate":
		handleAdminDeactivatePassword(response, request)
	case "/admin/passwords/activate":
		handleAdminActivatePassword(response, request)
	case "/admin/passwords/delete":
		handleAdminDeletePassword(response, request)
	case "/admin/passwords/unbind-device":
		handleAdminUnbindDevice(response, request)
	case "/admin/qrcode":
		handleAdminQRCode(response, request)
	case "/admin/passwords/reset-traffic":
		handleAdminResetTraffic(response, request)
	default:
		panic("unsupported test path: " + path)
	}
	return response
}

func TestAdminCreateAndUpdateTrafficLimit(t *testing.T) {
	cleanup := setupAdminCreateTest(t)
	defer cleanup()

	request := httptest.NewRequest(http.MethodPost, "/admin/passwords", strings.NewReader(url.Values{
		"vk_hash":             {"test-hash"},
		"traffic_limit_bytes": {"1048576"},
	}.Encode()))
	request.Header.Set("Authorization", "Bearer admin-api-test-token")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handleAdminCreatePassword(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", response.Code, response.Body.String())
	}
	var view adminPasswordView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if view.TrafficLimit != 1048576 {
		t.Fatalf("traffic limit = %d, want 1048576", view.TrafficLimit)
	}

	updateRequest := httptest.NewRequest(http.MethodPost, "/admin/passwords/update", strings.NewReader(url.Values{
		"password":            {view.Password},
		"traffic_limit_bytes": {"0"},
	}.Encode()))
	updateRequest.Header.Set("Authorization", "Bearer admin-api-test-token")
	updateRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	updated := httptest.NewRecorder()
	handleAdminUpdatePassword(updated, updateRequest)
	if updated.Code != http.StatusOK {
		t.Fatalf("update status = %d, body = %s", updated.Code, updated.Body.String())
	}
	view = adminPasswordView{}
	if err := json.Unmarshal(updated.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if view.TrafficLimit != 0 {
		t.Fatalf("traffic limit after clearing = %d, want 0", view.TrafficLimit)
	}
}

func TestAdminResetTrafficClearsCounters(t *testing.T) {
	cleanup := setupAdminCreateTest(t)
	defer cleanup()
	db.Passwords["test-password"] = &PasswordEntry{
		DeviceIDs: []string{"device-a"}, UpBytes: 100, DownBytes: 200,
	}
	db.Devices["device-a"] = &ClientDevice{DeviceID: "device-a", UpBytes: 100, DownBytes: 200}
	response := postAdminForm("/admin/passwords/reset-traffic", "", url.Values{"password": {"test-password"}})
	if response.Code != http.StatusOK {
		t.Fatalf("reset status = %d, body = %s", response.Code, response.Body.String())
	}
	entry := db.Passwords["test-password"]
	if entry.UpBytes != 0 || entry.DownBytes != 0 || db.Devices["device-a"].UpBytes != 0 || db.Devices["device-a"].DownBytes != 0 {
		t.Fatalf("traffic counters not cleared: entry=%+v device=%+v", entry, db.Devices["device-a"])
	}
}

func TestTrafficLimitReached(t *testing.T) {
	for _, test := range []struct {
		name  string
		entry *PasswordEntry
		want  bool
	}{
		{name: "unlimited", entry: &PasswordEntry{UpBytes: 500, DownBytes: 500}, want: false},
		{name: "below", entry: &PasswordEntry{TrafficLimit: 1001, UpBytes: 500, DownBytes: 500}, want: false},
		{name: "at limit", entry: &PasswordEntry{TrafficLimit: 1000, UpBytes: 500, DownBytes: 500}, want: true},
		{name: "over limit", entry: &PasswordEntry{TrafficLimit: 900, UpBytes: 500, DownBytes: 500}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := trafficLimitReached(test.entry); got != test.want {
				t.Fatalf("trafficLimitReached() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestVKHashLibraryHelpersDeduplicate(t *testing.T) {
	got := splitVKHashes("one, two\none;one")
	want := []string{"one", "two"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitVKHashes() = %#v, want %#v", got, want)
	}
	merged := mergeVKHashes([]string{"two", "three"}, []string{"one", "two"})
	want = []string{"two", "three", "one"}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("mergeVKHashes() = %#v, want %#v", merged, want)
	}
}

func TestAdminVKHashLibraryCRUD(t *testing.T) {
	cleanup := setupAdminCreateTest(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerAdminAPIRoutes(mux)
	post := httptest.NewRequest(http.MethodPost, "/admin/vk-hash-library", strings.NewReader(url.Values{
		"hashes": {"hash-a\nhash-b,hash-a"},
	}.Encode()))
	post.Header.Set("Authorization", "Bearer admin-api-test-token")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, post)
	if response.Code != http.StatusOK {
		t.Fatalf("library POST status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		Hashes []string `json:"hashes"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode library POST: %v", err)
	}
	if !reflect.DeepEqual(payload.Hashes, []string{"hash-a", "hash-b"}) {
		t.Fatalf("library hashes = %#v", payload.Hashes)
	}

	get := httptest.NewRequest(http.MethodGet, "/admin/vk-hash-library", nil)
	get.Header.Set("Authorization", "Bearer admin-api-test-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, get)
	if response.Code != http.StatusOK {
		t.Fatalf("library GET status = %d", response.Code)
	}

	delete := httptest.NewRequest(http.MethodDelete, "/admin/vk-hash-library", nil)
	delete.Header.Set("Authorization", "Bearer admin-api-test-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, delete)
	if response.Code != http.StatusOK || len(db.VKHashLibrary) != 0 {
		t.Fatalf("library DELETE status = %d, hashes = %#v", response.Code, db.VKHashLibrary)
	}
}

func postAdminCreatePassword(key, vkHash string) *httptest.ResponseRecorder {
	return postAdminForm("/admin/passwords", key, url.Values{
		"vk_hash":     {vkHash},
		"days":        {"30"},
		"max_devices": {"4"},
		"label":       {"test account"},
	})
}

func TestAdminCreatePasswordIsIdempotent(t *testing.T) {
	cleanup := setupAdminCreateTest(t)
	defer cleanup()

	first := postAdminCreatePassword("order-123", "vk-hash")
	if first.Code != http.StatusOK {
		t.Fatalf("first create status = %d, body = %s", first.Code, first.Body.String())
	}
	var firstView adminPasswordView
	if err := json.Unmarshal(first.Body.Bytes(), &firstView); err != nil {
		t.Fatalf("decode first create response: %v", err)
	}
	if firstView.Password == "" {
		t.Fatal("first create response omitted password")
	}

	duplicate := postAdminCreatePassword("order-123", "vk-hash")
	if duplicate.Code != http.StatusOK {
		t.Fatalf("duplicate create status = %d, body = %s", duplicate.Code, duplicate.Body.String())
	}
	var duplicateView adminPasswordView
	if err := json.Unmarshal(duplicate.Body.Bytes(), &duplicateView); err != nil {
		t.Fatalf("decode duplicate create response: %v", err)
	}
	if duplicateView.Password != firstView.Password {
		t.Fatalf("duplicate returned password %q, want original %q", duplicateView.Password, firstView.Password)
	}
	if got := len(db.Passwords); got != 1 {
		t.Fatalf("stored passwords = %d, want 1", got)
	}
	data, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read persisted database: %v", err)
	}
	var persisted Database
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("decode persisted database: %v", err)
	}
	if len(persisted.CreateRequests) != 1 {
		t.Fatalf("persisted idempotency records = %d, want 1", len(persisted.CreateRequests))
	}

	conflict := postAdminCreatePassword("order-123", "different-vk-hash")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("same idempotency key with changed payload status = %d, want %d", conflict.Code, http.StatusConflict)
	}
}

func TestAdminMutationsRollbackWhenPersistenceFails(t *testing.T) {
	deviceID := "test-device"
	tests := []struct {
		name   string
		path   string
		form   url.Values
		setup  func() error
		assert func(*testing.T)
	}{
		{
			name: "update",
			path: "/admin/passwords/update",
			form: url.Values{"password": {"test-password"}, "label": {"after"}},
			setup: func() error {
				db.Passwords["test-password"] = &PasswordEntry{Label: "before"}
				return nil
			},
			assert: func(t *testing.T) {
				if got := db.Passwords["test-password"].Label; got != "before" {
					t.Fatalf("label after failed update = %q, want before", got)
				}
			},
		},
		{
			name: "deactivate",
			path: "/admin/passwords/deactivate",
			form: url.Values{"password": {"test-password"}},
			setup: func() error {
				db.Passwords["test-password"] = &PasswordEntry{}
				return serverWrapKeys.AddPassword("test-password")
			},
			assert: func(t *testing.T) {
				if db.Passwords["test-password"].IsDeactivated || serverWrapKeys.Count() != 1 {
					t.Fatal("failed deactivation changed credential state")
				}
			},
		},
		{
			name: "activate",
			path: "/admin/passwords/activate",
			form: url.Values{"password": {"test-password"}},
			setup: func() error {
				db.Passwords["test-password"] = &PasswordEntry{IsDeactivated: true}
				return nil
			},
			assert: func(t *testing.T) {
				if !db.Passwords["test-password"].IsDeactivated || serverWrapKeys.Count() != 0 {
					t.Fatal("failed activation changed credential state")
				}
			},
		},
		{
			name: "delete",
			path: "/admin/passwords/delete",
			form: url.Values{"password": {"test-password"}},
			setup: func() error {
				db.Passwords["test-password"] = &PasswordEntry{DeviceID: deviceID, DeviceIDs: []string{deviceID}}
				db.Devices[deviceID] = &ClientDevice{DeviceID: deviceID}
				return serverWrapKeys.AddPassword("test-password")
			},
			assert: func(t *testing.T) {
				if db.Passwords["test-password"] == nil || db.Devices[deviceID] == nil || serverWrapKeys.Count() != 1 {
					t.Fatal("failed deletion did not restore credential state")
				}
			},
		},
		{
			name: "unbind-device",
			path: "/admin/passwords/unbind-device",
			form: url.Values{"password": {"test-password"}, "device_id": {deviceID}},
			setup: func() error {
				db.Passwords["test-password"] = &PasswordEntry{DeviceID: deviceID, DeviceIDs: []string{deviceID}}
				db.Devices[deviceID] = &ClientDevice{DeviceID: deviceID}
				return nil
			},
			assert: func(t *testing.T) {
				if db.Devices[deviceID] == nil || !passwordEntryHasDevice(db.Passwords["test-password"], deviceID) {
					t.Fatal("failed unbind did not restore device state")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cleanup := setupAdminCreateTest(t)
			defer cleanup()
			if err := test.setup(); err != nil {
				t.Fatalf("setup: %v", err)
			}
			dbFile = filepath.Join(t.TempDir(), "missing", "passwords.json")
			response := postAdminForm(test.path, "", test.form)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusInternalServerError, response.Body.String())
			}
			test.assert(t)
		})
	}
}

func TestAdminUnbindDeviceAllowsEmptyIDToUnbindAll(t *testing.T) {
	cleanup := setupAdminCreateTest(t)
	defer cleanup()
	ids := []string{"device-a", "device-b"}
	db.Passwords["test-password"] = &PasswordEntry{DeviceID: "multi", DeviceIDs: append([]string(nil), ids...), MaxDevices: 4}
	for _, id := range ids {
		db.Devices[id] = &ClientDevice{DeviceID: id}
	}
	if err := serverWrapKeys.AddPassword("test-password"); err != nil {
		t.Fatalf("AddPassword() error = %v", err)
	}

	response := postAdminForm("/admin/passwords/unbind-device", "", url.Values{
		"password":  {"test-password"},
		"device_id": {""},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("unbind-all status = %d, body = %s", response.Code, response.Body.String())
	}
	entry := db.Passwords["test-password"]
	if len(db.Devices) != 0 || len(entry.DeviceIDs) != 0 || entry.DeviceID != "" {
		t.Fatalf("unbind-all left state behind: devices=%d ids=%v legacy=%q", len(db.Devices), entry.DeviceIDs, entry.DeviceID)
	}
}

func TestAdminQRCodeReturnsPNG(t *testing.T) {
	cleanup := setupAdminCreateTest(t)
	defer cleanup()
	response := postAdminForm("/admin/qrcode", "", url.Values{
		"payload": {"qwdtt://config?name=Test&peer=example.org:56000&hashes=vk-hash&workers=18&port=9000&pass=local-test"},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("QR status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("QR Content-Type = %q, want image/png", got)
	}
	if len(response.Body.Bytes()) < 8 || string(response.Body.Bytes()[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatal("QR response is not a PNG image")
	}
}

func TestAdminPublicAddressRequiresAuthorization(t *testing.T) {
	cleanup := setupAdminCreateTest(t)
	defer cleanup()
	request := httptest.NewRequest(http.MethodGet, "/admin/public-address", nil)
	response := httptest.NewRecorder()
	handleAdminPublicAddress(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("public address status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestHealthzReportsReadiness(t *testing.T) {
	previousWGDevice := globalWgDev
	previousKeyStore := serverWrapKeys
	defer func() {
		globalWgDev = previousWGDevice
		serverWrapKeys = previousKeyStore
	}()

	globalWgDev = new(device.Device)
	serverWrapKeys = newWrapKeyStore()
	if err := serverWrapKeys.AddPassword("health-test-password"); err != nil {
		t.Fatalf("AddPassword() error = %v", err)
	}
	response := httptest.NewRecorder()
	handleHealthz(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"ready"`) {
		t.Fatalf("ready health response = %d %s", response.Code, response.Body.String())
	}

	globalWgDev = nil
	response = httptest.NewRecorder()
	handleHealthz(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unready health status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestPrometheusMetricsRequireAdminTokenAndExposeNodeState(t *testing.T) {
	cleanup := setupAdminCreateTest(t)
	defer cleanup()
	db.Passwords["metrics-test-password"] = &PasswordEntry{}
	db.Devices["metrics-test-device"] = &ClientDevice{DeviceID: "metrics-test-device"}
	if err := serverWrapKeys.AddPassword("metrics-test-password"); err != nil {
		t.Fatalf("AddPassword() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer admin-api-test-token")
	response := httptest.NewRecorder()
	handlePrometheusMetrics(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "qwdtt_server_passwords 1") || !strings.Contains(body, "qwdtt_server_devices 1") || !strings.Contains(body, "qwdtt_server_wrap_keys 1") {
		t.Fatalf("metrics omitted expected node state:\n%s", body)
	}
}

func TestAdminCreatePasswordRollsBackWhenPersistenceFails(t *testing.T) {
	cleanup := setupAdminCreateTest(t)
	defer cleanup()
	dbFile = filepath.Join(t.TempDir(), "missing", "passwords.json")

	response := postAdminCreatePassword("order-persist-failure", "vk-hash")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("create status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	if len(db.Passwords) != 0 || len(db.CreateRequests) != 0 || serverWrapKeys.Count() != 0 {
		t.Fatalf("failed create left state behind: passwords=%d idempotency=%d wrap-keys=%d", len(db.Passwords), len(db.CreateRequests), serverWrapKeys.Count())
	}
}
