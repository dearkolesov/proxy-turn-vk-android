package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunStatusCheckUsesServerProfileProof(t *testing.T) {
	const (
		password = "load-test-password"
		deviceID = "load-test-device"
		nonce    = "load-test-nonce"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/profile/challenge":
			if r.Method != http.MethodPost {
				t.Errorf("challenge method = %s, want POST", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})
		case "/api/profile/status":
			if r.Method != http.MethodPost {
				t.Errorf("status method = %s, want POST", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse status form: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mac := hmac.New(sha256.New, []byte(password))
			_, _ = mac.Write([]byte("status\n" + deviceID + "\n" + nonce))
			if got := r.FormValue("proof"); got != hex.EncodeToString(mac.Sum(nil)) {
				t.Errorf("proof = %s, want matching HMAC", got)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if got := r.FormValue("key_id"); got != profileKeyID(password) {
				t.Errorf("key_id = %s, want %s", got, profileKeyID(password))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if got := r.FormValue("device_id"); got != deviceID {
				t.Errorf("device_id = %s, want %s", got, deviceID)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	code, err := runStatusCheck(context.Background(), server.Client(), server.URL, password, profileKeyID(password), deviceID)
	if err != nil {
		t.Fatalf("runStatusCheck() error = %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("runStatusCheck() status = %d, want %d", code, http.StatusOK)
	}
}
