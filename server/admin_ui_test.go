package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminUIIsEmbeddedWithSecurityHeaders(t *testing.T) {
	mux := http.NewServeMux()
	registerAdminAPIRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := response.Header.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") || !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("Content-Security-Policy = %q", got)
	}
	if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}

	for _, path := range []string{"/app.css", "/app.js"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", path, response.StatusCode, http.StatusOK)
		}
	}

	response, err = server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("GET /healthz was intercepted by UI: status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}

	response, err = server.Client().Get(server.URL + "/admin/passwords")
	if err != nil {
		t.Fatalf("GET /admin/passwords: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || !strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("GET /admin/passwords was intercepted by UI: status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
}
