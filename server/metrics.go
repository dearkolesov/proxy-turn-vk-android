package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ready := globalWgDev != nil && serverWrapKeys.Count() > 0
	status := http.StatusOK
	message := "ready"
	if !ready {
		status = http.StatusServiceUnavailable
		message = "not ready"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": message})
}

func handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !adminAuthorized(r) {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	dbMutex.Lock()
	passwordCount := len(db.Passwords)
	deviceCount := len(db.Devices)
	dbMutex.Unlock()
	profileChallenges.Lock()
	challengeCount := len(profileChallenges.items)
	profileChallenges.Unlock()

	uptime := 0.0
	if !serverStartTime.IsZero() {
		uptime = time.Since(serverStartTime).Seconds()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "# HELP qwdtt_server_up Whether this node is ready to serve tunnels.\n# TYPE qwdtt_server_up gauge\nqwdtt_server_up %d\n", boolMetric(globalWgDev != nil && serverWrapKeys.Count() > 0))
	fmt.Fprintf(w, "# HELP qwdtt_server_uptime_seconds Process uptime in seconds.\n# TYPE qwdtt_server_uptime_seconds gauge\nqwdtt_server_uptime_seconds %.3f\n", uptime)
	fmt.Fprintf(w, "# HELP qwdtt_server_active_connections Active outer client connections on this node.\n# TYPE qwdtt_server_active_connections gauge\nqwdtt_server_active_connections %d\n", atomic.LoadInt32(&activeConns))
	fmt.Fprintf(w, "# HELP qwdtt_server_total_connections_total Accepted client connections since start.\n# TYPE qwdtt_server_total_connections_total counter\nqwdtt_server_total_connections_total %d\n", atomic.LoadInt64(&totalConns))
	fmt.Fprintf(w, "# HELP qwdtt_server_bytes_from_clients_total Bytes received from clients since start.\n# TYPE qwdtt_server_bytes_from_clients_total counter\nqwdtt_server_bytes_from_clients_total %d\n", atomic.LoadInt64(&totalBytesFromClient))
	fmt.Fprintf(w, "# HELP qwdtt_server_bytes_to_clients_total Bytes sent to clients since start.\n# TYPE qwdtt_server_bytes_to_clients_total counter\nqwdtt_server_bytes_to_clients_total %d\n", atomic.LoadInt64(&totalBytesToClient))
	fmt.Fprintf(w, "# HELP qwdtt_server_passwords Current password records on this node.\n# TYPE qwdtt_server_passwords gauge\nqwdtt_server_passwords %d\n", passwordCount)
	fmt.Fprintf(w, "# HELP qwdtt_server_devices Current device records on this node.\n# TYPE qwdtt_server_devices gauge\nqwdtt_server_devices %d\n", deviceCount)
	fmt.Fprintf(w, "# HELP qwdtt_server_wrap_keys Active WRAP keys loaded on this node.\n# TYPE qwdtt_server_wrap_keys gauge\nqwdtt_server_wrap_keys %d\n", serverWrapKeys.Count())
	fmt.Fprintf(w, "# HELP qwdtt_server_profile_challenges Outstanding profile API nonces on this node.\n# TYPE qwdtt_server_profile_challenges gauge\nqwdtt_server_profile_challenges %d\n", challengeCount)
}

func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}
