package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

func serverReady() bool {
	if globalWgDev == nil || serverWrapKeys.Count() == 0 {
		return false
	}
	if clusterStore != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return clusterStore.Ping(ctx) == nil
	}
	return true
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ready := serverReady()
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
	challengeCount := 0
	if clusterStore != nil {
		var err error
		challengeCount, err = clusterStore.ProfileChallengeCount()
		if err != nil {
			writeAdminError(w, http.StatusServiceUnavailable, "challenge metrics unavailable")
			return
		}
	} else {
		profileChallenges.Lock()
		challengeCount = len(profileChallenges.items)
		profileChallenges.Unlock()
	}

	uptime := 0.0
	if !serverStartTime.IsZero() {
		uptime = time.Since(serverStartTime).Seconds()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "# HELP qwdtt_server_up Whether this node is ready to serve tunnels.\n# TYPE qwdtt_server_up gauge\nqwdtt_server_up %d\n", boolMetric(serverReady()))
	fmt.Fprintf(w, "# HELP qwdtt_server_uptime_seconds Process uptime in seconds.\n# TYPE qwdtt_server_uptime_seconds gauge\nqwdtt_server_uptime_seconds %.3f\n", uptime)
	fmt.Fprintf(w, "# HELP qwdtt_server_active_connections Active outer client connections on this node.\n# TYPE qwdtt_server_active_connections gauge\nqwdtt_server_active_connections %d\n", atomic.LoadInt32(&activeConns))
	fmt.Fprintf(w, "# HELP qwdtt_server_total_connections_total Accepted client connections since start.\n# TYPE qwdtt_server_total_connections_total counter\nqwdtt_server_total_connections_total %d\n", atomic.LoadInt64(&totalConns))
	fmt.Fprintf(w, "# HELP qwdtt_server_bytes_from_clients_total Bytes received from clients since start.\n# TYPE qwdtt_server_bytes_from_clients_total counter\nqwdtt_server_bytes_from_clients_total %d\n", atomic.LoadInt64(&totalBytesFromClient))
	fmt.Fprintf(w, "# HELP qwdtt_server_bytes_to_clients_total Bytes sent to clients since start.\n# TYPE qwdtt_server_bytes_to_clients_total counter\nqwdtt_server_bytes_to_clients_total %d\n", atomic.LoadInt64(&totalBytesToClient))
	fmt.Fprintf(w, "# HELP qwdtt_server_passwords Current password records on this node.\n# TYPE qwdtt_server_passwords gauge\nqwdtt_server_passwords %d\n", passwordCount)
	fmt.Fprintf(w, "# HELP qwdtt_server_devices Current device records on this node.\n# TYPE qwdtt_server_devices gauge\nqwdtt_server_devices %d\n", deviceCount)
	fmt.Fprintf(w, "# HELP qwdtt_server_wrap_keys Active WRAP keys loaded on this node.\n# TYPE qwdtt_server_wrap_keys gauge\nqwdtt_server_wrap_keys %d\n", serverWrapKeys.Count())
	fmt.Fprintf(w, "# HELP qwdtt_server_profile_challenges Outstanding profile API nonces; cluster-wide when PostgreSQL mode is enabled.\n# TYPE qwdtt_server_profile_challenges gauge\nqwdtt_server_profile_challenges %d\n", challengeCount)
	fmt.Fprintf(w, "# HELP qwdtt_server_profile_challenge_rejected_total Profile challenge requests rejected by rate or capacity limits.\n# TYPE qwdtt_server_profile_challenge_rejected_total counter\nqwdtt_server_profile_challenge_rejected_total %d\n", atomic.LoadInt64(&profileChallengeRejectedTotal))
	fmt.Fprintf(w, "# HELP qwdtt_server_profile_challenge_errors_total Profile challenge requests failing because shared challenge storage is unavailable.\n# TYPE qwdtt_server_profile_challenge_errors_total counter\nqwdtt_server_profile_challenge_errors_total %d\n", atomic.LoadInt64(&profileChallengeErrorTotal))
	if clusterStore != nil {
		poolStats := clusterStore.pool.Stat()
		fmt.Fprintf(w, "# HELP qwdtt_postgres_pool_total_connections PostgreSQL pool connections allocated on this node.\n# TYPE qwdtt_postgres_pool_total_connections gauge\nqwdtt_postgres_pool_total_connections %d\n", poolStats.TotalConns())
		fmt.Fprintf(w, "# HELP qwdtt_postgres_pool_acquired_connections PostgreSQL connections currently acquired by this node.\n# TYPE qwdtt_postgres_pool_acquired_connections gauge\nqwdtt_postgres_pool_acquired_connections %d\n", poolStats.AcquiredConns())
		fmt.Fprintf(w, "# HELP qwdtt_postgres_pool_idle_connections PostgreSQL idle connections in this node pool.\n# TYPE qwdtt_postgres_pool_idle_connections gauge\nqwdtt_postgres_pool_idle_connections %d\n", poolStats.IdleConns())
	}
}

func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}
