package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	clusterStateLockClass int32 = 0x57445454
	clusterStateLockID    int32 = 1
	clusterSchemaLockID   int32 = 4
	clusterNonceLockID    int32 = 2
	clusterRateLockID     int32 = 3
	clusterPresenceTTL          = 45 * time.Second
)

var errClusterChallengeCapacity = errors.New("profile challenge capacity reached")

type postgresStore struct {
	pool   *pgxpool.Pool
	nodeID string
}

func newPostgresStore(databaseURL, nodeID string) (*postgresStore, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL URL: %w", err)
	}
	config.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL pool: %w", err)
	}
	store := &postgresStore{pool: pool, nodeID: nodeID}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	if err := store.createSchema(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("initialize PostgreSQL schema: %w", err)
	}
	return store, nil
}

func (s *postgresStore) createSchema(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if err := acquirePostgresLock(ctx, conn, clusterStateLockClass, clusterSchemaLockID); err != nil {
		return err
	}
	defer releasePostgresLock(ctx, conn, clusterStateLockClass, clusterSchemaLockID)

	statements := []string{
		`CREATE TABLE IF NOT EXISTS wdtt_state (
			id SMALLINT PRIMARY KEY CHECK (id = 1),
			revision BIGINT NOT NULL,
			state JSONB NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS wdtt_profile_challenges (
			nonce TEXT PRIMARY KEY,
			expires_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS wdtt_profile_challenges_expiry_idx ON wdtt_profile_challenges (expires_at)`,
		`CREATE TABLE IF NOT EXISTS wdtt_profile_rate_limits (
			client_ip TEXT PRIMARY KEY,
			tokens DOUBLE PRECISION NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS wdtt_profile_rate_limits_updated_idx ON wdtt_profile_rate_limits (updated_at)`,
		`CREATE TABLE IF NOT EXISTS wdtt_active_devices (
			node_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			connections INTEGER NOT NULL CHECK (connections > 0),
			last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (node_id, device_id)
		)`,
		`CREATE INDEX IF NOT EXISTS wdtt_active_devices_seen_idx ON wdtt_active_devices (last_seen)`,
	}
	for _, statement := range statements {
		if _, err := conn.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *postgresStore) Initialize(initial *Database) (*Database, int64, error) {
	conn, err := s.pool.Acquire(context.Background())
	if err != nil {
		return nil, 0, err
	}
	defer conn.Release()
	ctx := context.Background()
	if err := acquirePostgresLock(ctx, conn, clusterStateLockClass, clusterStateLockID); err != nil {
		return nil, 0, err
	}
	defer releasePostgresLock(ctx, conn, clusterStateLockClass, clusterStateLockID)

	var payload []byte
	var revision int64
	err = conn.QueryRow(ctx, `SELECT revision, state FROM wdtt_state WHERE id = 1`).Scan(&revision, &payload)
	if err == nil {
		loaded := &Database{}
		if err := json.Unmarshal(payload, loaded); err != nil {
			return nil, 0, fmt.Errorf("decode shared state: %w", err)
		}
		normalizeDatabaseMaps(loaded)
		return loaded, revision, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, err
	}
	data, err := json.Marshal(initial)
	if err != nil {
		return nil, 0, err
	}
	err = conn.QueryRow(ctx, `INSERT INTO wdtt_state (id, revision, state) VALUES (1, 1, $1::jsonb) RETURNING revision, state`, string(data)).Scan(&revision, &payload)
	if err != nil {
		return nil, 0, err
	}
	loaded := &Database{}
	if err := json.Unmarshal(payload, loaded); err != nil {
		return nil, 0, fmt.Errorf("decode initialized shared state: %w", err)
	}
	normalizeDatabaseMaps(loaded)
	return loaded, revision, nil
}

func (s *postgresStore) acquireState() (*pgxpool.Conn, []byte, int64, error) {
	return s.acquireStateSince(-1, true)
}

func (s *postgresStore) acquireStateSince(knownRevision int64, forceReload bool) (*pgxpool.Conn, []byte, int64, error) {
	ctx := context.Background()
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := acquirePostgresLock(ctx, conn, clusterStateLockClass, clusterStateLockID); err != nil {
		conn.Release()
		return nil, nil, 0, err
	}
	var revision int64
	if err := conn.QueryRow(ctx, `SELECT revision FROM wdtt_state WHERE id = 1`).Scan(&revision); err != nil {
		releasePostgresLock(ctx, conn, clusterStateLockClass, clusterStateLockID)
		conn.Release()
		return nil, nil, 0, err
	}
	if !forceReload && revision == knownRevision {
		return conn, nil, revision, nil
	}
	var payload []byte
	if err := conn.QueryRow(ctx, `SELECT state FROM wdtt_state WHERE id = 1`).Scan(&payload); err != nil {
		releasePostgresLock(ctx, conn, clusterStateLockClass, clusterStateLockID)
		conn.Release()
		return nil, nil, 0, err
	}
	return conn, payload, revision, nil
}

func (s *postgresStore) saveState(conn *pgxpool.Conn, data []byte) (int64, error) {
	var revision int64
	err := conn.QueryRow(context.Background(), `UPDATE wdtt_state SET state = $1::jsonb, revision = revision + 1, updated_at = now() WHERE id = 1 RETURNING revision`, string(data)).Scan(&revision)
	return revision, err
}

func (s *postgresStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *postgresStore) Close() {
	s.pool.Close()
}

func (s *postgresStore) AddProfileChallenge(nonce string, expiresAt time.Time, maxEntries int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, $2)`, clusterStateLockClass, clusterNonceLockID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM wdtt_profile_challenges WHERE expires_at <= now()`); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM wdtt_profile_challenges`).Scan(&count); err != nil {
		return err
	}
	if count >= maxEntries {
		return errClusterChallengeCapacity
	}
	if _, err := tx.Exec(ctx, `INSERT INTO wdtt_profile_challenges (nonce, expires_at) VALUES ($1, $2)`, nonce, expiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *postgresStore) AllowProfileChallenge(host string, now time.Time, burst, ratePerSecond, maxBuckets int, bucketTTL time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, $2)`, clusterStateLockClass, clusterRateLockID); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM wdtt_profile_rate_limits WHERE updated_at <= $1`, now.Add(-bucketTTL)); err != nil {
		return false, err
	}
	var tokens float64
	var updatedAt time.Time
	err = tx.QueryRow(ctx, `SELECT tokens, updated_at FROM wdtt_profile_rate_limits WHERE client_ip = $1 FOR UPDATE`, host).Scan(&tokens, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM wdtt_profile_rate_limits`).Scan(&count); err != nil {
			return false, err
		}
		if count >= maxBuckets {
			return false, tx.Commit(ctx)
		}
		tokens = float64(burst)
		updatedAt = now
	} else if err != nil {
		return false, err
	} else if elapsed := now.Sub(updatedAt).Seconds(); elapsed > 0 {
		tokens = min(float64(burst), tokens+elapsed*float64(ratePerSecond))
		updatedAt = now
	}
	allowed := tokens >= 1
	if allowed {
		tokens--
	}
	if _, err := tx.Exec(ctx, `INSERT INTO wdtt_profile_rate_limits (client_ip, tokens, updated_at) VALUES ($1, $2, $3) ON CONFLICT (client_ip) DO UPDATE SET tokens = EXCLUDED.tokens, updated_at = EXCLUDED.updated_at`, host, tokens, updatedAt); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return allowed, nil
}

func (s *postgresStore) HasProfileChallenge(nonce string, now time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM wdtt_profile_challenges WHERE nonce = $1 AND expires_at > $2)`, nonce, now).Scan(&exists)
	return exists, err
}

func (s *postgresStore) ConsumeProfileChallenge(nonce string, now time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var consumed string
	err := s.pool.QueryRow(ctx, `DELETE FROM wdtt_profile_challenges WHERE nonce = $1 AND expires_at > $2 RETURNING nonce`, nonce, now).Scan(&consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *postgresStore) CleanupProfileChallenges(now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(ctx, `DELETE FROM wdtt_profile_challenges WHERE expires_at <= $1`, now); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM wdtt_profile_rate_limits WHERE updated_at <= $1`, now.Add(-profileChallengeBucketTTL))
	return err
}

func (s *postgresStore) ProfileChallengeCount() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var count int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM wdtt_profile_challenges WHERE expires_at > now()`).Scan(&count)
	return count, err
}

func (s *postgresStore) TrackActiveDevice(deviceID string, delta int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if delta > 0 {
		_, err := s.pool.Exec(ctx, `INSERT INTO wdtt_active_devices (node_id, device_id, connections, last_seen) VALUES ($1, $2, $3, now()) ON CONFLICT (node_id, device_id) DO UPDATE SET connections = wdtt_active_devices.connections + EXCLUDED.connections, last_seen = now()`, s.nodeID, deviceID, delta)
		return err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM wdtt_active_devices WHERE node_id = $1 AND device_id = $2 AND connections + $3 <= 0`, s.nodeID, deviceID, delta); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE wdtt_active_devices SET connections = connections + $3, last_seen = now() WHERE node_id = $1 AND device_id = $2`, s.nodeID, deviceID, delta)
	return err
}

func (s *postgresStore) ActiveDeviceCount(deviceIDs []string) (int, error) {
	active, err := s.ActiveDeviceIDs(deviceIDs)
	return len(active), err
}

func (s *postgresStore) ActiveDeviceIDs(deviceIDs []string) (map[string]struct{}, error) {
	active := make(map[string]struct{}, len(deviceIDs))
	if len(deviceIDs) == 0 {
		return active, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT device_id FROM wdtt_active_devices WHERE device_id = ANY($1::text[]) AND last_seen > now() - $2::interval`, deviceIDs, clusterPresenceTTL.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var deviceID string
		if err := rows.Scan(&deviceID); err != nil {
			return nil, err
		}
		active[deviceID] = struct{}{}
	}
	return active, rows.Err()
}

func trackActiveDevice(deviceID string) func() {
	if deviceID == "" {
		return func() {}
	}
	activeDevicesMu.Lock()
	activeDevices[deviceID]++
	activeDevicesMu.Unlock()
	if clusterStore != nil {
		if err := clusterStore.TrackActiveDevice(deviceID, 1); err != nil {
			log.Printf("[DB] Failed to publish active device %s: %v", deviceID, err)
		}
	}
	return func() {
		activeDevicesMu.Lock()
		activeDevices[deviceID]--
		if activeDevices[deviceID] <= 0 {
			delete(activeDevices, deviceID)
		}
		activeDevicesMu.Unlock()
		if clusterStore != nil {
			if err := clusterStore.TrackActiveDevice(deviceID, -1); err != nil {
				log.Printf("[DB] Failed to remove active device %s: %v", deviceID, err)
			}
		}
	}
}

func countActiveDevices(deviceIDs []string) (int, error) {
	active, err := activeDeviceSet(deviceIDs)
	return len(active), err
}

func activeDeviceSet(deviceIDs []string) (map[string]struct{}, error) {
	active := make(map[string]struct{}, len(deviceIDs))
	if clusterStore != nil {
		return clusterStore.ActiveDeviceIDs(deviceIDs)
	}
	activeDevicesMu.Lock()
	defer activeDevicesMu.Unlock()
	for _, id := range deviceIDs {
		if activeDevices[id] > 0 {
			active[id] = struct{}{}
		}
	}
	return active, nil
}

func (s *postgresStore) RefreshNodePresence() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(ctx, `UPDATE wdtt_active_devices SET last_seen = now() WHERE node_id = $1`, s.nodeID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM wdtt_active_devices WHERE last_seen <= now() - $1::interval`, clusterPresenceTTL.String())
	return err
}

func clusterStateSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dbMutex.Lock()
			dbMutex.Unlock()
		}
	}
}

func clusterPresenceLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if err := clusterStore.RefreshNodePresence(); err != nil {
			log.Printf("[DB] Active-device heartbeat failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func acquirePostgresLock(ctx context.Context, conn *pgxpool.Conn, lockClass, lockID int32) error {
	_, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1, $2)`, lockClass, lockID)
	return err
}

func releasePostgresLock(ctx context.Context, conn *pgxpool.Conn, lockClass, lockID int32) error {
	_, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1, $2)`, lockClass, lockID)
	return err
}

type sharedStateMutex struct {
	local       sync.Mutex
	store       *postgresStore
	conn        *pgxpool.Conn
	revision    int64
	forceReload bool
}

func (m *sharedStateMutex) Configure(store *postgresStore, revision int64) {
	m.local.Lock()
	m.store = store
	m.revision = revision
	m.local.Unlock()
}

func (m *sharedStateMutex) Lock() {
	m.local.Lock()
	if m.store == nil {
		return
	}
	for {
		conn, payload, revision, err := m.store.acquireStateSince(m.revision, m.forceReload)
		if err != nil {
			log.Printf("[DB] PostgreSQL state unavailable; retrying: %v", err)
			time.Sleep(time.Second)
			continue
		}
		m.conn = conn
		if payload != nil {
			oldDB := db
			newDB := &Database{}
			if err := json.Unmarshal(payload, newDB); err != nil {
				_ = releasePostgresLock(context.Background(), conn, clusterStateLockClass, clusterStateLockID)
				conn.Release()
				m.conn = nil
				log.Fatalf("[DB] Invalid shared PostgreSQL state: %v", err)
			}
			normalizeDatabaseMaps(newDB)
			if oldDB != nil {
				newDB.MainPassword = oldDB.MainPassword
				newDB.AdminID = oldDB.AdminID
				newDB.BotToken = oldDB.BotToken
			}
			db = newDB
			if oldDB != nil {
				applySharedDatabaseChangeLocked(oldDB, newDB)
			}
			m.revision = revision
			m.forceReload = false
		}
		return
	}
}

func (m *sharedStateMutex) Unlock() {
	if m.conn != nil {
		conn := m.conn
		m.conn = nil
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := releasePostgresLock(ctx, conn, clusterStateLockClass, clusterStateLockID)
		cancel()
		if err != nil {
			m.forceReload = true
			log.Printf("[DB] PostgreSQL advisory unlock failed: %v", err)
			raw := conn.Hijack()
			_ = raw.Close(context.Background())
		} else {
			conn.Release()
		}
	}
	m.local.Unlock()
}

func normalizeDatabaseMaps(database *Database) {
	if database.Passwords == nil {
		database.Passwords = make(map[string]*PasswordEntry)
	}
	if database.Devices == nil {
		database.Devices = make(map[string]*ClientDevice)
	}
	if database.CreateRequests == nil {
		database.CreateRequests = make(map[string]CreateRequestRecord)
	}
}

func applySharedDatabaseChangeLocked(oldDB, newDB *Database) {
	for password, oldEntry := range oldDB.Passwords {
		if oldEntry == nil || isPasswordExpired(oldEntry) || oldEntry.IsDeactivated {
			continue
		}
		newEntry, exists := newDB.Passwords[password]
		if !exists || newEntry == nil || isPasswordExpired(newEntry) || newEntry.IsDeactivated {
			disconnectCredentialConnections(password)
		}
	}
	if activePasswordSetChanged(oldDB, newDB) {
		if err := refreshWrapKeysFromDBLocked(); err != nil {
			log.Printf("[WRAP] Failed to refresh shared credentials: %v", err)
		}
	}
	if globalWgDev == nil {
		return
	}
	for deviceID, oldDevice := range oldDB.Devices {
		newDevice, exists := newDB.Devices[deviceID]
		if !exists || oldDevice.PubKey != newDevice.PubKey || oldDevice.IP != newDevice.IP || !sharedDeviceHasActiveOwner(newDB, deviceID, newDevice) {
			removePeerFromWG(globalWgDev, oldDevice)
		}
	}
	for deviceID, newDevice := range newDB.Devices {
		oldDevice, exists := oldDB.Devices[deviceID]
		if sharedDeviceHasActiveOwner(newDB, deviceID, newDevice) && (!exists || oldDevice.PubKey != newDevice.PubKey || oldDevice.IP != newDevice.IP || !sharedDeviceHasActiveOwner(oldDB, deviceID, oldDevice)) {
			upsertPeerInWG(globalWgDev, newDevice)
		}
	}
}

func activePasswordExists(database *Database, password string) bool {
	entry, exists := database.Passwords[password]
	return exists && !isPasswordExpired(entry) && !entry.IsDeactivated
}

func activePasswordSetChanged(oldDB, newDB *Database) bool {
	if oldDB.MainPassword != newDB.MainPassword || len(oldDB.Passwords) != len(newDB.Passwords) {
		return true
	}
	for password := range oldDB.Passwords {
		if activePasswordExists(oldDB, password) != activePasswordExists(newDB, password) {
			return true
		}
	}
	return false
}

func sharedDeviceHasActiveOwner(database *Database, deviceID string, device *ClientDevice) bool {
	if device == nil {
		return false
	}
	if database.MainPassword != "" && (device.OwnerID == wrapKeyID(database.MainPassword) || device.RawOwnerID == wrapKeyID(database.MainPassword)) {
		return true
	}
	for password, entry := range database.Passwords {
		if device.OwnerID == wrapKeyID(password) || device.RawOwnerID == wrapKeyID(password) || passwordEntryHasDevice(entry, deviceID) {
			return entry != nil && !isPasswordExpired(entry) && !entry.IsDeactivated
		}
	}
	return device.OwnerID == "" && device.RawOwnerID == ""
}

func (m *sharedStateMutex) Persist(data []byte) error {
	if m.store == nil {
		return errors.New("shared store is not configured")
	}
	if m.conn == nil {
		return errors.New("shared state save requires database lock")
	}
	revision, err := m.store.saveState(m.conn, data)
	if err != nil {
		m.forceReload = true
		return err
	}
	m.revision = revision
	return nil
}
