package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func isolatedPostgresTestURL(t *testing.T) string {
	t.Helper()
	databaseURL := os.Getenv("WDTT_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set WDTT_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	parsedURL, err := url.Parse(databaseURL)
	if err != nil || parsedURL.Scheme == "" {
		t.Fatalf("WDTT_TEST_DATABASE_URL must be a PostgreSQL URL")
	}
	schema := fmt.Sprintf("wdtt_test_%x", time.Now().UnixNano())
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to PostgreSQL test database: %v", err)
	}
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		conn.Close(ctx)
		t.Fatalf("create isolated test schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
		if err := conn.Close(ctx); err != nil {
			t.Errorf("close test database connection: %v", err)
		}
	})
	query := parsedURL.Query()
	query.Set("search_path", schema)
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

func TestPostgresStoreSharesStateChallengesAndPresence(t *testing.T) {
	databaseURL := isolatedPostgresTestURL(t)

	nodeA, err := newPostgresStore(databaseURL, "integration-node-a")
	if err != nil {
		t.Fatalf("open node A store: %v", err)
	}
	defer nodeA.Close()
	nodeB, err := newPostgresStore(databaseURL, "integration-node-b")
	if err != nil {
		t.Fatalf("open node B store: %v", err)
	}
	defer nodeB.Close()

	initial := &Database{
		Passwords:      make(map[string]*PasswordEntry),
		Devices:        make(map[string]*ClientDevice),
		CreateRequests: make(map[string]CreateRequestRecord),
	}
	if _, _, err := nodeA.Initialize(initial); err != nil {
		t.Fatalf("initialize node A: %v", err)
	}
	if _, _, err := nodeB.Initialize(initial); err != nil {
		t.Fatalf("initialize node B: %v", err)
	}

	credential := fmt.Sprintf("integration-password-%d", time.Now().UnixNano())
	conn, payload, _, err := nodeA.acquireState()
	if err != nil {
		t.Fatalf("lock node A state: %v", err)
	}
	state := &Database{}
	if err := json.Unmarshal(payload, state); err != nil {
		releasePostgresLock(context.Background(), conn, clusterStateLockClass, clusterStateLockID)
		conn.Release()
		t.Fatalf("decode shared state: %v", err)
	}
	normalizeDatabaseMaps(state)
	state.Passwords[credential] = &PasswordEntry{Label: "cluster test", MaxDevices: 4}
	state.CreateRequests["integration-idempotency"] = CreateRequestRecord{RequestHash: "request-hash", PasswordHash: "password-hash", CreatedAt: time.Now().Unix()}
	updated, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("encode shared state: %v", err)
	}
	if _, err := nodeA.saveState(conn, updated); err != nil {
		releasePostgresLock(context.Background(), conn, clusterStateLockClass, clusterStateLockID)
		conn.Release()
		t.Fatalf("save shared state: %v", err)
	}
	if err := releasePostgresLock(context.Background(), conn, clusterStateLockClass, clusterStateLockID); err != nil {
		t.Fatalf("unlock node A state: %v", err)
	}
	conn.Release()

	conn, payload, _, err = nodeB.acquireState()
	if err != nil {
		t.Fatalf("load node B state: %v", err)
	}
	state = &Database{}
	if err := json.Unmarshal(payload, state); err != nil {
		t.Fatalf("decode node B state: %v", err)
	}
	if state.Passwords[credential] == nil || state.CreateRequests["integration-idempotency"].PasswordHash != "password-hash" {
		t.Fatal("node B did not observe state committed by node A")
	}
	if err := releasePostgresLock(context.Background(), conn, clusterStateLockClass, clusterStateLockID); err != nil {
		t.Fatalf("unlock node B state: %v", err)
	}
	conn.Release()

	nonce := fmt.Sprintf("integration-nonce-%d", time.Now().UnixNano())
	if err := nodeA.AddProfileChallenge(nonce, time.Now().Add(time.Minute), profileChallengeMaxEntries); err != nil {
		t.Fatalf("create challenge on node A: %v", err)
	}
	if exists, err := nodeB.HasProfileChallenge(nonce, time.Now()); err != nil || !exists {
		t.Fatalf("node B challenge lookup = (%t, %v)", exists, err)
	}
	if consumed, err := nodeB.ConsumeProfileChallenge(nonce, time.Now()); err != nil || !consumed {
		t.Fatalf("node B challenge consume = (%t, %v)", consumed, err)
	}
	if consumed, err := nodeA.ConsumeProfileChallenge(nonce, time.Now()); err != nil || consumed {
		t.Fatalf("challenge was not single-use across nodes: (%t, %v)", consumed, err)
	}

	clientIP := fmt.Sprintf("198.51.100.%d", time.Now().UnixNano()%200+1)
	rateNow := time.Now()
	var allowedCount int64
	var rateWG sync.WaitGroup
	for request := 0; request < 400; request++ {
		rateWG.Add(1)
		go func(request int) {
			defer rateWG.Done()
			store := nodeA
			if request%2 == 1 {
				store = nodeB
			}
			allowed, err := store.AllowProfileChallenge(clientIP, rateNow, 400, 1, profileChallengeMaxBuckets, profileChallengeBucketTTL)
			if err != nil {
				t.Errorf("shared rate request %d failed: %v", request+1, err)
				return
			}
			if allowed {
				atomic.AddInt64(&allowedCount, 1)
			}
		}(request)
	}
	rateWG.Wait()
	if allowedCount != 400 {
		t.Fatalf("shared 400-request burst allowed %d requests, want 400", allowedCount)
	}
	if allowed, err := nodeB.AllowProfileChallenge(clientIP, rateNow, 400, 1, profileChallengeMaxBuckets, profileChallengeBucketTTL); err != nil || allowed {
		t.Fatalf("request beyond shared burst = (%t, %v), want rejected", allowed, err)
	}

	deviceID := fmt.Sprintf("integration-device-%d", time.Now().UnixNano())
	if err := nodeA.TrackActiveDevice(deviceID, 1); err != nil {
		t.Fatalf("track device on node A: %v", err)
	}
	active, err := nodeB.ActiveDeviceCount([]string{deviceID})
	if err != nil || active != 1 {
		t.Fatalf("node B active-device count = (%d, %v), want (1, nil)", active, err)
	}
	if err := nodeA.TrackActiveDevice(deviceID, -1); err != nil {
		t.Fatalf("untrack device on node A: %v", err)
	}
	active, err = nodeB.ActiveDeviceCount([]string{deviceID})
	if err != nil || active != 0 {
		t.Fatalf("node B active-device count after disconnect = (%d, %v), want (0, nil)", active, err)
	}
}

func TestPostgresStateLockPreventsLostUpdates(t *testing.T) {
	databaseURL := isolatedPostgresTestURL(t)
	stores := make([]*postgresStore, 2)
	for i := range stores {
		store, err := newPostgresStore(databaseURL, fmt.Sprintf("lock-test-node-%d", i))
		if err != nil {
			t.Fatalf("open node %d store: %v", i, err)
		}
		stores[i] = store
		defer store.Close()
	}
	if _, _, err := stores[0].Initialize(&Database{Passwords: map[string]*PasswordEntry{}, Devices: map[string]*ClientDevice{}}); err != nil {
		t.Fatalf("initialize state: %v", err)
	}

	const writers = 8
	const writesPerWorker = 10
	var wg sync.WaitGroup
	errors := make(chan error, writers)
	for worker := 0; worker < writers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			store := stores[worker%len(stores)]
			for write := 0; write < writesPerWorker; write++ {
				conn, payload, _, err := store.acquireState()
				if err != nil {
					errors <- err
					return
				}
				state := &Database{}
				if err := json.Unmarshal(payload, state); err != nil {
					releasePostgresLock(context.Background(), conn, clusterStateLockClass, clusterStateLockID)
					conn.Release()
					errors <- err
					return
				}
				normalizeDatabaseMaps(state)
				state.CreateRequests[fmt.Sprintf("%d-%d", worker, write)] = CreateRequestRecord{CreatedAt: time.Now().Unix()}
				updated, err := json.Marshal(state)
				if err == nil {
					_, err = store.saveState(conn, updated)
				}
				unlockErr := releasePostgresLock(context.Background(), conn, clusterStateLockClass, clusterStateLockID)
				conn.Release()
				if err != nil {
					errors <- err
					return
				}
				if unlockErr != nil {
					errors <- unlockErr
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}

	conn, payload, _, err := stores[0].acquireState()
	if err != nil {
		t.Fatalf("load final state: %v", err)
	}
	state := &Database{}
	if err := json.Unmarshal(payload, state); err != nil {
		t.Fatalf("decode final state: %v", err)
	}
	if got, want := len(state.CreateRequests), writers*writesPerWorker; got < want {
		t.Fatalf("concurrent shared writes = %d, want at least %d", got, want)
	}
	if err := releasePostgresLock(context.Background(), conn, clusterStateLockClass, clusterStateLockID); err != nil {
		t.Fatal(err)
	}
	conn.Release()
}
