package main

import (
	"sync"
	"testing"
	"time"
)

func resetProfileChallengeStateForTest() {
	profileChallenges.Lock()
	profileChallenges.items = make(map[string]time.Time)
	profileChallenges.buckets = make(map[string]profileChallengeBucket)
	profileChallenges.Unlock()
}

func TestAllowProfileChallengeSupportsSharedNATBurst(t *testing.T) {
	resetProfileChallengeStateForTest()
	now := time.Unix(1_800_000_000, 0)
	for request := 0; request < 400; request++ {
		if !allowProfileChallenge("198.51.100.10", now) {
			t.Fatalf("request %d was rejected inside the 400-client burst", request+1)
		}
	}
}

func TestAllowProfileChallengeSupportsConcurrentSharedNATBurst(t *testing.T) {
	resetProfileChallengeStateForTest()
	now := time.Unix(1_800_000_000, 0)
	var wg sync.WaitGroup
	errors := make(chan int, 400)
	for request := 0; request < 400; request++ {
		wg.Add(1)
		go func(request int) {
			defer wg.Done()
			if !allowProfileChallenge("198.51.100.12", now) {
				errors <- request
			}
		}(request)
	}
	wg.Wait()
	close(errors)
	for request := range errors {
		t.Errorf("concurrent request %d was rejected inside the 400-client burst", request+1)
	}
}

func TestAllowProfileChallengeRefillsBucket(t *testing.T) {
	resetProfileChallengeStateForTest()
	now := time.Unix(1_800_000_000, 0)
	for request := 0; request < profileChallengeBurst; request++ {
		if !allowProfileChallenge("198.51.100.11", now) {
			t.Fatalf("request %d was rejected before the burst was exhausted", request+1)
		}
	}
	if allowProfileChallenge("198.51.100.11", now) {
		t.Fatal("request beyond the configured burst was accepted")
	}

	refilledAt := now.Add(time.Second)
	for request := 0; request < profileChallengeRatePerSecond; request++ {
		if !allowProfileChallenge("198.51.100.11", refilledAt) {
			t.Fatalf("request %d was rejected after one second of refill", request+1)
		}
	}
	if allowProfileChallenge("198.51.100.11", refilledAt) {
		t.Fatalf("request beyond the one-second refill (%d) was accepted", profileChallengeRatePerSecond)
	}
}

func TestCleanupProfileChallengeStateRemovesExpiredEntries(t *testing.T) {
	resetProfileChallengeStateForTest()
	now := time.Unix(1_800_000_000, 0)
	profileChallenges.Lock()
	profileChallenges.items["expired"] = now.Add(-time.Second)
	profileChallenges.items["fresh"] = now.Add(time.Second)
	profileChallenges.buckets["idle"] = profileChallengeBucket{tokens: 1, updatedAt: now.Add(-profileChallengeBucketTTL - time.Second)}
	profileChallenges.buckets["active"] = profileChallengeBucket{tokens: 1, updatedAt: now}
	profileChallenges.Unlock()

	cleanupProfileChallengeState(now)
	profileChallenges.Lock()
	defer profileChallenges.Unlock()
	if _, exists := profileChallenges.items["expired"]; exists {
		t.Fatal("expired nonce was not removed")
	}
	if _, exists := profileChallenges.items["fresh"]; !exists {
		t.Fatal("unexpired nonce was removed")
	}
	if _, exists := profileChallenges.buckets["idle"]; exists {
		t.Fatal("idle rate bucket was not removed")
	}
	if _, exists := profileChallenges.buckets["active"]; !exists {
		t.Fatal("active rate bucket was removed")
	}
}