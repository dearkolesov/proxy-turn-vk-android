package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type loadResults struct {
	mu         sync.Mutex
	latencies  []time.Duration
	statusCode map[int]int64
	errors     int64
}

func (r *loadResults) record(code int, elapsed time.Duration, err error) {
	r.mu.Lock()
	r.latencies = append(r.latencies, elapsed)
	r.statusCode[code]++
	if err != nil {
		r.errors++
	}
	r.mu.Unlock()
}

func main() {
	endpoint := flag.String("endpoint", "", "base profile API URL, for example http://127.0.0.1:56000")
	clients := flag.Int("clients", 400, "simulated devices sharing one profile password")
	duration := flag.Duration("duration", time.Minute, "test duration")
	interval := flag.Duration("interval", 8*time.Second, "delay between status requests per simulated device")
	flag.Parse()

	password := os.Getenv("PROFILE_PASSWORD")
	if *endpoint == "" || password == "" || *clients < 1 || *duration <= 0 || *interval <= 0 {
		fmt.Fprintln(os.Stderr, "usage: PROFILE_PASSWORD=<staging-key> go run scripts/profile-api-loadtest.go -endpoint http://host:56000 [-clients 400] [-duration 10m] [-interval 8s]")
		os.Exit(2)
	}
	baseURL := strings.TrimRight(*endpoint, "/")
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		fmt.Fprintf(os.Stderr, "invalid endpoint: %v\n", err)
		os.Exit(2)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = *clients
	transport.MaxIdleConnsPerHost = *clients
	transport.MaxConnsPerHost = *clients
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	keyID := profileKeyID(password)
	results := &loadResults{statusCode: make(map[int]int64)}
	var workers sync.WaitGroup
	for clientID := 0; clientID < *clients; clientID++ {
		workers.Add(1)
		go func(clientID int) {
			defer workers.Done()
			deviceID := fmt.Sprintf("loadtest-device-%06d", clientID)
			for ctx.Err() == nil {
				started := time.Now()
				code, err := runStatusCheck(ctx, client, baseURL, password, keyID, deviceID)
				results.record(code, time.Since(started), err)
				wait := time.NewTimer(*interval)
				select {
				case <-ctx.Done():
					if !wait.Stop() {
						select {
						case <-wait.C:
						default:
						}
					}
					return
				case <-wait.C:
				}
			}
		}(clientID)
	}
	workers.Wait()
	printResults(*clients, *duration, *interval, results)
}

func profileKeyID(password string) string {
	sum := sha256.Sum256([]byte("WDTT-PROFILE-ID-v1\x00" + password))
	return hex.EncodeToString(sum[:])
}

func runStatusCheck(ctx context.Context, client *http.Client, baseURL, password, keyID, deviceID string) (int, error) {
	challengeRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/profile/challenge", nil)
	if err != nil {
		return 0, err
	}
	challengeResponse, err := client.Do(challengeRequest)
	if err != nil {
		return 0, err
	}
	challengeBody, readErr := io.ReadAll(io.LimitReader(challengeResponse.Body, 64<<10))
	challengeResponse.Body.Close()
	if readErr != nil {
		return challengeResponse.StatusCode, readErr
	}
	if challengeResponse.StatusCode != http.StatusOK {
		return challengeResponse.StatusCode, nil
	}
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(challengeBody, &challenge); err != nil || challenge.Nonce == "" {
		if err == nil {
			err = fmt.Errorf("challenge response has no nonce")
		}
		return 0, err
	}

	mac := hmac.New(sha256.New, []byte(password))
	_, _ = mac.Write([]byte("status\n" + deviceID + "\n" + challenge.Nonce))
	form := url.Values{
		"device_id": {deviceID},
		"nonce":     {challenge.Nonce},
		"key_id":    {keyID},
		"proof":     {hex.EncodeToString(mac.Sum(nil))},
	}
	statusRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/profile/status", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	statusRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	statusResponse, err := client.Do(statusRequest)
	if err != nil {
		return 0, err
	}
	_, readErr = io.Copy(io.Discard, io.LimitReader(statusResponse.Body, 64<<10))
	statusResponse.Body.Close()
	if readErr != nil {
		return statusResponse.StatusCode, readErr
	}
	return statusResponse.StatusCode, nil
}

func printResults(clients int, duration, interval time.Duration, results *loadResults) {
	results.mu.Lock()
	latencies := append([]time.Duration(nil), results.latencies...)
	codes := make(map[int]int64, len(results.statusCode))
	for code, count := range results.statusCode {
		codes[code] = count
	}
	errors := results.errors
	results.mu.Unlock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Printf("clients=%d duration=%s interval=%s cycles=%d errors=%d\n", clients, duration, interval, len(latencies), errors)
	codeKeys := make([]int, 0, len(codes))
	for code := range codes {
		codeKeys = append(codeKeys, code)
	}
	sort.Ints(codeKeys)
	for _, code := range codeKeys {
		fmt.Printf("http_%d=%d\n", code, codes[code])
	}
	if len(latencies) == 0 {
		return
	}
	fmt.Printf("latency_p50=%s latency_p95=%s latency_p99=%s\n", percentile(latencies, 0.50), percentile(latencies, 0.95), percentile(latencies, 0.99))
}

func percentile(latencies []time.Duration, fraction float64) time.Duration {
	index := int(float64(len(latencies)-1) * fraction)
	return latencies[index]
}
