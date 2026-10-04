package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	vkHashCheckClientID     = "6287487"
	vkHashCheckClientSecret = "MuAxFaKDYDOICzGnEOhp"
)

type vkHashCheckResult struct {
	Hash    string `json:"hash"`
	Working bool   `json:"working"`
	Reason  string `json:"reason,omitempty"`
}

func newVKHashCheckClient(proxyURL string) (*http.Client, error) {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return &http.Client{Timeout: 20 * time.Second}, nil
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("proxy_url must be a complete socks5:// or http:// URL")
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	switch strings.ToLower(parsed.Scheme) {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if parsed.User != nil {
			password, _ := parsed.User.Password()
			auth = &proxy.Auth{User: parsed.User.Username(), Password: password}
		}
		dialer, dialErr := proxy.SOCKS5("tcp", parsed.Host, auth, proxy.Direct)
		if dialErr != nil {
			return nil, fmt.Errorf("configure SOCKS5 proxy: %w", dialErr)
		}
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		}
	case "http", "https":
		transport.Proxy = http.ProxyURL(parsed)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q; use socks5 or http", parsed.Scheme)
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}, nil
}

func checkVKHashes(ctx context.Context, hashes []string, proxyURL string) ([]vkHashCheckResult, error) {
	client, err := newVKHashCheckClient(proxyURL)
	if err != nil {
		return nil, err
	}
	token, err := getVKAnonymousToken(ctx, client)
	if err != nil {
		return nil, err
	}
	results := make([]vkHashCheckResult, 0, len(hashes))
	for _, hash := range hashes {
		result := vkHashCheckResult{Hash: hash}
		working, reason := checkVKHash(ctx, client, token, hash)
		result.Working = working
		result.Reason = reason
		results = append(results, result)
	}
	return results, nil
}

func getVKAnonymousToken(ctx context.Context, client *http.Client) (string, error) {
	form := url.Values{
		"client_id":     {vkHashCheckClientID},
		"token_type":    {"messages"},
		"client_secret": {vkHashCheckClientSecret},
		"version":       {"1"},
		"app_id":        {vkHashCheckClientID},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://login.vk.ru/?act=get_anonym_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
		Error json.RawMessage `json:"error"`
	}
	if err := doVKJSON(client, request, &response); err != nil {
		return "", err
	}
	if response.Data.AccessToken == "" {
		return "", fmt.Errorf("VK anonymous token was not returned")
	}
	return response.Data.AccessToken, nil
}

func checkVKHash(ctx context.Context, client *http.Client, token, hash string) (bool, string) {
	form := url.Values{
		"vk_join_link": {"https://vk.com/call/join/" + hash},
		"fields":       {"photo_200"},
		"access_token": {token},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+vkHashCheckClientID, strings.NewReader(form.Encode()))
	if err != nil {
		return false, "request setup failed"
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		Response json.RawMessage `json:"response"`
		Error    struct {
			Code    int    `json:"error_code"`
			Message string `json:"error_msg"`
		} `json:"error"`
	}
	if err := doVKJSON(client, request, &response); err != nil {
		return false, err.Error()
	}
	if len(response.Response) > 0 && string(response.Response) != "null" {
		return true, ""
	}
	if response.Error.Message != "" {
		return false, fmt.Sprintf("VK %d: %s", response.Error.Code, response.Error.Message)
	}
	return false, "VK returned no call preview"
}

func doVKJSON(client *http.Client, request *http.Request, target interface{}) error {
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("VK HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode VK response: %w", err)
	}
	return nil
}
