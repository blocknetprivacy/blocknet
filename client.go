package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type CoreClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("API %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("API %d", e.StatusCode)
}

// NewCoreClient creates a client from an API address and cookie file path.
// The cookie file contains the bearer token written by the core on startup.
func NewCoreClient(apiAddr, cookiePath string) (*CoreClient, error) {
	token, err := readCookie(cookiePath)
	if err != nil {
		return nil, fmt.Errorf("read cookie %s: %w", cookiePath, err)
	}

	base := apiAddr
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	base = strings.TrimRight(base, "/")

	return &CoreClient{
		baseURL: base,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// NewCoreClientDirect creates a client with a known token (no cookie file).
func NewCoreClientDirect(apiAddr, token string) *CoreClient {
	base := apiAddr
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	base = strings.TrimRight(base, "/")

	return &CoreClient{
		baseURL: base,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *CoreClient) Get(ctx context.Context, path string) (json.RawMessage, error) {
	return c.do(ctx, http.MethodGet, path, nil)
}

func (c *CoreClient) Post(ctx context.Context, path string, body any) (json.RawMessage, error) {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		r = strings.NewReader(string(data))
	}
	return c.do(ctx, http.MethodPost, path, r)
}

// SSE opens a Server-Sent Events stream. It calls handler for each event
// until the context is cancelled or the connection drops. The event type
// and data fields are passed to the handler.
func (c *CoreClient) SSE(ctx context.Context, path string, handler func(event, data string)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	noTimeout := *c.httpClient
	noTimeout.Timeout = 0
	resp, err := noTimeout.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &APIError{StatusCode: resp.StatusCode}
	}

	scanner := bufio.NewScanner(resp.Body)
	var eventType, eventData string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			eventData = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case line == "":
			if eventData != "" {
				handler(eventType, eventData)
			}
			eventType = ""
			eventData = ""
		}
	}
	return scanner.Err()
}

// Status is a convenience for the health check endpoint (public, no auth).
func (c *CoreClient) Status(ctx context.Context) (json.RawMessage, error) {
	return c.Get(ctx, "/api/status")
}

func (c *CoreClient) do(ctx context.Context, method, path string, body io.Reader) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(respBody))
		// Try to extract an error message from JSON responses.
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			msg = errResp.Error
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Message: msg}
	}

	if len(respBody) == 0 {
		return nil, nil
	}
	return json.RawMessage(respBody), nil
}

func readCookie(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
