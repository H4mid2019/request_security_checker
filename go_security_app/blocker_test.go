package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func performStandaloneRequest(t *testing.T, method, path string, expectedStatus int) {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)

	rr := httptest.NewRecorder()

	authCheckHandler(rr, req)

	if status := rr.Code; status != expectedStatus {
		t.Errorf("Standalone handler returned wrong status code for %s %s: got %v want %v",
			method, path, status, expectedStatus)
	}

}

func TestStandaloneHandler(t *testing.T) {
	testCases := []struct {
		name           string
		method         string
		path           string // Includes query string
		expectedStatus int
	}{
		// Allowed Scenarios
		{"Allowed Root GET", "GET", "/", http.StatusOK},
		{"Allowed Path GET", "GET", "/some/valid/path", http.StatusOK},
		{"Allowed Path POST", "POST", "/api/submit", http.StatusOK},

		// Blocked Paths
		{"Blocked PHP Suffix", "GET", "/index.php", http.StatusForbidden},
		{"Blocked PHP Suffix Case", "GET", "/config.PHP", http.StatusForbidden},
		{"Blocked WP-Admin Prefix", "GET", "/wp-admin/options.php", http.StatusForbidden},
		{"Blocked WP-Includes Prefix", "GET", "/wp-includes/script.js", http.StatusForbidden},
		{"Blocked XMLRPC Exact", "GET", "/xmlrpc.php", http.StatusForbidden},
		{"Blocked Git Dir", "GET", "/.git/config", http.StatusForbidden},

		// Blocked Raw Query Substrings
		{"Blocked EL Injection Raw", "GET", "/search?q=test%24%7Bcode%7D", http.StatusForbidden},
		{"Blocked XSS Script Raw", "GET", "/page?data=%3Cscript", http.StatusForbidden},
		{"Blocked SQLi OR Raw", "GET", "/login?user=admin%27%20OR%20%271", http.StatusForbidden},
		{"Blocked Path Trav Raw Encoded", "GET", "/files?load=..%2F..%2Fetc/passwd", http.StatusForbidden},
		{"Blocked Path Trav Raw Decoded", "GET", "/files?load=../../etc/passwd", http.StatusForbidden},

		// Blocked Decoded Query Regex
		{"Blocked XSS Script Decoded", "GET", "/profile?bio=%3Cscript%3Ealert(1)%3C/script%3E", http.StatusForbidden},
		{"Blocked SQLi Comment Decoded", "GET", "/product?id=1%20--%20comment", http.StatusForbidden},
		{"Blocked EL Injection Decoded", "GET", "/api?action=$%7B1+1%7D", http.StatusForbidden},
	}

	for _, tt := range testCases {
		t.Run("Standalone_"+tt.name, func(t *testing.T) {
			performStandaloneRequest(t, tt.method, tt.path, tt.expectedStatus)
		})
	}
}

func performAuthCheck(t *testing.T, originalMethod, originalURI string, expectedStatus int) {
	t.Helper()

	// Simulate the sub-request Nginx makes to the auth endpoint
	req := httptest.NewRequest("GET", "/_auth_check", nil)

	req.Header.Set("X-Original-URI", originalURI)
	req.Header.Set("X-Original-Method", originalMethod)
	req.Header.Set("X-Real-IP", "192.168.1.100")

	rr := httptest.NewRecorder()

	authCheckHandler(rr, req)

	if status := rr.Code; status != expectedStatus {
		t.Errorf("Auth handler returned wrong status code for %s %s: got %v want %v",
			originalMethod, originalURI, status, expectedStatus)
	}
}

func TestAuthCheckHandler(t *testing.T) {
	testCases := []struct {
		name           string
		originalMethod string
		originalURI    string // Includes path AND query string
		expectedStatus int
	}{
		// Allowed Scenarios
		{"Allowed Root GET", "GET", "/", http.StatusOK},
		{"Allowed Path GET with Query", "GET", "/some/valid/path?user=1", http.StatusOK},
		{"Allowed Path POST", "POST", "/api/submit", http.StatusOK},

		// Blocked Paths
		{"Blocked PHP Suffix", "GET", "/index.php", http.StatusForbidden},
		{"Blocked WP-Admin Prefix", "GET", "/wp-admin/options.php", http.StatusForbidden},
		{"Blocked XMLRPC Exact", "GET", "/xmlrpc.php", http.StatusForbidden},

		// Blocked Raw Query Substrings
		{"Blocked EL Injection Raw", "GET", "/search?q=test%24%7Bcode%7D", http.StatusForbidden},
		{"Blocked XSS Script Raw", "GET", "/page?data=%3Cscript", http.StatusForbidden},
		{"Blocked SQLi OR Raw", "GET", "/login?user=admin%27%20OR%20%271", http.StatusForbidden},
		{"Blocked Path Trav Raw Encoded", "GET", "/files?load=..%2F..%2Fetc/passwd", http.StatusForbidden},

		// Blocked Decoded Query Regex
		{"Blocked XSS Script Decoded", "GET", "/profile?bio=%3Cscript%3Ealert(1)%3C/script%3E", http.StatusForbidden},
		{"Blocked SQLi Comment Decoded", "GET", "/product?id=1%20--%20comment", http.StatusForbidden},
		{"Blocked EL Injection Decoded", "GET", "/api?action=$%7B1+1%7D", http.StatusForbidden},
	}

	for _, tt := range testCases {
		t.Run("AuthCheck_"+tt.name, func(t *testing.T) {
			performAuthCheck(t, tt.originalMethod, tt.originalURI, tt.expectedStatus)
		})
	}
}

func setupMockRedis(t *testing.T) (*redis.Client, redismock.ClientMock, func()) {
	t.Helper()

	originalRedisClient := redisClient
	originalCooldown := cooldownMinutes

	cooldownMinutes = 1

	mockClient, mock := redismock.NewClientMock()

	redisClient = mockClient

	cleanup := func() {
		redisClient = originalRedisClient
		cooldownMinutes = originalCooldown
	}

	return mockClient, mock, cleanup
}

func TestRateLimitExpiration(t *testing.T) {

	_, mock, cleanup := setupMockRedis(t)
	defer cleanup()

	clientIP := "192.168.1.123"
	blockedKey := fmt.Sprintf("blocked:%s", clientIP)

	mock.ExpectGet(blockedKey).RedisNil()

	mockTime := time.Now().Add(time.Duration(cooldownMinutes) * time.Minute).Unix()
	mock.ExpectSet(
		blockedKey,
		mockTime,
		time.Duration(cooldownMinutes)*time.Minute,
	).SetVal("OK")

	mock.ExpectGet(blockedKey).SetVal(fmt.Sprintf("%d", mockTime))

	req1 := httptest.NewRequest("GET", "/_auth_check", nil)
	req1.Header.Set("X-Original-URI", "/wp-admin/index.php")
	req1.Header.Set("X-Original-Method", "GET")
	req1.Header.Set("X-Real-IP", clientIP)

	rr1 := httptest.NewRecorder()
	authCheckHandler(rr1, req1)
	assert.Equal(t, http.StatusForbidden, rr1.Code, "First request should be blocked due to invalid path")

	req2 := httptest.NewRequest("GET", "/_auth_check", nil)
	req2.Header.Set("X-Original-URI", "/valid/path")
	req2.Header.Set("X-Original-Method", "GET")
	req2.Header.Set("X-Real-IP", clientIP)

	rr2 := httptest.NewRecorder()
	authCheckHandler(rr2, req2)
	assert.Equal(t, http.StatusForbidden, rr2.Code, "Client should be blocked immediately after invalid request")

	mock.ExpectGet(blockedKey).RedisNil()

	req3 := httptest.NewRequest("GET", "/_auth_check", nil)
	req3.Header.Set("X-Original-URI", "/valid/path")
	req3.Header.Set("X-Original-Method", "GET")
	req3.Header.Set("X-Real-IP", clientIP)

	rr3 := httptest.NewRecorder()
	authCheckHandler(rr3, req3)
	assert.Equal(t, http.StatusOK, rr3.Code, "Client should be allowed after cooldown period")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Redis mock expectations were not met: %v", err)
	}
}

func TestRateLimitBlocking(t *testing.T) {
	_, mock, cleanup := setupMockRedis(t)
	defer cleanup()

	clientIP := "192.168.1.124"
	blockedKey := fmt.Sprintf("blocked:%s", clientIP)

	mock.ExpectGet(blockedKey).RedisNil()

	mockTime := time.Now().Add(time.Duration(cooldownMinutes) * time.Minute).Unix()
	mock.ExpectSet(
		blockedKey,
		mockTime,
		time.Duration(cooldownMinutes)*time.Minute,
	).SetVal("OK")

	mock.ExpectGet(blockedKey).SetVal(fmt.Sprintf("%d", mockTime))

	req1 := httptest.NewRequest("GET", "/_auth_check", nil)
	req1.Header.Set("X-Original-URI", "/wp-admin/config.php")
	req1.Header.Set("X-Original-Method", "GET")
	req1.Header.Set("X-Real-IP", clientIP)

	rr1 := httptest.NewRecorder()
	authCheckHandler(rr1, req1)
	assert.Equal(t, http.StatusForbidden, rr1.Code, "First request should be blocked due to invalid path")

	req2 := httptest.NewRequest("GET", "/_auth_check", nil)
	req2.Header.Set("X-Original-URI", "/valid/path")
	req2.Header.Set("X-Original-Method", "GET")
	req2.Header.Set("X-Real-IP", clientIP)

	rr2 := httptest.NewRecorder()
	authCheckHandler(rr2, req2)
	assert.Equal(t, http.StatusForbidden, rr2.Code, "Client should be blocked due to rate limiting")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Redis mock expectations were not met: %v", err)
	}
}

func TestRateLimitMultipleClients(t *testing.T) {
	_, mock, cleanup := setupMockRedis(t)
	defer cleanup()

	clientIP1 := "192.168.1.101"
	clientIP2 := "192.168.1.102"
	blockedKey1 := fmt.Sprintf("blocked:%s", clientIP1)
	blockedKey2 := fmt.Sprintf("blocked:%s", clientIP2)

	mock.ExpectGet(blockedKey1).RedisNil()

	mockTime := time.Now().Add(time.Duration(cooldownMinutes) * time.Minute).Unix()
	mock.ExpectSet(
		blockedKey1,
		mockTime,
		time.Duration(cooldownMinutes)*time.Minute,
	).SetVal("OK")

	mock.ExpectGet(blockedKey2).RedisNil()

	mock.ExpectGet(blockedKey1).SetVal(fmt.Sprintf("%d", mockTime))

	req1 := httptest.NewRequest("GET", "/_auth_check", nil)
	req1.Header.Set("X-Original-URI", "/wp-admin/index.php")
	req1.Header.Set("X-Original-Method", "GET")
	req1.Header.Set("X-Real-IP", clientIP1)

	rr1 := httptest.NewRecorder()
	authCheckHandler(rr1, req1)
	assert.Equal(t, http.StatusForbidden, rr1.Code)

	req2 := httptest.NewRequest("GET", "/_auth_check", nil)
	req2.Header.Set("X-Original-URI", "/valid/path")
	req2.Header.Set("X-Original-Method", "GET")
	req2.Header.Set("X-Real-IP", clientIP2)

	rr2 := httptest.NewRecorder()
	authCheckHandler(rr2, req2)
	assert.Equal(t, http.StatusOK, rr2.Code, "Second client should not be affected by first client's rate limit")

	req3 := httptest.NewRequest("GET", "/_auth_check", nil)
	req3.Header.Set("X-Original-URI", "/valid/path")
	req3.Header.Set("X-Original-Method", "GET")
	req3.Header.Set("X-Real-IP", clientIP1)

	rr3 := httptest.NewRecorder()
	authCheckHandler(rr3, req3)
	assert.Equal(t, http.StatusForbidden, rr3.Code, "First client should still be blocked")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Redis mock expectations were not met: %v", err)
	}
}
