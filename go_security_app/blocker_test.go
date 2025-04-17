package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
