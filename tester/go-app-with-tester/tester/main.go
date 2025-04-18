package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	url := "http://localhost:5000"
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Map of URIs with expected status codes
	// 403 = Blocked/Forbidden, 200 = OK/Allowed
	uriTests := map[string]int{
		// Original test cases - all should be blocked
		"/?query=<script>alert('XSS')</script>":                                      403,
		"/?query=SELECT * FROM users WHERE username='admin' AND password='password'": 403,
		"/?query=DROP TABLE users":                                                   403,
		"/?query=UNION SELECT username, password FROM users":                         403,
		"/?query=1 OR 1=1":                                                           403,
		"/?query=1; DROP TABLE users":                                                403,

		// Testing blocked path suffixes - all should be blocked
		"/malicious.php": 403,
		"/config.aspx":   403,
		"/index.jsp":     403,
		"/.htaccess":     403,
		"/.htpasswd":     403,
		"/repo/.git/":    403,
		"/.env":          403,

		// Testing blocked path prefixes - all should be blocked
		"/wp-admin/index.php":    403,
		"/wp-includes/script.js": 403,
		"/admin/dashboard":       403,
		"/remote/access":         403,
		"/manager/login":         403,

		// Testing blocked exact paths - all should be blocked
		"/xmlrpc.php":        403,
		"/config.json":       403,
		"/configuration.php": 403,

		// Testing blocked path contains - all should be blocked
		"/repository/.git/config":       403,
		"/themes/wp-includes/style.css": 403,
		"/plugins/wp-admin/edit.php":    403,
		"/console/admin/settings":       403,
		"/api/remote/data":              403,
		"/dashboard/manager/users":      403,
		"/app/config.json":              403,
		"/system/configuration.php":     403,

		// Testing suspicious raw query substrings - all should be blocked
		"/?query=%24%7B%7Bsystem%7D%7D":                    403, // ${
		"/?query=%3Cscript%3Ealert(1)%3C/script%3E":        403, // <script>
		"/?query=%27%20OR%201=1":                           403, // ' OR
		"/?query=UNION%20SELECT%20password%20FROM%20users": 403, // UNION SELECT
		"/?query=%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd":  403, // ../../
		"/?query=../../../etc/passwd":                      403,
		"/?query=cat%20/etc/passwd":                        403,
		"/?query=eval(base64_decode('PHN5c3RlbT4='))":      403,
		"/?query=base64_decode('PHN5c3RlbT4=')":            403,
		"/?query=phpinfo()":                                403,

		// Testing suspicious decoded query regex patterns - all should be blocked
		"/?query=user' SELECT * FROM users":                 403,
		"/?query=user' UNION SELECT password FROM users":    403,
		"/?query=user' INSERT INTO users VALUES (1,'hack')": 403,
		"/?query=user' UPDATE users SET admin=1":            403,
		"/?query=user' DELETE FROM users":                   403,
		"/?query=user' OR '1'='1":                           403,
		"/?query=user' AND '1'='1":                          403,
		"/?query=user'--comment":                            403,
		"/?query=user'#comment":                             403,
		"/?query=user' /* SQL injection */":                 403,
		"/?query=<script>document.cookie":                   403,
		"/?query=<img onerror=alert(1)>":                    403,
		"/?query=<div onload=alert(1)>":                     403,
		"/?query=javascript:alert(1)":                       403,
		"/?query=test${execute}":                            403,
		"/?query=cat /etc/passwd && ls":                     403,
		"/?query=ls ; rm -rf /":                             403,
		"/?query=echo 'evil' | grep e":                      403,
		"/?query=echo `whoami`":                             403,

		// Some legitimate requests that should be allowed
		"/":                        200,
		"/index.html":              200,
		"/api/data":                200,
		"/?query=normal_parameter": 200,
		"/images/logo.png":         200,
	}

	passed := 0
	failed := 0

	for uri, expectedStatus := range uriTests {
		testURL := url + uri
		fmt.Printf("Testing URL: %s\n", testURL)
		resp, err := client.Get(testURL)
		if err != nil {
			fmt.Printf("Error sending request: %v\n", err)
			return
		}

		if resp.StatusCode == expectedStatus {
			fmt.Printf("✅ PASS: Got expected status %d\n", resp.StatusCode)
			passed++
		} else {
			fmt.Printf("❌ FAIL: Expected status %d, got %d\n", expectedStatus, resp.StatusCode)
			failed++
		}

		resp.Body.Close()
		fmt.Println("----------------------------------------")
	}

	fmt.Printf("\nTest Summary: %d passed, %d failed\n", passed, failed)
}
