package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func main() {
	baseURL := "http://localhost:5000"
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Map of test descriptions to URIs with expected status codes
	// 403 = Blocked/Forbidden, 200 = OK/Allowed
	testCases := []struct {
		description string
		path        string
		queryParams map[string]string
		expected    int
	}{
		// Original test cases - all should be blocked
		{"XSS Attack", "/", map[string]string{"query": "<script>alert('XSS')</script>"}, 403},
		{"SQL Injection", "/", map[string]string{"query": "SELECT * FROM users WHERE username='admin' AND password='password'"}, 403},
		{"SQL DROP", "/", map[string]string{"query": "DROP TABLE users"}, 403},
		{"SQL UNION", "/", map[string]string{"query": "UNION SELECT username, password FROM users"}, 403},
		{"SQL OR Condition", "/", map[string]string{"query": "1 OR 1=1"}, 403},
		{"SQL Command Chain", "/", map[string]string{"query": "1; DROP TABLE users"}, 403},

		// Testing blocked path suffixes - all should be blocked
		{"PHP File", "/malicious.php", nil, 403},
		{"ASP File", "/config.aspx", nil, 403},
		{"JSP File", "/index.jsp", nil, 403},
		{"htaccess File", "/.htaccess", nil, 403},
		{"htpasswd File", "/.htpasswd", nil, 403},
		{"Git Folder", "/repo/.git/", nil, 403},
		{"Env File", "/.env", nil, 403},

		// Testing blocked path prefixes - all should be blocked
		{"WP Admin Path", "/wp-admin/index.php", nil, 403},
		{"WP Includes Path", "/wp-includes/script.js", nil, 403},
		{"Admin Dashboard", "/admin/dashboard", nil, 403},
		{"Remote Access", "/remote/access", nil, 403},
		{"Manager Login", "/manager/login", nil, 403},

		// Testing blocked exact paths - all should be blocked
		{"XML-RPC", "/xmlrpc.php", nil, 403},
		{"Config JSON", "/config.json", nil, 403},
		{"Configuration PHP", "/configuration.php", nil, 403},

		// Testing blocked path contains - all should be blocked
		{"Git Config", "/repository/.git/config", nil, 403},
		{"WP Includes Theme", "/themes/wp-includes/style.css", nil, 403},
		{"WP Admin Plugin", "/plugins/wp-admin/edit.php", nil, 403},
		{"Admin Console", "/console/admin/settings", nil, 403},
		{"Remote API", "/api/remote/data", nil, 403},
		{"Manager Dashboard", "/dashboard/manager/users", nil, 403},
		{"Config JSON File", "/app/config.json", nil, 403},
		{"Configuration PHP File", "/system/configuration.php", nil, 403},

		// Testing suspicious raw query substrings - all should be blocked
		{"EL Injection", "/", map[string]string{"query": "${system}"}, 403},
		{"XSS in Query", "/", map[string]string{"query": "<script>alert(1)</script>"}, 403},
		{"SQL OR in Query", "/", map[string]string{"query": "' OR 1=1"}, 403},
		{"UNION SELECT in Query", "/", map[string]string{"query": "UNION SELECT password FROM users"}, 403},
		{"Path Traversal", "/", map[string]string{"query": "../../etc/passwd"}, 403},
		{"Path Traversal Explicit", "/", map[string]string{"query": "../../../etc/passwd"}, 403},
		{"Cat Command", "/", map[string]string{"query": "cat /etc/passwd"}, 403},
		{"PHP Eval", "/", map[string]string{"query": "eval(base64_decode('PHN5c3RlbT4='))"}, 403},
		{"Base64 Decode", "/", map[string]string{"query": "base64_decode('PHN5c3RlbT4=')"}, 403},
		{"PHP Info", "/", map[string]string{"query": "phpinfo()"}, 403},

		// Testing suspicious decoded query regex patterns - all should be blocked
		{"SQL SELECT", "/", map[string]string{"query": "user' SELECT * FROM users"}, 403},
		{"SQL UNION SELECT", "/", map[string]string{"query": "user' UNION SELECT password FROM users"}, 403},
		{"SQL INSERT", "/", map[string]string{"query": "user' INSERT INTO users VALUES (1,'hack')"}, 403},
		{"SQL UPDATE", "/", map[string]string{"query": "user' UPDATE users SET admin=1"}, 403},
		{"SQL DELETE", "/", map[string]string{"query": "user' DELETE FROM users"}, 403},
		{"SQL OR Condition", "/", map[string]string{"query": "user' OR '1'='1"}, 403},
		{"SQL AND Condition", "/", map[string]string{"query": "user' AND '1'='1"}, 403},
		{"SQL Comment", "/", map[string]string{"query": "user'--comment"}, 403},
		{"SQL Hash Comment", "/", map[string]string{"query": "user'#comment"}, 403},
		{"SQL Block Comment", "/", map[string]string{"query": "user' /* SQL injection */"}, 403},
		{"XSS Cookie", "/", map[string]string{"query": "<script>document.cookie"}, 403},
		{"XSS Image Error", "/", map[string]string{"query": "<img onerror=alert(1)>"}, 403},
		{"XSS Div Load", "/", map[string]string{"query": "<div onload=alert(1)>"}, 403},
		{"JavaScript Protocol", "/", map[string]string{"query": "javascript:alert(1)"}, 403},
		{"EL Execution", "/", map[string]string{"query": "test${execute}"}, 403},
		{"Command And", "/", map[string]string{"query": "cat /etc/passwd && ls"}, 403},
		{"Command Chain", "/", map[string]string{"query": "ls ; rm -rf /"}, 403},
		{"Command Pipe", "/", map[string]string{"query": "echo 'evil' | grep e"}, 403},
		{"Command Backtick", "/", map[string]string{"query": "echo `whoami`"}, 403},

		// Some legitimate requests that should be allowed
		{"Root Path", "/", nil, 200},
		{"Index HTML", "/index.html", nil, 200},
		{"API Data", "/api/data", nil, 200},
		{"Normal Parameter", "/", map[string]string{"query": "normal_parameter"}, 200},
		{"Image File", "/images/logo.png", nil, 200},
	}

	passed := 0
	failed := 0

	for _, tc := range testCases {
		reqURL, err := url.Parse(baseURL)
		if err != nil {
			fmt.Printf("Error parsing URL: %v\n", err)
			continue
		}

		reqURL.Path = tc.path

		if tc.queryParams != nil {
			values := url.Values{}
			for key, value := range tc.queryParams {
				values.Add(key, value)
			}
			reqURL.RawQuery = values.Encode()
		}

		testURL := reqURL.String()
		fmt.Printf("Testing [%s]: %s\n", tc.description, testURL)

		resp, err := client.Get(testURL)
		if err != nil {
			fmt.Printf("Error sending request: %v\n", err)
			continue
		}

		if resp.StatusCode == tc.expected {
			fmt.Printf("✅ PASS: Got expected status %d\n", resp.StatusCode)
			passed++
		} else {
			fmt.Printf("❌ FAIL: Expected status %d, got %d\n", tc.expected, resp.StatusCode)
			failed++
		}

		resp.Body.Close()
		fmt.Println("----------------------------------------")
	}

	fmt.Printf("\nTest Summary: %d passed, %d failed\n", passed, failed)
}
