package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

var blockedPathSuffixes = []string{
	".php", ".aspx", ".jsp", ".htaccess", ".htpasswd", ".git/", ".env",
}
var blockedPathPrefixes = []string{
	"/wp-admin/", "/wp-includes/", "/admin/", "/remote/", "/manager/",
}
var blockedExactPaths = []string{
	"/xmlrpc.php", "/config.json", "/configuration.php",
}
var blockedPathContains = []string{
	".git/", "wp-includes/", "wp-admin/", "admin/", "remote/", "manager/", "config.json", "configuration.php",
}
var suspiciousRawQuerySubstrings = []string{
	"%24%7B", "%3Cscript", "%27%20OR%20", "UNION%20SELECT", "%2E%2E%2F", "../", "etc/passwd", "eval(", "base64_decode", "()",
}
var suspiciousDecodedQueryRegex = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\s(SELECT|UNION|INSERT|UPDATE|DELETE)\s|\s(OR|AND)\s*['"]?1['"]?\s*=\s*['"]?1|--|#|\/\*.*\*\/)`),
	regexp.MustCompile(`(?i)(<script|onerror=|onload=|javascript:|alert\()`),
	regexp.MustCompile(`\${`),
	regexp.MustCompile(`(&&|\s*;\s*|\s*\|\s*|\s*` + "``" + `)`),
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func authCheckHandler(w http.ResponseWriter, r *http.Request) {

	originalURI := r.Header.Get("X-Original-URI")
	originalMethod := r.Header.Get("X-Original-Method")
	clientIP := r.Header.Get("X-Real-IP")
	forwardFor := r.Header.Get("X-Forwarded-For")

	if forwardFor != "" {
		parts := strings.Split(forwardFor, ",")
		if len(parts) > 0 {
			clientIP = strings.TrimSpace(parts[0])
		}
	}

	var parsedURI *url.URL
	var err error

	if originalURI == "" {
		parsedURI = r.URL
		originalURI = r.URL.String()
		originalMethod = r.Method
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
	} else {
		parsedURI, err = url.ParseRequestURI(originalURI)
		if err != nil {
			log.Printf("AuthCheck: BLOCK - Failed to parse original URI '%s' from %s: %v", originalURI, clientIP, err)
			http.Error(w, "Forbidden", http.StatusForbidden) // Block if URI is malformed
			return
		}
	}

	path := parsedURI.Path
	rawQuery := parsedURI.RawQuery

	log.Printf("AuthCheck: Checking request for %s [%s] From: %s", originalURI, originalMethod, clientIP)

	lowerPath := strings.ToLower(path)
	for _, pattern := range blockedPathContains {
		if strings.Contains(lowerPath, strings.ToLower(pattern)) {
			sendAuthBlockedResponse(w, clientIP, originalURI, fmt.Sprintf("Blocked path containing: %s", pattern))
			return
		}
	}
	for _, suffix := range blockedPathSuffixes {
		if strings.HasSuffix(lowerPath, strings.ToLower(suffix)) {
			sendAuthBlockedResponse(w, clientIP, originalURI, fmt.Sprintf("Blocked path suffix: %s", suffix))
			return
		}
	}
	for _, prefix := range blockedPathPrefixes {
		if strings.HasPrefix(lowerPath, strings.ToLower(prefix)) {
			sendAuthBlockedResponse(w, clientIP, originalURI, fmt.Sprintf("Blocked path prefix: %s", prefix))
			return
		}
	}
	for _, exactPath := range blockedExactPaths {
		if strings.EqualFold(path, exactPath) {
			sendAuthBlockedResponse(w, clientIP, originalURI, fmt.Sprintf("Blocked exact path: %s", exactPath))
			return
		}
	}

	if rawQuery != "" {
		lowerRawQuery := strings.ToLower(rawQuery)
		for _, pattern := range suspiciousRawQuerySubstrings {
			if strings.Contains(lowerRawQuery, strings.ToLower(pattern)) {
				sendAuthBlockedResponse(w, clientIP, originalURI, fmt.Sprintf("Blocked suspicious raw query substring: %s", pattern))
				return
			}
		}
		decodedQuery, err := url.QueryUnescape(rawQuery)
		if err == nil {
			for _, re := range suspiciousDecodedQueryRegex {
				if re.MatchString(decodedQuery) {
					sendAuthBlockedResponse(w, clientIP, originalURI, fmt.Sprintf("Blocked suspicious decoded query regex: %s", re.String()))
					return
				}
			}
		} else {
			log.Printf("AuthCheck: Warning: Query decode failed for '%s' from %s: %v", rawQuery, clientIP, err)
			// block based on decode failure
			// sendAuthBlockedResponse(w, clientIP, originalURI, "Blocked due to invalid query encoding")
			// return
		}
	}
	log.Printf("AuthCheck: ALLOW request for %s From: %s", originalURI, clientIP)
	w.WriteHeader(http.StatusOK)
}

func sendAuthBlockedResponse(w http.ResponseWriter, clientIP, originalURI, reason string) {
	log.Printf("AuthCheck: BLOCK request for %s [%s] From: %s", originalURI, reason, clientIP)
	http.Error(w, "Forbidden", http.StatusForbidden)
}

func main() {
	logFile := &lumberjack.Logger{
		Filename:   getEnv("LOG_FILE", "blocker.log"),
		MaxSize:    10, // megabytes
		MaxBackups: 2,
		MaxAge:     28,
		Compress:   true,
	}
	defer logFile.Close()
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	port := getEnv("PORT", "5000")
	http.HandleFunc("/", authCheckHandler)
	log.Printf("Starting Go security auth check server on port %s...", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
