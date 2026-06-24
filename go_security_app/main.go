package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"gopkg.in/natefinch/lumberjack.v2"
)

var blockedPathSuffixes = []string{
	".php", ".aspx", ".jsp", ".htaccess", ".htpasswd", ".git/", ".env",
}
var blockedPathContains = []string{
	".git/", "wp-includes/", "wp-admin/", "admin/", "remote/", "manager/",
	"xmlrpc.php", "config.json", "configuration.php",
}

// Encoded markers matched against the raw query before decoding, used as a
// fallback when the query has malformed encoding. Plain keywords are left to
// suspiciousDecodedQueryRegex so values like ?category= are not blocked.
var suspiciousRawQuerySubstrings = []string{
	"%24%7b", // ${
	"%3cscript",
	"%2e%2e%2f",
	"..%2f",
	"%2f..",
	"../",
	"%2fetc%2f",
	"etc/passwd",
}

// Checked against both the decoded path and query.
var commandInjectionRegex = regexp.MustCompile(
	"(?i)(&&|\\|\\||;\\s*\\w|\\s\\|\\s|`|\\$\\(|\\bcat\\s+/|\\beval\\(|base64_decode|phpinfo\\(\\)|system\\(\\)|exec\\(\\)|shell_exec\\(\\)|passthru\\()")

var suspiciousDecodedQueryRegex = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bunion\b\s+\bselect\b`),
	regexp.MustCompile(`(?i)\bselect\b\s+.*\bfrom\b`),
	regexp.MustCompile(`(?i)\binsert\b\s+\binto\b`),
	regexp.MustCompile(`(?i)\bupdate\b\s+.+\bset\b`),
	regexp.MustCompile(`(?i)\bdelete\b\s+\bfrom\b`),
	regexp.MustCompile(`(?i)\bdrop\b\s+\b(table|database)\b`),
	regexp.MustCompile(`(?i)\b(or|and)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+`),
	regexp.MustCompile(`(?i)['"]\s*\b(or|and)\b\s+['"\d]`),
	regexp.MustCompile(`(--|#|/\*.*?\*/)`),
	regexp.MustCompile(`(?i)(<script|<img|<svg|onerror\s*=|onload\s*=|javascript:|alert\s*\()`),
	regexp.MustCompile(`\$\{`),
	regexp.MustCompile(`(?i)(\.\./|\.\.\\|etc/passwd)`),
}

var redisClient *redis.Client
var ctx = context.Background()
var rateLimitingDisabled bool

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

var (
	cooldownMinutes = 15
)

func initRedis() {
	if rateLimitingDisabled {
		log.Println("Rate limiting is disabled via DISABLE_RATE_LIMIT environment variable")
		return
	}

	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")
	redisPassword := getEnv("REDIS_PASSWORD", "")
	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))

	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
	})

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Printf("Warning: Redis connection failed: %v. Will continue without rate limiting.", err)
	} else {
		log.Printf("Redis connected successfully at %s", redisAddr)
	}
}

func isClientBlocked(clientIP string) bool {
	if rateLimitingDisabled || redisClient == nil {
		return false
	}

	blockedKey := fmt.Sprintf("blocked:%s", clientIP)
	blockedUntil, err := redisClient.Get(ctx, blockedKey).Int64()
	if err == redis.Nil {
		return false
	}
	if err != nil {
		log.Printf("Redis error checking blocked status: %v", err)
		return false // On error, allow the request
	}

	return time.Now().Unix() < blockedUntil
}

func recordInvalidAttempt(clientIP string) {
	if rateLimitingDisabled || redisClient == nil {
		return
	}

	now := time.Now()
	blockedKey := fmt.Sprintf("blocked:%s", clientIP)

	blockedUntil := now.Add(time.Duration(cooldownMinutes) * time.Minute).Unix()

	err := redisClient.Set(ctx, blockedKey, blockedUntil, time.Duration(cooldownMinutes)*time.Minute).Err()
	if err != nil {
		log.Printf("Redis error setting blocked status: %v", err)
		return
	}

	log.Printf("RateLimit: Blocking client %s until %v (cooldown: %d minutes)",
		clientIP, time.Unix(blockedUntil, 0), cooldownMinutes)
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

	if isClientBlocked(clientIP) {
		log.Printf("RateLimit: BLOCK - Client %s is in cooldown period", clientIP)
		http.Error(w, "Too Many Invalid Requests", http.StatusForbidden)
		return
	}

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
			recordInvalidAttempt(clientIP)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	path := parsedURI.Path
	rawQuery := parsedURI.RawQuery

	log.Printf("AuthCheck: Checking request for %s [%s] From: %s", originalURI, originalMethod, clientIP)

	lowerPath := strings.ToLower(path)
	type pathCheck struct {
		patterns []string
		checkFn  func(path, pattern string) bool
		message  string
	}

	pathChecks := []pathCheck{
		{blockedPathContains, strings.Contains, "Blocked path containing"},
		{blockedPathSuffixes, strings.HasSuffix, "Blocked path suffix"},
	}

	for _, check := range pathChecks {
		for _, pattern := range check.patterns {
			if check.checkFn(lowerPath, pattern) {
				recordInvalidAttempt(clientIP)
				sendAuthBlockedResponse(w, clientIP, originalURI,
					fmt.Sprintf("%s: %s", check.message, pattern))
				return
			}
		}
	}

	if commandInjectionRegex.MatchString(path) {
		recordInvalidAttempt(clientIP)
		sendAuthBlockedResponse(w, clientIP, originalURI, "Blocked command injection in path")
		return
	}

	if rawQuery != "" {
		lowerRawQuery := strings.ToLower(rawQuery)
		for _, pattern := range suspiciousRawQuerySubstrings {
			if strings.Contains(lowerRawQuery, pattern) {
				recordInvalidAttempt(clientIP)
				sendAuthBlockedResponse(w, clientIP, originalURI, fmt.Sprintf("Blocked suspicious raw query substring: %s", pattern))
				return
			}
		}

		decodedQuery, err := url.QueryUnescape(rawQuery)
		if err == nil {
			for _, re := range suspiciousDecodedQueryRegex {
				if re.MatchString(decodedQuery) {
					recordInvalidAttempt(clientIP)
					sendAuthBlockedResponse(w, clientIP, originalURI, fmt.Sprintf("Blocked suspicious decoded query regex: %s", re.String()))
					return
				}
			}

			if commandInjectionRegex.MatchString(decodedQuery) {
				recordInvalidAttempt(clientIP)
				sendAuthBlockedResponse(w, clientIP, originalURI, "Blocked command injection in query")
				return
			}
		} else {
			log.Printf("AuthCheck: Warning: Query decode failed for '%s' from %s: %v", rawQuery, clientIP, err)
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

	if val := getEnv("COOLDOWN_MINUTES", ""); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
			cooldownMinutes = parsed
		}
	}

	// Check if rate limiting should be disabled
	disableRateLimit := getEnv("DISABLE_RATE_LIMIT", "")
	rateLimitingDisabled = disableRateLimit != ""

	initRedis()

	port := getEnv("PORT", "5000")
	http.HandleFunc("/", authCheckHandler)
	log.Printf("Starting Go security auth check server on port %s...", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
