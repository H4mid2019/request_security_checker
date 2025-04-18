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
	"cat", "passwd", "%2Fetc%2F", "%2F..%2F", "..%2F", "%2F..", "phpinfo", "%28%29",
	"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "alert(", "onerror=", "onload=", "'OR", "OR'", "'AND", "AND'",
}

var commandInjectionPatterns = []string{
	`\|\s*\w+`,
	`echo\s+['"]?.*['"]?\s*\|`,
	`[;&\|\\` + "`" + `]\s*\w+`,
	`\$\(\w+`,
	`\` + "`" + `\w+`,
	`echo ['"].*?['"].*?\|.*?grep`, // Specifically match "echo 'evil' | grep e"
	`%7C`,                          // URL encoded pipe character |
	`echo`,                         // detects the "echo" command
}

var suspiciousDecodedQueryRegex = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\s(SELECT|UNION|INSERT|UPDATE|DELETE)\s|\s(OR|AND)\s*['"]?1['"]?\s*=\s*['"]?1|--|#|\/\*.*\*\/)`),
	regexp.MustCompile(`(?i)(<script|onerror=|onload=|javascript:|alert\()`),
	regexp.MustCompile(`\${`),
	regexp.MustCompile(`(&&|\s*;\s*|\s*\|\s*|\s*` + "``" + `)`),

	regexp.MustCompile(`(?i)(\.\.\/|\.\.\\|etc\/passwd)`),
	regexp.MustCompile(`(?i)(cat\s+.*passwd|ls\s+|rm\s+)`),
	regexp.MustCompile(`(?i)(phpinfo\(\)|system\(\)|exec\(\)|shell_exec\(\)|passthru\(\)|eval\()`),

	regexp.MustCompile(`(?i)(\s+(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+|'.*?(OR|AND)\s*['"]?[01]['"]?\s*=\s*['"]?[01]|--|#|\/\*.*?\*\/)`),
	regexp.MustCompile(`(?i)(<script|<img|onerror=|onload=|javascript:|alert\()`),
	regexp.MustCompile(`(?i)(\$\{|\s*\|\s*|\s*;\s*|\s*&&\s*|\s*\|\|\s*|\s*` + "`" + `)`),
	regexp.MustCompile(`(?i)(UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+.*?\s+SET)`),
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
		patterns    []string
		checkFn     func(path, pattern string) bool
		isEqualFold bool
		message     string
	}

	pathChecks := []pathCheck{
		{blockedPathContains, strings.Contains, false, "Blocked path containing"},
		{blockedPathSuffixes, strings.HasSuffix, false, "Blocked path suffix"},
		{blockedPathPrefixes, strings.HasPrefix, false, "Blocked path prefix"},
		{blockedExactPaths, strings.EqualFold, true, "Blocked exact path"},
		{commandInjectionPatterns, strings.Contains, false, "Blocked command injection pattern"},
	}

	for _, check := range pathChecks {
		for _, pattern := range check.patterns {
			patternLower := strings.ToLower(pattern)
			var match bool
			if check.isEqualFold {
				match = check.checkFn(path, pattern)
			} else {
				match = check.checkFn(lowerPath, patternLower)
			}

			if match {
				recordInvalidAttempt(clientIP)
				sendAuthBlockedResponse(w, clientIP, originalURI,
					fmt.Sprintf("%s: %s", check.message, pattern))
				return
			}
		}
	}

	if rawQuery != "" {
		lowerRawQuery := strings.ToLower(rawQuery)
		for _, pattern := range suspiciousRawQuerySubstrings {
			if strings.Contains(lowerRawQuery, strings.ToLower(pattern)) {
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

			for _, pattern := range commandInjectionPatterns {
				if strings.Contains(strings.ToLower(decodedQuery), strings.ToLower(pattern)) {
					recordInvalidAttempt(clientIP)
					sendAuthBlockedResponse(w, clientIP, originalURI,
						fmt.Sprintf("Blocked command injection in query: %s", pattern))
					return
				}
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
