# request_security_checker

[![Test and Build](https://github.com/H4mid2019/request_security_checker/actions/workflows/test_builder.yml/badge.svg)](https://github.com/H4mid2019/request_security_checker/actions/workflows/test_builder.yml)

A small Go service that sits in front of an application and rejects obviously
malicious requests before they reach it. It plugs into Nginx as an
`auth_request` backend, so Nginx asks it about each request and drops the ones
it refuses.

The reason it exists: a Python application server has a limited number of
workers, and scanner traffic asking for `/wp-login.php` or
`/index.php?id=1' OR '1'='1` ties them up. Answering those in Go, in front of
the application, keeps them off the workers.

## What this demonstrates

- **Nginx `auth_request` integration.** The service answers 200 or 403 for a
  subrequest carrying the original URI, method and client IP. A sample
  [nginx.conf](nginx.conf) is in the repo.
- **Pattern matching on paths and query strings.** Requests for common
  vulnerable paths (PHP endpoints, admin panels, backup files) and query strings
  carrying SQL injection or XSS payloads are rejected.
- **Rate limiting with a cooldown, backed by Redis.** An IP that trips the
  filter repeatedly gets blocked for `COOLDOWN_MINUTES`. Keeping the counters in
  Redis rather than in process memory means several instances share one view of
  who is blocked, and a restart does not clear the blocklist.
- **Two modes.** It works as an Nginx auth backend or as a standalone
  pass-through checker.

## Run it

```bash
docker compose up -d
```

Or take a binary from the
[releases](https://github.com/H4mid2019/request_security_checker/releases) page:

```bash
wget https://github.com/H4mid2019/request_security_checker/releases/latest/download/request_security_checker-linux-amd64
chmod +x request_security_checker-linux-amd64
./request_security_checker-linux-amd64
```

## Nginx wiring

```nginx
location / {
    auth_request /auth;
    auth_request_set $auth_status $upstream_status;
    proxy_pass http://your_main_app;
}

location = /auth {
    internal;
    proxy_pass http://request_security_checker:5000;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Real-IP $remote_addr;
}
```

Redis is optional. Without it the service still filters requests; it just loses
the shared rate limiting.

## Configuration

| Variable           | Default          | Description |
| ------------------ | ---------------- | ----------- |
| `PORT`             | `5000`           | Listen port |
| `REDIS_ADDR`       | `localhost:6379` | Redis address |
| `REDIS_PASSWORD`   | empty            | |
| `REDIS_DB`         | `0`              | |
| `COOLDOWN_MINUTES` | `15`             | How long a tripped IP stays blocked |
| `LOG_FILE`         | `blocker.log`    | |

## Requirements

Go 1.24+ to build. Docker 28.0+ and Compose v2.35.0+ for the container setup.

## Tests

```bash
cd go_security_app && go test -race ./...
```

Covered today: the standalone handler, the `auth_request` handler, and rate
limiting across expiry, blocking, and multiple clients independently.

Not covered yet:

1. **The detection rules themselves.** They are exercised indirectly through the
   handlers, but there is no table-driven test listing payloads that must be
   blocked alongside benign requests that must not be. That second half matters
   more: a filter that blocks a legitimate query string is a worse outage than
   the scanner it was meant to stop.
2. **Throughput.** There is no benchmark in the repo, so this README does not
   quote a requests-per-second figure. `go test -bench` over the check function
   would give a real one.

## License

MIT
