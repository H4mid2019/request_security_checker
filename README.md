# Request Security Checker

[![Test and Build](https://github.com/H4mid2019/request_security_checker/actions/workflows/test_builder.yml/badge.svg)](https://github.com/H4mid2019/request_security_checker/actions/workflows/test_builder.yml)

## Overview

```markdown
Request Security Checker is a high-performance security middleware designed to protect web applications 
from malicious requests. Built in Go, it acts as a protective shield in front of your main application, 
particularly beneficial for Python applications that may struggle with handling high request volumes.
```

## Why Use This?

```markdown
- **Reduce Load on Main Application**: Filters out malicious requests before they reach your main app
- **Protect Against Common Attacks**: Blocks SQL injection, XSS, path traversal, and other attack patterns
- **Rate Limiting**: Automatically blocks IPs that send suspicious requests
- **High Performance**: Written in Go for excellent throughput (handles thousands of requests per second)
- **Easy Integration**: Works with Nginx and other reverse proxies
```

## Features

```markdown
- **Path Security**: Blocks suspicious paths (PHP files, admin pages, etc.)
- **Query Parameter Analysis**: Detects SQL injection and XSS attempts
- **Rate Limiting**: Blocks repeat offenders with configurable cooldown periods
- **Redis Integration**: Distributed rate limiting for multi-instance deployments
```

## Requirements

```markdown
- Go 1.24+ (for building)
- Docker 28.0+ and Docker Compose v2.35.0+ (for containerized deployment)
- Redis (optional, for distributed rate limiting)
```

## Quick Start

### Using Docker Compose

```bash
# Clone the repository
git clone https://github.com/H4mid2019/request_security_checker.git
cd request_security_checker

# Start the service
docker-compose up -d
```

### Using Pre-built Binaries

```markdown
Download the latest binary for your platform from the [Releases](https://github.com/H4mid2019/request_security_checker/releases) page.
```

```bash
# Download (replace with your architecture)
wget https://github.com/H4mid2019/request_security_checker/releases/latest/download/request_security_checker-linux-amd64

# Make executable
chmod +x request_security_checker-linux-amd64

# Run
./request_security_checker-linux-amd64
```

## Configuration

```markdown
Configuration is done via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5000` | Port to listen on |
| `REDIS_ADDR` | `localhost:6379` | Redis server address |
| `REDIS_PASSWORD` | `` | Redis password |
| `REDIS_DB` | `0` | Redis database |
| `COOLDOWN_MINUTES` | `15` | Duration to block IPs after violation |
| `LOG_FILE` | `blocker.log` | Log file location |
```

## Integration with Nginx

```nginx
location / {
    auth_request /auth;
    auth_request_set $auth_status $upstream_status;
    
    # Your main app
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

A sample Nginx config is in repo. [nginx.conf](nginx.conf)

## Building from Source

```bash
# Clone the repository
git clone https://github.com/H4mid2019/request_security_checker.git
cd request_security_checker/go_security_app

# Build
go build -o request_security_checker

# Run
./request_security_checker
```

## License

```markdown
MIT License - See [LICENSE](LICENSE) for details.
```

## Contributing

```markdown
Contributions are welcome! Please feel free to submit a Pull Request.
```