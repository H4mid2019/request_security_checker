# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2025-04-18

### Added
- New patterns for blocking malicious requests
- Log files added to .gitignore

### Changed
- Updated integration tests

### Removed
- Unnecessary files cleaned up

## [1.0.3] - 2025-04-17

### Added

- Support for macOS M-series processors (ARM64)
- Official Windows AMD64 builds
- Improved CI/CD pipeline for multi-platform releases

### Changed

- Enhanced build process for cross-platform compatibility
- Updated documentation for platform-specific installation

## [1.0.0] - 2025-04-17

### Added

- Initial release of the request security checker
- Core functionality for validating HTTP requests
- Security scanning for common vulnerabilities
- Configuration options for custom security rules
- Comprehensive documentation

### Security

- Implemented validation for input url path
- Added protection against common injection attacks
- Rate limit
