# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-08-06

### Added
- Initial release
- Secure credential storage with Argon2id + AES-256-GCM encryption
- Git synchronization for backup and sharing
- Nested key support (e.g., service.username.field)
- Password rotation with `change-password` command
- Progress indicators for all operations
- Homebrew installation support

### Security
- 256MB Argon2id memory cost for strong KDF
- Automatic memory zeroization for sensitive data
- Hidden password input
- No recovery mechanism by design

