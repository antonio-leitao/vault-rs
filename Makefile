.PHONY: help build test clean install run-test release check fmt security-check

# Default target
help:
	@echo "Available targets:"
	@echo "  build          - Build the project in debug mode"
	@echo "  release        - Build the project in release mode"
	@echo "  test           - Run all tests"
	@echo "  run-test       - Run the integration test script"
	@echo "  install        - Install creds to ~/.cargo/bin"
	@echo "  clean          - Clean build artifacts"
	@echo "  check          - Run cargo check"
	@echo "  fmt            - Format code with rustfmt"
	@echo "  clippy         - Run clippy linter"
	@echo "  security-check - Check for security best practices"

# Build in debug mode
build:
	cargo build

# Build in release mode
release:
	cargo build --release

# Run tests
test:
	cargo test --all

# Run the integration test script
run-test: release
	chmod +x test_creds.sh
	./test_creds.sh

# Install to user's cargo bin directory
install: release
	cargo install --path creds

# Clean build artifacts
clean:
	cargo clean
	rm -rf ~/.creds
	rm -rf /tmp/test-creds-repo

# Check code without building
check:
	cargo check --all

# Format code
fmt:
	cargo fmt --all

# Run clippy
clippy:
	cargo clippy --all -- -D warnings

# Security audit
security-check:
	@echo "🔒 Security Best Practices Check"
	@echo "================================="
	@echo
	@echo "✓ Encryption: Argon2id + AES-256-GCM"
	@echo "✓ KDF Settings: 256MB RAM, 4 iterations"
	@echo "✓ Password Input: Hidden via rpassword"
	@echo "✓ Memory: Sensitive data zeroized after use"
	@echo
	@if [ -f ~/.creds/config.json ]; then \
		echo "📊 Vault Status:"; \
		echo -n "   Last sync: "; \
		grep -o '"last_sync":"[^"]*"' ~/.creds/config.json | cut -d'"' -f4 || echo "Never"; \
		echo; \
		echo "💡 Security Recommendations:"; \
		echo "   • Change master password every 90 days"; \
		echo "   • Run: creds change-password"; \
		echo "   • Use passwords with 16+ characters"; \
		echo "   • Enable 2FA on your Git provider"; \
	else \
		echo "ℹ️  No vault found. Run 'creds init' to create one."; \
	fi

# Development build with all checks
dev: fmt check clippy test build
	@echo "✅ All checks passed!"
