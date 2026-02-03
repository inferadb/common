# Default recipe
default: check

# Run all checks (build, clippy, test, fmt)
check: build clippy test fmt-check

# Build all targets
build:
    cargo +1.92 build --all-targets

# Run clippy lints
clippy:
    cargo +1.92 clippy --all-targets -- -D warnings

# Run all tests
test:
    cargo +1.92 test --all

# Check formatting
fmt-check:
    cargo +nightly fmt --check

# Format code
fmt:
    cargo +nightly fmt

# Check for unused dependencies
udeps:
    cargo +nightly udeps --all-targets

# Run all checks including udeps
check-all: check udeps

# Update dependencies to latest versions
update:
    ./scripts/update-dependencies.sh

# Clean build artifacts
clean:
    cargo clean
