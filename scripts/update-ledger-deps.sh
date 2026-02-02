#!/usr/bin/env bash
set -euo pipefail

# Update InferaDB Ledger dependencies to latest nightly versions from crates.io
#
# This script temporarily disables the [patch.crates-io] config to ensure
# we lock to actual crates.io versions, not local path dependencies.

CARGO_CONFIG=".cargo/config.toml"
CARGO_CONFIG_BAK=".cargo/config.toml.bak"

# Temporarily move cargo config if it exists (contains path overrides)
if [[ -f "$CARGO_CONFIG" ]]; then
    mv "$CARGO_CONFIG" "$CARGO_CONFIG_BAK"
    trap 'mv "$CARGO_CONFIG_BAK" "$CARGO_CONFIG"' EXIT
fi

# Update all dependencies - this re-resolves inferadb-ledger-sdk from crates.io
# (can't use -p because the lockfile may only have the path dependency version)
cargo update
