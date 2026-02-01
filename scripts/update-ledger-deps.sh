#!/usr/bin/env bash
set -euo pipefail

# Update InferaDB Ledger dependencies to latest nightly versions from crates.io

cargo update \
    -p inferadb-ledger-raft \
    -p inferadb-ledger-sdk \
    -p inferadb-ledger-state \
    -p inferadb-ledger-store \
    -p inferadb-ledger-types
