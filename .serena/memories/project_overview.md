# InferaDB Common - Project Overview

## Purpose
Shared library crates for InferaDB: storage abstraction, authentication, and ledger-backed storage.

## Tech Stack
- Rust workspace with 4 crates: `storage`, `authn`, `storage-ledger`, `proto-ledger`
- Async runtime: Tokio
- Builder pattern: `bon`
- Caching: `moka`
- Error handling: `snafu` style with thiserror
- Serialization: `serde` (JSON)

## Crate Structure
- `crates/storage/` — Core `StorageBackend` trait, `MemoryBackend`, error types, metrics
- `crates/authn/` — JWT validation, signing key cache, authentication
- `crates/storage-ledger/` — `LedgerBackend` implementing `StorageBackend` via Ledger SDK
- `crates/proto-ledger/` — Protobuf definitions for Ledger

## Key Commands
- Build: `cargo build --workspace`
- Test: `cargo test --workspace`
- Clippy: `cargo +1.92 clippy --workspace --all-targets -- -D warnings`
- Format: `cargo +nightly fmt --all -- --check`
- Format fix: `cargo +nightly fmt --all`

## Conventions
- `#![deny(unsafe_code)]`
- No `.unwrap()`, `panic!`, `todo!()`, `unimplemented!()`
- `#[non_exhaustive]` on public error enums
- `#[builder(into)]` for String fields with bon
- Doc comments use ` ```no_run `
