# InferaDB Common

Shared storage abstractions for InferaDB services.

## Crates

| Crate | Description |
|-------|-------------|
| `inferadb-storage` | Storage backend trait and in-memory implementation |
| `inferadb-storage-ledger` | Ledger-backed storage implementation |

## Requirements

- Rust 1.92+ (2024 edition)
- Rust nightly (for formatting)

## Development

```bash
just check      # build + clippy + test + fmt-check
just fmt        # format code
just udeps      # check unused dependencies
just check-all  # full check including udeps
```

Or without just:

```bash
cargo +1.92 build --all-targets
cargo +1.92 clippy --all-targets -- -D warnings
cargo +1.92 test --all
cargo +nightly fmt
cargo +nightly udeps --all-targets
```

## License

Dual-licensed under [Apache 2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT).
