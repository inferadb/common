# AGENTS.md

## Running Benchmarks

The `inferadb-storage` crate includes Criterion benchmarks for measuring storage backend performance. These benchmarks run automatically in CI and compare against the main branch baseline.

## Critical Constraints

**These rules are non-negotiable:**

- No `unsafe` code
- No `.unwrap()` — use snafu `.context()`
- No `panic!`, `todo!()`, `unimplemented!()`
- No placeholder stubs — fully implement or don't write
- No TODO/FIXME/HACK comments
- No backwards compatibility shims or feature flags
- Write tests before implementation, target 90%+ coverage
- Never make git commits

## Serena (MCP Server)

Activate at session start: `mcp__plugin_serena_serena__activate_project`

**Use semantic tools, not file operations:**

| Task                 | Use                                            | Not                  |
| -------------------- | ---------------------------------------------- | -------------------- |
| Understand file      | `get_symbols_overview`                         | Reading entire file  |
| Find function/struct | `find_symbol` with pattern                     | Grep/glob            |
| Find usages          | `find_referencing_symbols`                     | Grep for text        |
| Edit function        | `replace_symbol_body`                          | Raw text replacement |
| Add code             | `insert_after_symbol` / `insert_before_symbol` | Line number editing  |
| Search patterns      | `search_for_pattern` with `relative_path`      | Global grep          |

**Symbol paths:** `ClassName/method_name` format. Patterns: `Foo` (any), `Foo/bar` (nested), `/Foo/bar` (exact root path).

**Workflow:**

1. `get_symbols_overview` first
2. `find_symbol` with `depth=1` to see methods without bodies
3. `include_body=True` only when needed
4. `find_referencing_symbols` before any refactor

## Task Completion

**A task is not complete until all of these pass — no "pre-existing issue" exceptions:**

- `cargo build --workspace` — no errors or warnings
- `cargo nextest run` — all tests pass
- `cargo +1.92 clippy --workspace --all-targets -- -D warnings` — no warnings
- `cargo +nightly fmt --all -- --check` — no formatting issues

**Review workflow:**

1. Run `just ci` — all checks must pass
2. Review changes with CodeRabbit: `mcp__coderabbit__review_changes`
3. Fix all identified issues — no exceptions
4. Re-review if fixes were substantial

## Code Conventions

**Builders (bon):**

- `#[builder(into)]` for `String` fields to accept `&str`
- Match `#[builder(default)]` with `#[serde(default)]` for config
- Fallible builders via `#[bon]` impl block when validation needed
- Prefer compile-time required fields over runtime checks

**Doc comments:** Use ` ```no_run ` — `cargo test` skips, `cargo doc` validates.

**Writing:** No filler (very, really, basically), no wordiness (in order to → to), active voice, specific language.

**Markdown:** Concise, kebab-case filenames, specify language in code blocks.

## Running Locally

```bash
# Run all storage benchmarks
cargo bench -p inferadb-storage

# Run specific benchmark group
cargo bench -p inferadb-storage -- get_operations

# Save a baseline for comparison
cargo bench -p inferadb-storage -- --save-baseline my-baseline

# Compare against a baseline
cargo bench -p inferadb-storage -- --baseline my-baseline
```

## Benchmark Groups

| Group                    | Description                                                   |
| ------------------------ | ------------------------------------------------------------- |
| `get_operations`         | Single key lookups (existing key, missing key, varying sizes) |
| `set_operations`         | Single key writes (new key, overwrite, varying value sizes)   |
| `delete_operations`      | Key deletion (existing key, missing key)                      |
| `get_range_operations`   | Range scans with varying result sizes and prefix patterns     |
| `clear_range_operations` | Range deletion with varying sizes                             |
| `transaction_operations` | Transaction commit with single/multiple operations            |
| `concurrent_operations`  | Parallel read/write workloads                                 |
| `ttl_operations`         | Time-to-live key operations                                   |
| `health_check`           | Backend health check overhead                                 |

## Interpreting Results

Criterion reports timing statistics with confidence intervals:

```
get_operations/get_existing_key
                        time:   [1.234 µs 1.256 µs 1.278 µs]
                        change: [-2.34% +0.12% +2.56%] (p = 0.89 > 0.05)
                        No change in performance detected.
```

- **time**: [lower bound, estimate, upper bound] at 95% confidence
- **change**: Percentage change from baseline [lower, estimate, upper]
- **p-value**: Statistical significance (p < 0.05 indicates significant change)

## CI Integration

- **PRs**: Benchmarks compare against the main branch baseline
- **Main branch**: Benchmarks save a new baseline for future comparisons
- **Regression alerts**: PRs with >10% performance regression receive a warning comment
- **Artifacts**: Full benchmark results are stored as CI artifacts for 30 days
