# AGENTS.md

## Critical Constraints

**These rules are non-negotiable:**

- No `unsafe` code
- No `.unwrap()` in production code — propagate errors with `?` and `thiserror`
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

- `cargo +1.92 build --workspace --all-targets` — no errors or warnings
- `cargo +1.92 test --workspace` — all tests pass
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

**Doc comments:** Use ` ```no_run ` (never ignore or text) — `cargo test` skips, `cargo doc` validates. To avoid documentation compiling problems, instead use hidden setup lines.

**Writing:** No filler (very, really, basically), no wordiness (in order to → to), active voice, specific language.

**Markdown:** Concise, kebab-case filenames, specify language in code blocks.
