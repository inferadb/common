# Contributing

See the [main CONTRIBUTING guide](https://github.com/inferadb/inferadb/blob/main/CONTRIBUTING.md) for full details on:

- Commit message format (Conventional Commits)
- Version scheme (stable, canary, nightly)
- Review process

## Quick Start

1. Fork and clone the repository
2. Create a branch from `main`
3. Make changes and run `just check`
4. Submit a pull request

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <description>
```

| Type    | Version Bump | Example                           |
| ------- | ------------ | --------------------------------- |
| `feat`  | Minor        | `feat(storage): add batch writes` |
| `fix`   | Patch        | `fix(ledger): handle empty state` |
| `feat!` | Major        | `feat(api)!: rename Check method` |

PR titles follow the same format (squash merge uses PR title as commit).

## Reporting Issues

- **Bugs**: Search existing issues first. Include steps to reproduce.
- **Features**: Describe the use case and proposed solution.
- **Security**: Email [security@inferadb.com](mailto:security@inferadb.com) (do not open public issues).

## Pull Request Guidelines

- **PR title must follow Conventional Commits format** (validated by CI)
- Ensure `just check` passes
- Update documentation for API changes

## Code Standards

See [AGENTS.md](AGENTS.md) for coding conventions and constraints.

## License

Contributions are dual-licensed under [Apache 2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT).

## Questions

- Discord: [discord.gg/inferadb](https://discord.gg/inferadb)
- Email: [open@inferadb.com](mailto:open@inferadb.com)
