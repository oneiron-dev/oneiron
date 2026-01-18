# Oneiron

> A memory engine for AI systems that need to remember.

Oneiron gives AI systems:

- **Persistence** — memories survive context window resets
- **Continuity** — identity, preferences, and relationships maintained over time
- **Retrieval** — relevant memories surface when needed
- **Consent** — users control what's remembered about them

## Packages

| Package | Description |
|---------|-------------|
| `@oneiron/core` | Domain types and utilities |
| `@oneiron/api` | Convex backend (data plane) |
| `@oneiron/sdk` | TypeScript client |

## Quick Start

```bash
# Install dependencies
bun install

# Start development
bun run dev

# Run tests
bun test
```

## Architecture

See the [architecture documentation](https://docs.oneiron.dev) for details on:

- Entity types and the graph model
- Claims and the predicate registry
- Retrieval and ranking
- Access control and deletion guarantees

## License

Apache 2.0 - see [LICENSE](./LICENSE)
