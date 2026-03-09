# Agent Skills & TanStack Intent — SDK Research

> Source: [TanStack Blog: From Docs to Agents](https://tanstack.com/blog/from-docs-to-agents)
> Spec: [agentskills.io](https://agentskills.io)
> Date reviewed: 2026-03-09

## Problem Statement

Library knowledge lives in docs and types, but there's no versioned delivery mechanism
connecting it to AI coding agents. Model training data mixes versions permanently
("split-brain"), community rules files go stale, and discovery is entirely manual.

## Agent Skills Spec (Open Standard)

An open format originally developed by Anthropic for giving agents new capabilities.
A skill is a directory with a `SKILL.md` file containing YAML frontmatter + Markdown instructions.

### Directory Structure

```
skill-name/
├── SKILL.md          # Required: instructions + metadata
├── scripts/          # Optional: executable code
├── references/       # Optional: documentation
└── assets/           # Optional: templates, resources
```

### SKILL.md Format

```yaml
---
name: skill-name              # required, max 64 chars, lowercase + hyphens
description: What it does...   # required, max 1024 chars
license: Apache-2.0            # optional
compatibility: Requires git... # optional, max 500 chars
metadata:                      # optional, arbitrary key-value
  author: example-org
  version: "1.0"
allowed-tools: Bash(git:*) Read  # optional, experimental
---

# Markdown instructions follow...
```

### Progressive Disclosure

1. **Discovery** (~100 tokens): name + description loaded at startup for all skills
2. **Activation** (< 5000 tokens recommended): full SKILL.md loaded on match
3. **Execution**: scripts/references/assets loaded only when needed

### Adopting Agents/Tools

Massive adoption across the ecosystem:
- **Claude Code**, **Claude AI** (Anthropic)
- **VS Code**, **GitHub Copilot** (Microsoft)
- **OpenAI Codex**
- **Cursor**, **Amp**, **Goose**, **Roo Code**
- **Gemini CLI** (Google)
- **Junie** (JetBrains)
- **Databricks**, **Snowflake**
- **Spring AI**, **Laravel Boost**
- **Mistral AI Vibe**, **Letta**, **OpenHands**
- 30+ total integrations

### Validation

Reference library at [github.com/agentskills/agentskills](https://github.com/agentskills/agentskills):
```bash
skills-ref validate ./my-skill
```

## TanStack Intent — Skills-in-Package Distribution

TanStack Intent is a CLI + workflow that ships Agent Skills **inside npm packages**,
so knowledge travels with code and stays version-pinned.

### Key Insight

Skills are derived from docs with `metadata.sources` linking back to source files.
When you `npm update`, skills update too — no stale `.cursorrules` or community files.

### Skill Frontmatter Example

```yaml
---
name: tanstack-router-search-params
description: Type-safe search param patterns for TanStack Router...
metadata:
  sources:
    - docs/framework/react/guide/search-params.md
---
```

Skills include positive patterns *and* explicit anti-patterns (marked with ❌).

### CLI Commands (`@tanstack/intent`)

| Command | Purpose |
|---------|---------|
| `npx @tanstack/intent scaffold` | Generate skill drafts from docs |
| `npx @tanstack/intent validate` | Check well-formedness |
| `npx @tanstack/intent install` | Auto-discover intent-enabled packages in `node_modules`, wire into agent config |
| `npx @tanstack/intent stale` | Detect drift from source docs |
| `npx @tanstack/intent stale --json` | CI-friendly staleness check |
| `npx @tanstack/intent list` | Show available skills |
| `npx @tanstack/intent feedback` | Submit structured bug reports |
| `npx @tanstack/intent setup-github-actions` | CI integration |
| `npx @tanstack/intent meta` | View meta-skills for maintainers |

### Distribution Model

- Skills ship **inside the npm package** — no separate registry
- `npm update` delivers updated skills automatically
- Skills are pinned to the installed package version
- Config targets: `CLAUDE.md`, `.cursorrules`

### First Implementations

- TanStack Router, Query, Table, DB
- Reference PR: [TanStack/db#1330](https://github.com/TanStack/db/pull/1330)
- GitHub: [github.com/TanStack/intent](https://github.com/TanStack/intent)

## Relevance to Oneiron SDK

### If We Build an npm/PyPI Package

1. **Ship Agent Skills with the package** — follow TanStack Intent's model
2. Skills could cover:
   - Oneiron schema patterns and best practices
   - Embedding model configuration
   - Query construction patterns
   - Common anti-patterns to avoid
3. Use `metadata.sources` to link skills back to our docs
4. CI validation with `@tanstack/intent validate` + `stale` checks

### Python (PyPI) Considerations

The Agent Skills spec is language-agnostic (just files in directories), but
`@tanstack/intent` CLI is npm-focused. For Python distribution:
- Skills could live in package data (`package_data` / `data_files` in `setup.py`/`pyproject.toml`)
- Need a Python equivalent of the `install` command to wire skills into agent configs
- Or simply document manual skill installation

### Recommendations

1. **Adopt the Agent Skills spec** — it's the emerging standard with 30+ agent integrations
2. **Start with `SKILL.md` files** in the repo even before SDK packaging
3. **Track `@tanstack/intent`** for tooling maturity — scaffold and stale detection are valuable
4. **Consider both npm and PyPI** distribution paths since Oneiron has Rust FFI bindings
5. The spec's progressive disclosure model (metadata → instructions → resources) maps
   well to Oneiron's layered architecture
