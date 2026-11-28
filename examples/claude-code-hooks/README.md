# Claude Code hooks

Hooks that give a Claude Code session your vault: the vault bound and named at
session start, a memory line after relevant tool results, the board restored
after compaction if the session had one, and the session's log handed to the
running `serve` for import at each stop and before compaction.

The hooks are in the `oneiron` binary: `oneiron hook --host claude-code
<session-start|prompt|tool-result|focus-refresh|hand-over>`.

- `settings.json`: the snippet to merge into your Claude Code settings. Use
  the MCP server's credential for `focus-refresh`, and add
  `--carrier-in-content` to the server's `oneiron mcp` args.
- `check.sh`: the end-to-end check on invented data.

Set-up, removal and what lands: [docs/ops/claude-code-hooks.md](../../docs/ops/claude-code-hooks.md).
