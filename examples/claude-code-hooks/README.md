# Claude Code hooks

Hooks that give a Claude Code session your vault: a recall at session start,
and the session's log handed to the running `serve` for import at each stop and
before compaction.

- `oneiron_hook.py`: the hooks (`session-start`, `hand-over`).
- `settings.json`: the snippet to merge into your Claude Code settings.
- `check.sh`: the end-to-end check on invented data.

Set-up, removal and what lands: [docs/ops/claude-code-hooks.md](../../docs/ops/claude-code-hooks.md).
