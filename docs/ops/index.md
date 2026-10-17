# Operations Runbooks

Operator guides for running a vault, its server and the agents connected to it.
The incident runbooks do not replace counsel review for jurisdiction-specific calls.

- [Your vault: where it lives, backups, restore, export, one-act approvals](owner-actions.md) —
  `oneiron doctor`, `backup`, `restore --rehearse`, `restore`, `export`, `secret-scan`,
  `import`, `runs`, `learning-settings`, `widen-proposals`, and the `/v1/owner` routes.
- [Run the server, with or without models](run-with-models.md) — `[models]` config keys
  (HIGH, MID, DETAILED), provider kinds and env vars, what the Dreamer needs to start, chat
  streaming, the saved-workflow pump, and swapping a model in one edit.
- [Known-CSAM hosted media response](known-csam-hosted-media.md)
- [Wasabi snapshot credential runbook](wasabi-snapshot-credential-runbook.md) — preflight, mint,
  custody registration, smoke, root retirement, and rotation of the bucket-scoped snapshot
  credential.
- [Connect Claude Code or Codex](connect-an-agent.md) — `oneiron token agent` mints a scoped,
  revocable agent credential; `oneiron mcp` serves MCP on stdio to the agent.
- [Import your history](import-history.md) — `oneiron import` for ChatGPT and Claude.ai exports
  and Claude Code and Codex sessions: what lands, what is counted, and how re-imports dedup.
- [Claude Code hooks](claude-code-hooks.md) — recall at session start and each session handed to
  the running `serve` for import (`[import] queue`, `oneiron import claude-code <log> --queue`).
- [Forked dependencies](forked-dependencies.md) — the crates pinned by `rev` to the org forks
  (sudachi, formualizer): upstream base, fork branch, our commits, and how to change one.
- [Documents API handoff](documents-api-handoff.md) — the document engine's contract
  (`oneiron_docedit::contract`, schema 1): ops, media types, limits, refusal codes, and what the
  hosted documents API in oneiron-cloud owns (auth, metering, hosting, session images).
- [Load bench](load-bench.md) — `oneiron-bench load` runs the shipped server under synthetic
  load (facade ingest, recall per grade and agent count, fairness, memory) and compares two
  commits' JSON results.
- [Code map](../CODEMAP.md) — generated crate/module/file map (`python3 scripts/codemap/codemap.py`);
  per-crate file tables in [`../codemap/`](../codemap/).
