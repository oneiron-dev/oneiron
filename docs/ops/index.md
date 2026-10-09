# Operations Runbooks

Runbooks in this directory are operational response guides for hosted Oneiron
surfaces. They do not replace counsel review for jurisdiction-specific calls.

- [Your vault: where it lives, backups, restore, export, one-act approvals](owner-actions.md) —
  `oneiron doctor`, `backup`, `restore --rehearse`, `restore`, `export`, `secret-scan`,
  `import`, `runs`, and the `/v1/owner` routes.
- [Run the server, with or without models](run-with-models.md) — `[models]` config keys
  (HIGH, MID, DETAILED), provider kinds and env vars, what the Dreamer needs to start, chat
  streaming, the saved-workflow pump, and swapping a model in one edit.
- [Known-CSAM hosted media response](known-csam-hosted-media.md)
- [Wasabi snapshot credential runbook](wasabi-snapshot-credential-runbook.md) — preflight, mint,
  custody registration, smoke, root retirement, and rotation of the bucket-scoped snapshot
  credential.
- [ONE-208: captured Qodo C09 material repair](one-208-qodo-c09-repair.md) — change record for
  one captured-review repair, not a response guide.
- [Wave-6 module-split map](w6-module-split-map.md) — old→new paths for the fifteen 2026-08
  monolith splits; use it to re-anchor tickets, docs, and tooling.
- [Import your history](import-history.md) — `oneiron import` for ChatGPT and Claude.ai exports
  and Claude Code and Codex sessions: what lands, what is counted, and how re-imports dedup.
- [Forked dependencies](forked-dependencies.md) — the crates pinned by `rev` to the org forks
  (sudachi, formualizer): upstream base, fork branch, our commits, and how to change one.
- [Code map](../CODEMAP.md) — generated crate/module/file map (`python3 scripts/codemap/codemap.py`);
  per-crate file tables in [`../codemap/`](../codemap/).
