# Operations Runbooks

Operator guides for running a vault, its server and the agents connected to it.
The incident runbooks do not replace counsel review for jurisdiction-specific calls.

- [Your vault: where it lives, backups, restore, export, one-act approvals](owner-actions.md) —
  `oneiron doctor`, `backup`, `restore --rehearse`, `restore`, `export`, `secret-scan`,
  `import`, `runs`, `learning-settings`, `widen-proposals`, and the `/v1/owner` routes.
- [Key custody beside your backups](key-custody.md) — the custody head and keyless log each
  backup leaves beside it, the residence and hosted members, the anchor (`custody_anchor_root`,
  `custody_anchor_url`, `/v1/owner/custody-anchor`), the status names, and what a restore says.
- [Run the server, with or without models](run-with-models.md) — `[models]` config keys
- [Oneironer workers](oneironer-workers.md) — the managed MLX worker beside Candle: placement, activation, fallback, restart and down reasons, shutdown, receipts
  (HIGH, MID, DETAILED), provider kinds and env vars, what the Dreamer needs to start, chat
  streaming, the saved-workflow pump, and swapping a model in one edit.
- [Known-CSAM hosted media response](known-csam-hosted-media.md)
- [Wasabi snapshot credential runbook](wasabi-snapshot-credential-runbook.md) — preflight, mint,
  custody registration, smoke, root retirement, and rotation of the bucket-scoped snapshot
  credential.
- [Sync a machine to its home](device-sync.md) — the `[device_sync]` section: the home a
  machine dials over the paired mesh, the credential file the `/ws` upgrade presents, its MACRO
  home candidacy, and what the log shows.
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
- [Deck export gate run](deck-gate.md) — OF-510 `pptx-live-v1`: the engine half on a Linux fleet
  host, the Office half on the Mac mini, and the command that records the oracle receipt.
- [Load bench](load-bench.md) — `oneiron-bench load` runs the shipped server under synthetic
  load (facade ingest, recall per grade and agent count, fairness, memory) and compares two
  commits' JSON results.
- [Vault VM restore transport](vault-vm-transport.md) — the restore channel on vsock 1032 (FIX
  6584), and the custody anchor exchange and proxy on 1031 and 1033 (FIX 6517):
  `host vm --restore` and its pipes, the marker inspection's descriptors, the optional
  `restore_source_disk` at `/restore`, the guest network's one NIC and `/config/network.json`
  (FIX 6808), the managed profile's five typed `/config` files (FIX 6809), the lost-result
  decision table and the image manifest's revision floors.
- [Code map](../CODEMAP.md) — generated crate/module/file map (`python3 scripts/codemap/codemap.py`);
  per-crate file tables in [`../codemap/`](../codemap/).
