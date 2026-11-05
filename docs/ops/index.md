# Operations Runbooks

Operator guides for running a vault, its server and the agents connected to it.
The incident runbooks do not replace counsel review for jurisdiction-specific calls.

- [Your vault: where it lives, backups, restore, export, one-act approvals](owner-actions.md) —
  `oneiron doctor`, `backup`, `restore --rehearse`, `restore`, `export`, `secret-scan`,
  `import`, `files`, `runs`, `learning-settings`, `widen-proposals`, and the `/v1/owner` routes.
- [Retry a publisher issue signature](publisher-signature-retry.md) — an explicit owner new logical send after proved non-delivery, with the same frozen signature and normal outbound checks.
- [Call receipts after actor erasure](call-receipt-erase.md) — deferred writes keep their receipt while applying the native hard-erased actor identity scrub.
- [Owner custody commands](owner-custody.md) — `--unlock` for every vault-key command, a
  restore's `--wrap-to`, `secrets bind`/`unbind`, the kit push on a running server, credentials a
  restore left pending, `secrets import-supplement` for an export's secret supplements, and a
  stopped-vault guest revoke's `--peer`.
- [Key custody beside your backups](key-custody.md) — the custody head and keyless log each
  backup leaves beside it, the residence and hosted members, the anchor (`custody_anchor_root`,
  `custody_anchor_url`, `/v1/owner/custody-anchor`), the status names, and what a restore says.
- [Run the server, with or without models](run-with-models.md) — `[models]` config keys
  (HIGH, MID, DETAILED), provider kinds and env vars, what the Dreamer needs to start, chat
  streaming, the saved-workflow pump, and swapping a model in one edit.
- [Coach jobs in an embedded wake executor](dreamer-coach-embedded-executor.md) — explicit
  executor support for Coach host jobs and heals, with normal wake admission and settlement.
- [Shared proactivity-policy proposals](proactivity-policy.md) — nightly cadence
  proposals, exact owner review and confirmation, and atomic run-tray approval.
- [Oneironer workers](oneironer-workers.md) — the managed MLX worker and the native Core ML worker beside Candle: placement, activation, fallback, the Core ML cold compile, restart and down reasons, shutdown, receipts
- [Legal-hold clone implementation map](legal-hold-clone-map.md) — planned per-order legal custody, normal user erase, and the remaining implementation slices; MAP only, not a shipped clone.
- [Known-CSAM hosted media response](known-csam-hosted-media.md)
- [Wasabi snapshot credential runbook](wasabi-snapshot-credential-runbook.md) — preflight, mint,
  custody registration, smoke, root retirement, and rotation of the bucket-scoped snapshot
  credential.
- [Sync a machine to its home](device-sync.md) — the `[device_sync]` section: the home a
  machine dials over the paired mesh, the credential file the `/ws` upgrade presents, its MACRO
  home candidacy, and what the log shows.
- [A relay room's locker](relay-room.md) — `oneiron host relay`: the locker's routes under the
  room's access token, and its connection pressure check (`GET /v1/relay/{vault}/pressure`).
- [Connect Claude Code or Codex](connect-an-agent.md) — `oneiron token agent` mints a scoped,
  revocable agent credential; `oneiron mcp` serves MCP on stdio to the agent.
- [The built-in web connector](web-connector.md) — `connector.web.search` and `fetch`: the
  deploy's `TAVILY_API_KEY`, the owner's provider switch, result shapes and usage rows.
- [Clipboard storage and Mac intake](clipboard.md) — owner-bound ordinary text capture,
  masked read pages, cleanup policy and clip/range/world erasure; one Mac watcher,
  private-copy routing and owner IPC. Quiet purpose questions/search/sync proof remain open.
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
- [Cloud registration](cloud-registration.md) — the pins file, `oneiron account login`, `status`, `refresh` and `logout`, the link/refresh/logout/erase lifecycle, key rollover, and what the client wipes.
- [Guest image family](guest-image-family.md) — the mkosi builder in `crates/oneiron-container/images/`: the release list, the package lock, build and rebuild from the mirror, retention, pins vs digests vs signatures vs boot proof, byte fields, and the candidate hand-off.
- [Proposal birth attribution](proposal-birth-attribution.md) — captured draft attempts,
  snapshot/finalize retention, and the evidence-door fallback order.
- [Coach code-fix candidate provenance](coach-code-fix-provenance.md) — native Coach/publisher origin records, separate from model verdicts and independent learning evidence.
- [Coach grant-environment proposals](coach-grant-environment-repair.md) — real grant targets and same-writer review artifacts, without changing access or executing repairs.
- [Coach pilot answer release](coach-pilot-release.md) — frozen source rows for pilot
  replies, device-local details and invocation replay.
- [Frozen pattern revision witnesses](planned-spawn-revisions.md) — hard-erase scrubs,
  late intent writes, and launch comparison without changing the frozen pack body.
- [Code map](../CODEMAP.md) — generated crate/module/file map (`python3 scripts/codemap/codemap.py`);
  per-crate file tables in [`../codemap/`](../codemap/).
