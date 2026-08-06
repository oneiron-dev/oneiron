# WORKLOG — ONE-1892 · SKILL scan-verdict production wiring + anchor type assert

Lane SKILLS · flat (independent of SK / SKC / SKO) · branch `ONE-1892` off `origin/main` 09da3577.
Blueprint: `~/.claude-wave5/blueprints/SKILLS/ONE-1892.md`.

## What landed

All four blueprint arms.

### 1. Producer — the import/sync doors scan and ingest their own verdict

`crates/oneiron/src/skill_scan.rs` (new): `run_static_skill_scan(&HubPackage, scanned_at)`
is a pure deterministic pass producing a `SkillScanReceipt` under the pluggable provider id
`oneiron.static.v1`. Three checks, risk = max:

| signal | risk |
|---|---|
| embedded credential in any package file or in the encoded record | `High` |
| declared `env` requirement (asks for the host process's environment) | `Medium` |
| declared bin / MCP / allowed tool | `Low` |
| nothing | `None` |

Completeness is `Partial` for an empty tree or when a file exceeded the 1 MiB per-file scan
budget (the head is still scanned — truncated coverage, honestly labelled), `Complete`
otherwise.

Credential detection is CALL-REUSE of `batch::secret_scan::scan_metadata_field`
(secret_scan.rs:59) — the regex set keeps exactly one owner and `batch/secret_scan.rs` is
**untouched** (see deviation D1).

`Vault::scan_and_ingest_on_import_in_txn` is the single producer hook, called from
`import_skill_from_hub_with_id` (the door both public import entries and
`resolve_hub_dependency` delegate to) and from the tail of an applied `sync_skill_from_hub`.

### 2. Consumer — activation admission consult

`scan_gate_for_activation(vault, content_hash) -> ActivationPosture`
(`AutoEligible` | `ProposedRequired { risk }`), thresholded on a `vault_meta` dial
(`SKILL_SCAN_ACTIVATION_RISK_THRESHOLD_KEY`, default `High`) whose key const lives in
`skill_scan.rs` — `settings.rs` untouched, per the house per-feature-dial pattern.

Wired at `Vault::update_skill_record` (skill.rs), which is where activation approval is
computed today. **Dial, not wall**: on a transition INTO `Active`, a posture of
`ProposedRequired` rewrites `approval_status` `auto → proposed` and nothing else. The
activation still lands. There is no refusal path anywhere in the module.

The consult reads through a new `skill_scan_verdicts_for_content_hash_in_txn` from INSIDE
the door's write transaction, so no verdict can land between consult and write.

### 3. Newest-wins ingest + future-timestamp clamp

`ingest_skill_scan_verdict_in_txn` now compares `scannedAt` before deciding the active slot
for a `(content_hash, provider)` key:

- incoming `scannedAt` strictly older than the newest stored → the row is still WRITTEN and
  is immediately superseded BY the newer row in the same transaction (historical, auditable,
  never active). Blueprint offered "historical row or typed refusal"; historical row chosen —
  a scan that really happened is evidence, and the landed row semantics already model
  "not current" as `Superseded`.
- ties (equal `scannedAt`) → later call wins, which keeps
  `scan_verdict_supersedes_same_hash_and_provider` green with its assertions unchanged.
- incoming `scannedAt > learned_at + 300s` → clamped to `learned_at` before comparison, so a
  far-future receipt cannot permanently pin the slot. The clamp is RECEIPTED: the row carries
  the effective `scannedAt` plus `scannedAtDeclared` (present only when a clamp happened).

### 4. Anchor type assert

`ensure_skill_content_anchor_in_txn` now parses the header of any entity already at the
derived anchor id and returns the new typed `Error::SkillContentAnchorTypeMismatch { existing }`
unless it is `ENTITY_TYPE_SKILL_CONTENT_ANCHOR`. Fails closed; writes nothing.

## Deviations from the blueprint (declared, none silently absorbed)

**D1 — `detect_secret` NOT promoted to `pub(crate)`.** The blueprint allowed promoting it
"only if the scanner needs the reason string". It does not: `SkillScanReceipt` has no
free-text field, so the boolean from `scan_metadata_field`'s `Result` is the whole signal.
`crates/oneiron/src/batch/secret_scan.rs` is therefore byte-identical to main — one fewer
file in the packet than the blueprint budgeted.

**D2 — `run_static_skill_scan` takes `&HubPackage`, not `&SkillRecord`, and returns
`Result`.** The blueprint skeleton's `(record) -> SkillScanReceipt` cannot implement the
blueprint's own body text ("call `scan_metadata_field` over each skill-tree file" +
"capability-surface extraction"): neither the tree nor the capability surface lives on
`SkillRecord`. Both producer sites hold a `HubPackage`. `Result` because
`SkillScanReceipt::new` and `encode_skill_record` are both fallible.

**D3 — the static pass never emits `ScanVerdict::Clean`; a no-finding scan is `Unknown`.**
This is a correctness fix discovered at the seam, not a preference. `skill_reliability::
provenance_trust_class` (skill_reliability.rs:344) reads `verdict == "clean"` as a real
CLEARANCE and uses it to seed its most optimistic prior (`VettedImport`). Emitting `Clean`
from a regex/size pass would silently promote every hub import to the top prior on the
strength of the engine's own trivial scan — inverting the table it is keyed by. A pattern
scan can find known-bad shapes; it cannot establish safety. `Critical` and `Prohibited` are
likewise never machine-minted here.

**D4 — the consult fires on ANY transition into `Active`, not only `Candidate → Active`.**
The blueprint says "on skill activation"; `Stale → Active` (revival) and
`Quarantined → Active` (post-quarantine reactivation) are activations too, and the latter is
the riskiest of the three. One rule, strictly wider, no extra branch.

**D5 — producer idempotence is keyed on CONTENT, not on the create branch.** The producer is
skipped when the bytes already carry an ACTIVE `oneiron.static.v1` row. The static pass is a
pure function of the package bytes, so re-running it would mint a row identical but for its
timestamp and supersede the row it duplicates. Consequence: a second hub alias over known
bytes adds no verdict, while bytes that first entered through a non-hub birth path get
scanned the moment they reach a hub door.

**D6 — `batch.rs` NOT touched.** The blueprint claim listed "`skill.rs` / `batch.rs` —
activation consult call site". Wiring the escalation in `skill.rs` alone is sufficient and
strictly cheaper: the batch chokepoint holds `data: &[u8]` already encoded, so escalating
there would mean either re-encoding inside 1447-merged territory (a refactor my brief
forbids) or converting the dial into a rejection (a wall). Packet under-use, not over-use.

## PACKET_AMEND candidate (needs a ruling)

**`crates/oneiron/tests/skills_epic_oracle.rs`** — claimed by 1737/1738/1739 under arming
discipline, not by 1892. Forced +19 lines: one helper (`third_party_scan_verdicts`) plus two
call-site swaps in `sk02_scan_verdicts_key_on_content_hash_provider_time`.

Cause: that test hub-imports at line 476, so the producer now mints an `oneiron.static.v1`
row for those bytes and the arity assertions read 4 where the contract says 3. The contract
is about THIRD-PARTY providers staying independent rows; the helper filters the engine's own
row so the assertion measures the contract rather than the producer. **The count-asserts are
unchanged** (still `3`, `3`, `0`) — the oracle's "count-asserts are never weakened" law is
respected: only the input set is scoped, and the producer's own behaviour is covered by
`skill_scan::tests::import_produces_a_verdict_row_with_no_manual_ingest`.

## Known holes (banked, not fixed here)

1. **The escalation only moves `auto`.** A record arriving at activation already stamped
   `approved` is left alone — an owner tap is not re-asked. But nothing today constrains a
   hub PACKAGE from declaring `approval_status: approved` on the record it ships, so a hub
   can ship past the dial. Closing that belongs to the admission gate (ONE-1449), which owns
   `candidate → active` and can require the approval stamp to be locally authored.
2. **The consult is a DOOR check, not a chokepoint check.** A caller reaching
   `Vault::put_entity` / `apply_ops` directly with an already-`active` SKILL body bypasses it
   (the birth law at batch.rs:3584 blocks born-active locals, so this is the
   already-exists + raw-overwrite path). Fixing at the chokepoint requires making the put
   body owned in `apply_put`; deferred to whoever owns that refactor.
3. **No verdict ⇒ `AutoEligible`.** Absence of a scan is not evidence of risk, and blocking
   unscanned bytes would be the wall this gate is specified not to be. The producer is what
   makes verdicts common.

## Files

- `crates/oneiron/src/skill_scan.rs` **(new, 280 lines)** + `crates/oneiron/src/skill_scan/tests.rs` **(new, 13 tests)**
- `crates/oneiron/src/skill_hub.rs` — `ScanRiskLevel` `Ord`/`parse`/`pub as_str`; clamp const + helper; row readers; newest-wins ingest; producer hook + 2 call sites; txn-scoped verdict reader; anchor type assert; 3 new tests; 9 existing tests scoped past the producer row via a new `third_party_verdicts` helper
- `crates/oneiron/src/skill.rs` — activation consult in `update_skill_record` (additive)
- `crates/oneiron/src/error.rs` — `SkillContentAnchorTypeMismatch { existing: u8 }` + `ErrorKind` arm
- `crates/oneiron/src/lib.rs` — `pub mod skill_scan` + re-exports
- `crates/oneiron/tests/skills_epic_oracle.rs` — PACKET_AMEND above

Untouched, as claimed: `settings.rs`, `gate.rs`, `batch.rs`, `batch/secret_scan.rs`,
`skill_reliability.rs`, `Cargo.toml`, `Cargo.lock`.

## Gates

- `cargo fmt --all -- --check` — clean
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean
- `cargo nextest run -p oneiron --all-features` — **3943 passed, 0 failed, 61 skipped**

## SIMPLIFY (K3, deletion-biased pass on 5d0a940)

One edit, no test/assertion/fixture/public-API changes:

- `Vault::scan_and_ingest_on_import_in_txn`: `Result<Option<EntityId>>` → `Result<()>`.
  Both call sites (import door, sync door) discard the return, and the
  blueprint skeleton specifies `Result<()>`; the `Option` encoded an
  already-scanned distinction no consumer reads. Deleted the `.map(Some)` tail
  and the `Ok(None)` early return.

Considered and rejected: deduplicating the test helpers `row_text`
(skill_scan/tests.rs) against skill_hub's private `map_text` — the only call
sites sit inside assertion expressions, which the fixture-sync law puts
off-limits to this seat. Flagged, not done.

Gates after the pass: `cargo fmt -p oneiron -- --check` clean · `cargo clippy
-p oneiron --all-features --all-targets` clean · `cargo nextest run -p oneiron
--all-features` scoped to `skill_scan` + `skill_hub` (57/57) and the
`skills_epic_oracle` binary (16/16) all green.
