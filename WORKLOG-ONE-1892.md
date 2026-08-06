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

## VERDICT-FIX (Opus, on f690f0d)

Three REAL P1s from the finder/verdict legs, all in the activation-consent
invariant this ticket exists to arm, all fixed at their chokepoint. Two
adjudicated items (BANKED-1 clamp hardening, BANKED-2 packet amendment) are
not relitigated here.

### F1 — `untrusted-approval-bypass`: the hub cannot mint local consent

`import_skill_from_hub_with_id` cloned the hub-supplied record and forced only
`lifecycle_status = Candidate`, so a package declaring
`approvalStatus: approved` kept that stamp. The consult escalates `auto` and
nothing else — deliberately, since rewriting an owner's `approved` would re-ask
a question he answered — so a self-approved package walked a credential-bearing
skill into `active` with no tap.

Fix (2 lines, `skill_hub.rs`): the import door now STAMPS the approval
(`ClaimApprovalStatus::Auto`) instead of copying it. Consent is a local act;
the sync door already holds that law one line at a time ("canonical
approval/lifecycle state stays local") and the import door is where the FIRST
stamp is minted. `auto` is the same default a locally born candidate gets, so
the scan gate — not the package — decides what the activation costs.

Regression: `a_hub_package_cannot_declare_its_own_approval_past_the_gate`.
Mutation-verified: with the stamp line removed the import reads back
`Approved` (red); with it, `Auto` at import and `Proposed` at activation.

### F2 — `activation-chokepoint-bypass`: the consult moves to `apply_put`

The consult was wired into `Vault::update_skill_record` — ONE road to a SKILL
body among several. `Vault::put_entity` and `Vault::batch().put` re-encode an
existing candidate as `Active` + `Auto`, `apply_put` accepts the transition via
`validate_skill_update`, and the caller's bytes were staged unchanged. An
activation gate a caller can walk around is not a gate (house class:
`chokepoint-not-call-site`).

Fix: `skill_scan::escalate_activation_approval_in_txn(store, rtxn, id, &mut record)`
is wired into `apply_put`, the one arm every road converges on
(`update_skill_record` and `put_skill_record` both route through
`apply_skill_record_body` → `apply_ops` → `apply_put`, as does a raw
`batch().put`). It escalates the decoded record in place and the arm re-encodes
before staging. Local writes only (`!replicated && !hub_sync_imported`): a
replicated row carries a peer's already-settled consent and re-deciding it
would diverge replicas, and the hub-sync door copies the local stamp verbatim
so it never presents a transition to escalate.

Placement is load-bearing: the wire sits BEFORE `plan_short_id_update`, which
hashes the body bytes into the ARCH-0019 row-n3 disambiguator — an escalation
applied after it would stage a body the short-id row no longer describes.

Two consequences worth naming:

- **The call-site consult in `skill.rs` is DELETED, not duplicated.** With the
  chokepoint armed, a second consult on the typed door only re-derives the
  stamp `apply_put` is about to set. `consult_activation_scan_gate_in_txn` went
  with it. (Mutation check confirms the direction: disabling the `apply_put`
  arm reds the typed-door test too — the chokepoint now carries it.)
- **The gate reads the same rows from every door.** The verdict reader
  `skill_scan_verdicts_for_content_hash_in_store` and the posture reader
  `scan_gate_for_activation_in_txn` were re-based from `&Vault` onto `&Store`
  (`apply_put` never holds a `Vault`), with the `Vault` methods delegating.
  One implementation, walking the anchor's inbound `claim_of` edges exactly as
  `claims_for_subject_in_txn` resolves them — a gate that reads different rows
  depending on which door called it is not a gate either.

Also widened: a stored body that does NOT decode as a skill record now counts
as NOT-active, so a legacy-opaque predecessor is an activation to be consulted
rather than a hole. Absent stored body = a CREATE, left alone (the birth law
downstream rejects a locally born `active` skill outright).

Regression: `a_raw_entity_put_cannot_activate_around_the_scan_gate`.
Mutation-verified red (`Auto`) → green (`Proposed`).

### F3 — `secret-scan-coverage-bypass`: the scan budget IS the admission envelope

`run_static_skill_scan` read the first 1 MiB of each file while `HubPackage`
admits 16 MiB files and 32 MiB packages. A credential parked past byte
1,048,576 imported at `risk = None`; only `completeness` dropped to `Partial`,
and the gate reads `riskLevel` alone, so the honest label was consumer-inert.
The "unbounded work" defense was void — the package cap already bounds a full
scan at 32 MiB, one-time per import.

Fix: the per-file budget is now `skill_hub::MAX_HUB_FILE_BYTES` and a running
package budget of `MAX_HUB_PACKAGE_TOTAL_BYTES` was added, so the scan envelope
is exactly the admission envelope: nothing importable is scanned partially, and
a package too big to import (only reachable by calling the pure pass directly)
is still read to the envelope and honestly labelled `Partial`. The off-by-one
in the old `get(..N)` truncation went with it — a file of exactly the budget is
now `Complete`, not `Partial`.

Regression: `a_credential_parked_past_the_first_megabyte_is_still_found`
(credential at ~1 MiB + 4 KiB, inside the admission cap). Mutation-verified:
budget back at 1 MiB reads `risk = None` (red); at the admission cap, `High`
and `Complete`.

### Packet + gates

Diff ⊆ packet: `skill_scan.rs` + `skill_scan/tests.rs` (owned), `skill_hub.rs`
(owned), `skill.rs` (claimed), `batch.rs` (CLAIMS.md: "1892 (activation
consult)", additive — the source-index maintenance and the 1447-merged arms are
untouched), `error.rs`, `lib.rs`. No `Cargo.toml` / `Cargo.lock`. The
`skills_epic_oracle.rs` PACKET_AMEND is unchanged from the impl leg and stays
banked for the owner (BANKED-2).

- `cargo fmt --all -- --check` — clean
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean
- `cargo nextest run -p oneiron --all-features` — **3946 passed, 0 failed, 61 skipped**
