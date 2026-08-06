# WORKLOG — ONE-1738 [SK-05] `skill.reliability` claim + score demotion to cache

Branch `ONE-1738`, rebased onto `origin/main` @ `f5fce02` (#591). ONE-1737 is on main
as #581. Blueprint: `~/.claude-wave5/blueprints/SKILLS/ONE-1738.md`.

> **Lane-setup note worth carrying forward.** The lane worktree
> `/Volumes/Cinema/w5-lt/skills` is a separate CLONE, not a linked worktree of
> `~/Desktop/code/oneiron` — it has its own `.git` and its own remote-tracking refs. A
> `git fetch` run from the session cwd therefore does NOT advance the lane's `origin/main`,
> and the branch silently cut off a four-commit-stale base. Caught by three unexplained
> `calendar::claims` failures in the first full run, which #590 ("calendar validator
> restore") had already fixed on the real main. Fetch inside the lane directory.

## What landed

**New:** `crates/oneiron/src/skill_reliability.rs` (+ `skill_reliability/tests.rs`, 17 tests).
**Edited:** `crates/oneiron/src/skill.rs` (+ `skill/tests.rs`, 1 test), `crates/oneiron/src/lib.rs`
(mod + re-exports), `crates/oneiron/tests/skills_epic_oracle.rs` (3 `sk05_*` arms).

The shape, in one line each:

1. **`skill.reliability` is a claim, not a field.** Projector-written, superseding,
   `approval = auto`, subject = the SKILL entity, `value = {alpha, beta}`, `evidence` = the
   receipt ids it rests on. Written through the reserved `skill.*` door
   (`put_reserved_claim_in_txn` / `supersede_reserved_claim_in_txn`), mirroring skill_hub's
   scan-verdict precedent exactly.
2. **`SkillRecord.confidence` is a rebuildable cache** over that claim's posterior mean —
   CID-7's demotion. `rebuild_skill_confidence_cache` is the repair door.
3. **Selection reads the claim** (`skill_selection_score`), mean + exploration bonus, no cap.
4. **Floor crossing PROPOSES quarantine** as a `skill.quarantine_proposal` row with
   `approval = proposed`; the lifecycle never moves.
5. **Companion-surface skills are out** — module-doc note only; they produce no attributed
   outcomes, so they never enter the ledger. No special-case exists because none is needed.

## Decisions worth screening

### The win signal, and why it is a door rather than a scan
The blueprint's counted set is "SK-04-routed `skill_defect` losses / contributing-win
outcomes". SK-04 has no win verdict — its rule tier abstains on success on purpose, and its
module doc hands the job over explicitly: *"Crediting a win is the reliability posterior's
job (ONE-1738), which reads the same receipts."*

So wins come from receipts. The two ways to get them:

- **scan the attempt-pack receipt family per projection** — rejected. The only public inlet is
  `Vault::receipts(ReceiptQuery)`, which pulls all Outbound receipts (durable sends included)
  and truncates newest-first to a limit, so old wins would silently fall out of α as history
  grew. Reaching past it means editing `receipt.rs`, which is not this packet.
- **a grounded door** — taken. `record_skill_contributing_win(vault, skill, receipt_ref, at)`
  point-reads the receipt, requires `outcome == "completed"`, and requires the skill to appear
  in the manifest that receipt recorded — the same three checks SK-04's evidence door runs on
  blame. Cost is O(1) per win instead of O(all receipts) per projection.

Asymmetry between the classes is deliberate and matches §5: losses are gated by SK-04 routing
(only `skill_defect` counts), wins are gated by pack contribution + terminal success. A lapse
fails both — its attempt failed, so it is not a win, and it blames the actor, so it is not a
defect. That falls out of the definitions; there is no `if lapse` branch anywhere.

### Idempotency is a keyspace, and the posterior is recomputed
The blueprint asked for "the claim body's `receipt_refs` set IS the consumed-set". Implemented
one level down, which is strictly stronger: outcomes live at
`skill_reliability:outcome:v1:<skill><receipt_id>`, so recording the same outcome twice writes
the same row twice, and α/β are RECOMPUTED from that ledger on every pass rather than
incremented. Consequences:

- replaying a judgment batch changes nothing (test: `re_running_the_projector_...`), and an
  unchanged posterior supersedes nothing, so replay does not churn claim rows either;
- an interrupted multi-skill pass leaves a STALE claim, never a double-counted one;
- the claim's citation list can be capped (`SKILL_RELIABILITY_MAX_CITED_RECEIPTS = 64`, most
  recent kept) without weakening the counts — the keyspace stays the complete record, the
  citation list is the trace. Uncapped, a hot skill's claim body would become a ledger.

### Wire shape: `value = {alpha, beta}` (blueprint text overruled by the oracle)
The blueprint's prose said body `{alpha, beta, posterior_mean, receipt_refs, updated_at}`. The
oracle pins `posterior.len() == 2` with keys `{alpha, beta}`, and the arming law says
cardinalities stay. Resolved in the oracle's favour, and the other three have homes that are
not denormalization: `posterior_mean` is `alpha/(alpha+beta)`, `receipt_refs` is the claim's
own `evidence` field (which the same oracle asserts on), `updated_at` is the claim row's
temporal envelope.

### One uncertainty quantity, used at both ends
`lower_bound` = `mean − 1.645·σ` and the selection bonus = `c·σ·sqrt(2 ln N)` share the Beta
standard deviation `σ = sqrt(αβ / ((α+β)²(α+β+1)))`. Pinned anchors hold: Beta(3,1) → lb 0.43,
Beta(91,11) → lb 0.84 (the blueprint wrote ≈0.85; the exact value is 0.8419 — rounding, not a
formula disagreement). This is a deviation from `critic.rs`, whose UCB bonus is count-based
(`sqrt(2 ln N / n)`); a count-based bonus here would have disagreed with the lower bound about
how uncertain the same posterior is, and would have failed the done-means anchor below.

**`SELECTION_EXPLORATION = 0.25` is derived, not felt.** A 2-pull arm outranks a 100-pull arm
exactly when `c·(σ_new − σ_old)·sqrt(2 ln N)` beats the mean gap; for the anchor pair that
threshold is `c ≈ 0.285`. 0.25 sits under it, so the done-means bullet holds (2/2 does not
outrank 90/100 on the selection score) while anti-shadowing still works: an arm with an equal
mean and a wider posterior does rank above the well-pulled one, and the bonus decays as
evidence arrives. Both directions are tested
(`lower_bound_holds_its_pinned_anchors`, `selection_bonus_lifts_the_uncertain_arm_at_equal_means`).

### The floor needs evidence before it can fire
`SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES = 5`. Not a safety wall — a correctness one: every prior
in the table has a lower bound at or near 0 (Beta(1,1) → 0.025, Beta(1,2) → 0), so a bare
lower-bound test against any floor proposes quarantining **every newborn skill** on its first
projection. The lower bound measures ignorance until outcomes arrive; the floor asks whether
the evidence says the skill is bad. Test `floor_never_fires_on_a_bare_prior` pins exactly this
(and asserts the prior IS under the floor, so the guard cannot be quietly deleted).

### Provenance priors
| class | condition | prior | mean |
|---|---|---|---|
| `VettedImport` | imported + a `clean` `skill.scan_verdict` on its canonical content hash | Beta(3,1) | 0.75 |
| `HumanAuthored` | human-authored, not imported | Beta(2,1) | 0.667 |
| `UnvettedImport` | imported, no clean verdict (or no content hash to check) | Beta(1,1) | 0.50 |
| `Generated` | Dreamer distill / conversation convert | Beta(1,2) | 0.333 |

Total over lawful record shapes (the record invariant is `generated XOR human_authored` and
`generated ⟺ source == Generated`), so no unreachable arm and no default. Vetting is read
through the PUBLIC `skill_scan_verdicts_for_content_hash` door. The hub TRUST TIER was the
blueprint's first suggestion but is not reachable: `SkillHubRecord` has encode/decode only —
no storage door, no entity-type byte, no getter — so resolving a tier from a SKILL entity
would have been a guess. The scan verdict is the same signal with a real path to it.

### `skill.rs`: what the demotion actually costs
`skill_content_changed` now normalizes `confidence` away alongside the two state axes. This is
load-bearing in both directions:

- without it, every attributed outcome would demand a `version` bump — a content revision per
  observation;
- and the imported-content fork law would fire on every refresh, making an **imported** skill's
  reliability permanently unmaterializable. The oracle fixture is an imported skill; the test
  would have been impossible to satisfy honestly.

The carve-out is exactly one field wide — `confidence_moves_without_a_revision_...` asserts a
`desc` edit at the same version is still rejected, and that auto-quarantine is still banned.

The cache door (`refresh_skill_confidence_cache_in_txn`, crate-private) copies every other
field from the STORED record, so it structurally cannot smuggle a content edit, and still runs
`validate_skill_update` so the lifecycle machine keeps its say.

## Deviations from the blueprint sketch (all deliberate)
- `project_skill_reliability` returns `Vec<EntityId>` (the skills it touched) rather than `()`
  — the caller needs to know, and the oracle asserts on it.
- Write doors take an explicit `at: u64` (house style: deterministic time in, no
  `unix_seconds_now()` inside a projector).
- `skill_selection_score` takes `total_pulls` — same shape as `critic.rs::triage_weight`.
  Deriving it internally would mean a scan per skill, i.e. N² to rank N skills.
- `rebuild_skill_confidence_cache` returns the value it wrote.
- Added `record_skill_contributing_win` (the α inlet, argued above) and the floor dial
  accessors; `SKILL_RELIABILITY_FLOOR_KEY` is a per-feature `vault_meta` const in this module
  (the `INBOX_REVIEW_DIAL_KEY` pattern). `settings.rs` untouched, per CLAIMS.md.
- `claim.rs` untouched: `skill.*` is already reserved generically and the predicate needed no
  bespoke validation — the blueprint's "likely zero edit" held.
- `gate.rs` untouched (ONE-1739 owns it this batch). Its predicate→axes policy map has rows
  for the three `skill_hub` predicates; the two new ones fall to the map's defaults. That is a
  consent-routing dial, not a write gate, and the reserved claim door does not consult it —
  flagged here so 1739 can add rows in the file it already owns if the dial matters.

## Packet
Claimed rows only (`CLAIMS.md`, ONE-1738): `skill_reliability.rs` (new) + tests, `skill.rs` +
`skill/tests.rs`, `skills_epic_oracle.rs`, `lib.rs`. No `Cargo.toml`, no `Cargo.lock`, no
`skill_attribution.rs` (1737's, and ED-03's after it), no `skill_hub.rs`, no `settings.rs`.

## Oracle arming
All three `sk05_*` tests armed and green; count-asserts and wire-shape cardinalities untouched.
One new predicate const (`PRED_SKILL_QUARANTINE_PROPOSAL`) added for the floor test — the
ticket pins that row. The `Option` seam scaffolding in the two armed tests collapsed to direct
bindings (clippy `unnecessary_literal_unwrap` rejects `Some(x).expect(..)` under the workspace
deny list); the asserts they fed are unchanged. The four `sk04`/`sk06` tests stay ignored —
ONE-1739's.

## Gates (on the rebased tree, base `f5fce02`)
- `cargo fmt -p oneiron -- --check` — clean on every touched file.
- `cargo clippy -p oneiron --all-features --all-targets` — zero diagnostics on every touched
  file.
- `cargo test -p oneiron --lib skill` — 108 passed.
- `cargo test -p oneiron --test skills_epic_oracle` — 12 passed, 4 ignored (ONE-1739's).
- `cargo test -p oneiron --all-features` — 40 test binaries green; lib **3462 passed, 17
  ignored**, with the one pre-existing flake below as the only red ever seen (2 of 4 full runs).
- `cargo test -p oneiron --lib` (default features) — 3043 passed, 0 failed.

### Three pre-existing main defects, flagged not fixed
None is in this packet; each is reachable without any of this branch's code.

1. **`attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`
   is FLAKY** (from #589, SPINE-COMM ONE-1795). It failed in 2 of 4 full `--all-features` runs
   and — the decisive evidence — **reproduces with `--lib attempt_queue` alone** (56 passed / 1
   failed), i.e. with none of this lane's tests, none of its code, and no cross-module
   subscriber in play. `crates/oneiron/src/attempt_queue/` has zero lines in
   `git diff --stat origin/main` for this branch.

   Mechanism, for whoever fixes it: `TelemetryCapture` is installed with
   `tracing::subscriber::with_default`, which is THREAD-LOCAL, while `tracing`'s callsite
   `Interest` cache is process-GLOBAL. Five other tests in the same file call
   `cleanup_leases` with no subscriber installed; whichever thread first reaches the
   `attempt_queue_cleanup` span callsite registers it against an empty dispatcher, the
   `Interest::never()` verdict is cached for the process, and the capture test then finds no
   span however correct its own subscriber is. It passes in isolation and whenever it happens
   to win the race. The durable fix is to stop depending on registration order — a global
   dispatcher installed once for the test binary, or a capture that does not rely on a
   first-touch callsite — not a retry.

2. **fmt gate is RED on `crates/oneiron/src/surface_event/tests.rs:733`** (also #589) — one
   over-long `assert_eq!` rustfmt wants wrapped. Deliberately NOT reformatted here:
   `cargo fmt -p oneiron` would rewrite a file this lane does not own, which is a packet
   violation for a whitespace fix. It will fail `scripts/verify.sh` stage `fmt` for every lane
   until someone who owns that file takes it.

3. **clippy is RED on `crates/oneiron/src/secret_custody/tests.rs`** (from #566, SECRET-01
   ONE-1919) — `field_reassign_with_default` at :156 and `items_after_statements` at :256, both
   workspace-`deny`. Same reasoning: not this lane's file.

## Handoff to ONE-1739 (SK-06)
`sk04_attribution_routes_defect_to_skill_and_lapse_to_actor` still asserts
`total_claims(skill) - before == 1` for a defect. That is satisfied today by this ticket's
reliability claim, but 1739 owns the assert and should decide whether its `actor.*` writes make
the count 1-or-more. `attribution_judgments` remains the stack seam; 1739's actor rows read the
`ExecutionLapse` judgments this projector deliberately ignores.

## SIMPLIFY pass (K3, on tip `1b3b553`)

Two deletions, both in `skill_reliability.rs`; no test, fixture, or public-API touch:

1. `clamp_unit` helper deleted — single call site; `lower_bound` now clamps inline
   (`narrow((mean − Z·σ).clamp(0.0, 1.0))`), which the doc comment already states.
2. `decode_outcome_win` open-coded a map lookup the module's own `map_entry` helper exists
   for — now `map_entry(&value, KEY_WIN).and_then(Value::as_bool)` (−6 lines).

Considered and kept: `active_reliability_claim_in_txn` (3 call sites), `OutcomeTally::total`
(2), `read_skill` (2), the `map_f32` F64 arm (reserved-namespace bodies round-trip F32, but the
decoder is the wrong place to pin the encoder's width), and the unreachable-looking
`evidence_receipts.first().ok_or(..)` in the projector (cheap grounding at a trust boundary;
the batch filter above it is an optimization, not a contract). The full lib.rs re-export
surface stays: host wiring for the win/selection/floor doors lands in later tickets
(ONE-1739, batch runner), and deleting public exports is a public-API change, not a simplify.

Gates after the pass: `skill_reliability` lib 17/17 · `skill::` lib 28/28 · `skills_epic_oracle`
12 passed / 4 ignored · zero clippy diagnostics on the file · fmt clean on the file. The
`identity_topology/tests.rs:4203` redundant-clone clippy error and the `surface_event/tests.rs`
fmt red both reproduce with this branch's edits stashed — pre-existing main defects, not this
packet (the worklog's flagged-defects list above gains the identity_topology one).

## VERDICT-FIX (Opus, on tip `06fd491` → `fe7c187`)

Eight verdict-verified findings, all fixed. No re-adjudication; the notes below
record the SHAPE chosen and the bounds that remain honest, not a second opinion
on whether the findings were real.

Packet: `skill_reliability.rs` (+ tests), `skill.rs`, `WORKLOG-ONE-1738.md`.
No `skill_attribution.rs` (1737's — the persisted-judgment check consumes its
already-public `attribution_judgments` seam), no `skill_hub.rs`, no
`Cargo.toml`/`Cargo.lock`, no oracle edit (all three `sk05_*` arms pass
unchanged; the fixes were behaviour under the contract, not contract changes).

### F1 — reserved-door authorization (P1)
`project_skill_reliability` took `&[AttributionJudgment]` — a public type with
public fields — and authored reserved `skill.*` truth off it after checking only
"subject is a SKILL" and "receipts non-empty". The win door already resolved its
receipt and checked manifest membership; the loss door did neither.

Both halves added, at ONE chokepoint each:
- `receipt_manifest_names_skill` is now the single manifest predicate both doors
  run (previously the win door open-coded it).
- the persisted-store check compares the caller's row against
  `attribution_judgments()` **by sequence, whole-row** (`AttributionJudgment:
  Eq`), read ONCE per pass into a `HashMap` — the bulk seam is a prefix scan and
  N judgments must not cost N scans.

Ungrounded rows are **skipped, not fatal**. A batch already mixes rows this
projector deliberately ignores (lapses, discoveries); erroring the whole pass on
one forgery would let a single bad row deny every real one.

Gate ORDER is grounding-then-authorization, which is what gives each limb its
own witnessing test: a fabricated judgment dies on grounding, and
`a_judgment_routed_against_an_earlier_revision_no_longer_grounds` shows why the
grounding re-check is not redundant with 1737's evidence door — 1737 matches the
manifest by `skill_id` ALONE, so a judgment routed at v1 stays persisted after
the entity revises in place, and counting it would move v2's posterior.

### F2 + F3 + F8 — the replica-convergence cluster (P1/P1/P2)
Fixed together at `project_in_txn`, per the verdict's cluster guidance.

**The base (F2).** A head citing receipts the local outcome ledger has no rows
for was projected somewhere else; its α, β becomes the base the local tally folds
onto, instead of the provenance prior.

The base is **persisted** (`skill_reliability:imported_base:v1:<skill>`, one row
per skill, node-local like the ledger it completes). It has to be: F3 supersedes
the head that carried it in the same transaction, and the claim body is pinned by
the oracle to `{alpha, beta}`, so there is nowhere in the claim to keep it. Two
alternatives were tried and rejected on paper first:
- *carry the remote receipts forward in the new claim's `evidence`* — works until
  the 64-entry citation cap evicts the local receipts, after which every
  projection re-folds the whole local ledger onto the base. Unbounded α growth.
- *detect "the head knows more than the ledger can recompute" arithmetically* —
  not idempotent; the second pass re-folds.

Claims THIS replica writes cite only local receipts, so they never re-enter as a
base and the fold cannot double-count itself. Tested directly: re-project after
the merge is a no-op, and a second local loss moves β by exactly one.

**Honest bound, stated rather than hidden:** this converges history INTO a
replica. Two replicas that each attribute outcomes the other never sees still
double-count on a full round trip, because "fold α,β as the base" has no
per-outcome identity to dedupe against. Exactness needs the outcome ROWS on the
wire — a sync-scope change, not a projector one. Recorded in the module doc, not
just here.

**Every head (F3).** `active_reliability_heads_in_txn` replaces the
first-match reader; the projector supersedes all of them. The `unchanged`
fast-path now requires exactly ONE head that already matches — two heads is a
fork that must collapse even when the winning value is unchanged. Reads
(`skill_reliability_posterior`, the cache rebuild, the floor) resolve a
mid-fork subject to the RICHEST head rather than whichever the edge index
yielded first.

**The floor (F8).** `check_reliability_floor` reads the claim; the local tally
answers only for a skill nobody has projected. The outcome COUNT had the same
defect and is now derived — `attributed_outcomes(prior, posterior)` = the
pseudo-observation weight above the prior — which equals the local tally exactly
whenever the ledger is the whole story, so the pure-local reading is unchanged
and `floor_never_fires_on_a_bare_prior` still pins the guard.

### F4 — supersession temporal clamp (P2)
`superseded_at = at.max(prior_start)`, the same clamp `skill_hub.rs:1271`
applies, using the `occurred_start` the head reader now returns. Without it an
out-of-order event time hands `supersede_reserved_claim_in_txn` an inverted
`{start: old_start, end: now}` range, which fails the write and rolls the whole
projection back — permanently, because the retry re-derives the same `at`.

### F5 — frozen revisions keep their cache (P2)
The guard lands in the cache DOOR (`skill.rs::refresh_skill_confidence_cache_in_txn`),
not at the two call sites: it is the only writer of that field, and
`rebuild_skill_confidence_cache` needed the same protection. A `Superseded`
record returns early. Truth (outcome row + claim) still lands; only the
materialization the frozen revision no longer serves anything from is skipped.

### F6 — manifest membership compares the revision (P2)
`manifest_entry_names_skill(wire_form, skill_id, version)`. An entry with an
EMPTY version still resolves — it names no revision to disagree with, the same
absent-fact line the absent-manifest branch already draws — but a populated one
must match exactly.

### F7 — prior seeding reads both halves (P2)
Two limbs, both real:
1. `governance` is a POLICY axis carried on the scan row, and the ingest door
   validates only the provider text, so `clean` + `prohibited` is a storable
   receipt that was seeding Beta(3,1). `scan_verdict_cleared_the_bytes` now
   refuses it. `riskLevel`/`completeness` are deliberately NOT read: they are
   scanner-signal axes the scanner already summarized into `verdict`, and
   re-judging them would be this module second-guessing the provider. Governance
   is the one axis on the row that is not the scanner's opinion.
2. `VettedImport` is the **vetted-HUB** import (blueprint §5: "hub trust tier —
   scan-verdict + hub provenance rows"). Scan verdicts hang off the
   content-global anchor, so a clean verdict alone says a scanner looked at some
   bytes; the active `skill.hub_provenance` alias naming the same
   `contentHash` is what says a hub carried them HERE. Both are now required.

   The TIER byte itself is still unreachable and this lane did not invent a path
   to it: `SkillHubRecord` has encode/decode only — no storage door, no
   entity-type byte, no getter — so resolving a tier from a `hubRef.hubId` would
   mean decoding an entity that no engine door ever writes. The provenance ROW is
   the reachable half the blueprint names in the same parenthetical; whichever
   ticket lands hub storage (ONE-1751) can key the prior finer without moving
   this seam.

   Cost: the fixture test now imports through the real `import_skill_from_hub`
   door instead of `put_skill_record`, which is a stronger test of the same
   claim.

### Mutation verification
Every fix was reverted in place and the naming test re-run; all nine mutations
(F1 has two limbs) were KILLED:

| mutation | test that died |
|---|---|
| drop the persisted-store gate | `a_forged_judgment_writes_no_reserved_claim` |
| drop the loss-path receipt grounding | `a_judgment_routed_against_an_earlier_revision_no_longer_grounds` |
| `tally.posterior(base)` → `(prior)` | `a_synced_posterior_is_the_base_a_local_loss_folds_onto` |
| supersede only `heads.first()` | `every_active_head_is_superseded_not_just_the_first` |
| drop `at.max(head_start)` | `supersession_clamps_to_the_prior_rows_event_time` |
| drop the `Superseded` early return | `a_late_outcome_on_a_frozen_revision_keeps_its_outcome_and_claim` |
| drop the manifest version compare | `a_win_receipt_must_name_the_revision_it_credits` |
| drop the governance guard | `a_clean_scan_on_governance_prohibited_bytes_clears_nothing` |
| drop the hub-provenance requirement | `a_clean_scan_without_a_hub_alias_is_still_an_unvetted_import` |

### Gates (tip `fe7c187`)
- `rustfmt --check` on all three packet files — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — **zero diagnostics on
  every packet file**. The three pre-existing main defects flagged above still
  reproduce (`identity_topology/tests.rs:4203` redundant-clone is still the hard
  clippy error; `surface_event/tests.rs` and `campaign_claim_gate_oracle.rs` warn).
  A `cargo fmt -p oneiron` run touched `surface_event/tests.rs` and was reverted:
  reformatting a file this lane does not own is a packet violation for a
  whitespace fix, exactly as recorded in the first pass.
- `cargo test -p oneiron --all-features --lib skill` — **119 passed** (was 108;
  +11 verdict-fix tests, one renamed).
- `cargo test -p oneiron --all-features --test skills_epic_oracle` — 12 passed,
  4 ignored (ONE-1739's), no arm edited.
- `cargo test -p oneiron --all-features --lib` — **3473 passed, 0 failed, 17
  ignored**. The `attempt_queue` callsite-registration flake documented above did
  not fire on this run.

### Deltas a reviewer should look at first
- One new `vault_meta` keyspace (`skill_reliability:imported_base:v1:`), schema
  version 1, node-local by design. It is the price of preserving synced history
  under a claim body the oracle pins to two keys.
- `OutcomeTally::total` deleted — `attributed_outcomes` replaced its only two
  call sites.
- `provenance_trust_class` now takes the skill's `EntityId` (it must read
  per-skill provenance rows, not just the record).
