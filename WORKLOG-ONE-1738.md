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
- `cargo test -p oneiron --lib skill` — 106 passed.
- `cargo test -p oneiron --test skills_epic_oracle` — 12 passed, 4 ignored (ONE-1739's).
- `cargo test -p oneiron --all-features` — green: **3462 lib passed, 0 failed, 17 ignored**,
  plus 40 green test binaries.

### One flake observed, quarantined not charged
`attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`
failed once mid-run (its `TelemetryCapture` found no `attempt_queue_cleanup` span) and passed
on every subsequent run: two full `--all-features` suites green end to end, plus five isolated
re-runs of the test itself. `crates/oneiron/src/attempt_queue/` is untouched by this branch
(zero lines in `git diff --stat origin/main`), and the test captures tracing spans through a
`with_default` thread-local subscriber — a shape that races under the harness's thread reuse.
Charged to no lane; noting it because it is in ONE-1795's (#589) freshly-landed territory and
will re-appear on other lanes' verify legs.

### Two pre-existing main defects, flagged not fixed
Neither is in this packet, and both are reproducible on a clean `origin/main` checkout:

1. **fmt gate is RED on `crates/oneiron/src/surface_event/tests.rs:733`** (from #589,
   SPINE-COMM ONE-1795) — a single over-long `assert_eq!` rustfmt wants wrapped. Deliberately
   NOT reformatted here: `cargo fmt -p oneiron` would rewrite a file this lane does not own,
   which is a packet violation for a whitespace fix. Whoever owns the next `surface_event`
   touch (or a mech sweep) should take it. It will fail `scripts/verify.sh` stage `fmt` for
   every lane until then.
2. **clippy is RED on `crates/oneiron/src/secret_custody/tests.rs`** (from #566, SECRET-01
   ONE-1919) — `field_reassign_with_default` at :156 and `items_after_statements` at :256,
   both workspace-`deny`. Same reasoning: not this lane's file.

## Handoff to ONE-1739 (SK-06)
`sk04_attribution_routes_defect_to_skill_and_lapse_to_actor` still asserts
`total_claims(skill) - before == 1` for a defect. That is satisfied today by this ticket's
reliability claim, but 1739 owns the assert and should decide whether its `actor.*` writes make
the count 1-or-more. `attribution_judgments` remains the stack seam; 1739's actor rows read the
`ExecutionLapse` judgments this projector deliberately ignores.
