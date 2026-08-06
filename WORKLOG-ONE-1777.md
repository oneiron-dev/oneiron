# WORKLOG — ONE-1777 [CA-06] Campaign compliance pack + dispatch gate

Lane: CA · flat (no `gh-stack` parent or child).
Worktree: `/Volumes/Cinema/w5-lt/ca-1773` · Branch: `ONE-1777`.
Base: `00536ae92` (`origin/main` at cut time — `ONE-1774` #611 and `ONE-1758` #612
merged). base=main, no stacking.

Dispatch edge (C20) satisfied at cut time: `ONE-1728` merged, `ONE-1772` merged,
GATE lane has no in-flight `gate.rs` claim. CA `gate.rs` writer order
`1772 → 1777 → 1868` is preserved — this lane is the second writer. Rebase
immediately before merge is still mandatory.

## PACKET

| Path | Action |
|---|---|
| `crates/oneiron/src/campaign/compliance.rs` | CREATE |
| `crates/oneiron/src/campaign/compliance/seed_v1.json` | CREATE |
| `crates/oneiron/tests/campaign_compliance_oracle.rs` | CREATE |
| `crates/oneiron/src/campaign.rs` | MODIFY (one `pub mod compliance;` declaration) |
| `crates/oneiron/src/gate.rs` | MODIFY (dispatch evaluation seam + one deny reason code) |
| `WORKLOG-ONE-1777.md` | CREATE (wave convention) |

`git diff --name-only origin/main...HEAD` is exactly those six paths. No
`claims.rs`, `comm.rs`, `connector_key.rs`, `registry.rs`, `store.rs`,
`error.rs`, `lib.rs`, `booking/anti_abuse.rs`, `Cargo.toml`, or `Cargo.lock`
change. No entity type byte, registry row, entity kind, claim family, publisher
runtime, scheduler, transport, or new human-approval gate.

## What landed

### `compliance.rs` — law as data, evidence as types

**Pack schema.** `CompliancePack` carries the ARCH-0059 §8 rows
(`jurisdiction`, `channel`, `rule_kind`, `requirement`, `b2b_exemption`,
`source`, `verified_at`, `version`, `penalty_note` — byte-exact, unchanged) plus
pack-level dials. Row identity is `(jurisdiction, channel, rule_kind)`;
duplicates are rejected at parse. `jurisdiction` is HIERARCHICAL (`EU/DE`
selects the German rows AND the EU floor above them), which is how the directive
floor composes with a national pole without either being duplicated into the
other. The blueprint's own phrase "exact jurisdiction/variant first" is what the
slash encodes.

**Selection and composition.** Every matching row is evaluated in a
deterministic `(jurisdiction, channel, rule_kind)` order; no row can produce an
allow, only the absence of a block, so a permissive row structurally cannot
erase a stricter one. Staleness is swept first over the matched set.

**Unknown jurisdiction.** An absent token, a token below the pack's confidence
floor, and a token the pack does not seed all take the explicit `none`
disposition row, which routes evaluation to `strict_pole_jurisdiction`
(`EU/DE`). Never an automatic deny: facts that satisfy the pole allow.

**Fail-closed coverage rule.** A jurisdiction that seeds no `consent_class` row
for the dispatch channel cannot be evaluated and blocks (`RuleViolation`). This
is what stops an unlisted channel from silently passing on an empty axis; the
fix is a seeded row, i.e. a data revision.

**Post-send rows.** `optout_deadline` and `records` ship as data but never block
a dispatch: no dispatch-time fact can witness them, so blocking would deny every
send forever while enforcing nothing. Explicitly pinned by
`campaign_compliance_post_send_rows_never_block_dispatch`.

**Hydration.** `hydrate_dispatch_compliance_facts` resolves every evidence
reference from the vault, requires the resolved record to be an ACTIVE CLAIM of
the expected predicate whose SUBJECT is this counterparty, and (for list
provenance) requires the record's own stored class to equal the claimed class.
Any failure yields `None` — "no evidence", not "weaker evidence" — and the
strict path applies. `Some(EntityId)` is never sufficient. The subject binding
is what stops one contact's evidence from authorizing another's dispatch.

**Message elements** hydrate from the SENDING identity (`channel_identity_ref`),
which is where a compliance footer actually lives. An effect with no bound
identity reports `sender_identity_present = false` whatever a configuration row
claims.

**Amendment.** `store_active_compliance_pack` is private; the only public path
is `propose_compliance_amendment` / `ingest_published_compliance_update`, which
run the same classifier. Tightening (rows added, dials tightened, nothing
relaxed) and metadata refresh (citations / `verified_at` / penalty notes /
engine floor only) auto-apply with a durable notice keyed by the activated pack
version. Row deletion, a widened trust window, a moved strict pole, a dropped
prohibited class, a dropped evidence binding, and ANY free-text requirement edit
are `LooseningOrAmbiguous` and stage behind `stamp_compliance_amendment`, whose
`proposal_hash` is a domain-separated SHA-256 over the canonicalized rows,
version, and dials. A hash naming different rows or a different version is
rejected, and the staged slot is consumed on stamp so one stamp cannot activate
twice.

### `seed_v1.json` — 31 rows, four jurisdictions plus the poles

UK (PECR regs 22/23 + UK GDPR, DUAA 2025 uplift note), JP (特定電子メール法
Arts. 3/4 including the three publication-context facts), EU directive floor
plus `EU/DE` (UWG §7) and `EU/FR` (CPCE L.34-5 + CNIL) poles, US (CAN-SPAM
including the harvested/dictionary-attack source-hygiene refusal), and the
explicit `none` disposition row. Every row carries its primary-source citation +
URL, `verified_at = 1784505600` (2026-07-20), `version = 1`, and a penalty note.
The pack-level warning ships with the pack and is never suppressed.

### `gate.rs` — the dispatch evaluation seam

One stage inside `evaluate_external_effect_policy`, placed after
`evaluate_gate` and BEFORE the connector-key/charter/budget stages (all of which
are guarded on would-be-Allow), so a legal-row refusal never consumes budget —
the same posture as the counterparty-opt-out wall. It converts a would-be Allow
AND a Pending: an owner approval must not be able to unlock a dispatch the
governing row forbids. It never converts an existing Deny. Plus
`GateReasonCode::DenyCampaignCompliance` and its metric class.

**Scope.** The stage returns early (no evaluation at all) unless the effect's
counterparty resolves to a comm-owned PERSON carrying an ACTIVE
`campaign.member` claim. Membership IS the campaign scope — the CRM pack's
ratified law is that a cohort is claims — so booking confirmations, support
replies, and every other non-campaign effect never enter it. The full existing
suite is green (46 binaries, 3763 lib + integration tests, 0 failures).

## Blueprint deviations (declared, none silently absorbed)

1. **Four additive pack-level dials.** `strict_pole_jurisdiction`,
   `jurisdiction_confidence_floor_millis`, `prohibited_list_provenance_classes`,
   and `conditional_exemption_evidence` were added to `CompliancePack`. The
   §8 ROW schema is byte-exact and untouched. Each dial exists to keep a policy
   decision in DATA that would otherwise have to become a Rust branch: the
   blueprint says "the configured strict pole" but named no field; the pinned
   `jurisdiction_confidence_millis` fact needs a floor to be load-bearing;
   CAN-SPAM's "harvested or dictionary-attack lists = AGGRAVATED violation"
   needs the prohibited set as data; and a `conditional` row must declare WHICH
   evidence it demands, or "UK wants legal form, JP wants publication context"
   becomes exactly the jurisdiction-specific `if` the blueprint forbids. Rust
   keeps only two mechanical primitives (`ComplianceExemptionEvidence`); the
   binding is a pack row.

2. **`campaign_compliance_gate` returns `Result<Option<ComplianceVerdict>>`,
   not `Result<Option<GateDecision>>`.** `GateDecision::deny` is private to
   `gate.rs` and the reason-code taxonomy lives there. Compliance answers with a
   pure verdict and `gate.rs` maps it, which keeps decision construction in the
   file that owns decisions instead of widening a gate constructor for a
   campaign module.

3. **Store/txn signatures instead of `&Vault` on the gate-side functions.** The
   chokepoint holds a `Store` and a live write txn, not a `Vault`; taking
   `&Vault` would force a second transaction (a torn read) or be uncallable.
   The blueprint's `load_active_compliance_pack(vault: &Vault)` is preserved
   verbatim as the public reader; `active_compliance_pack_in_txn` is its
   txn-composable twin.

4. **`hydrate_dispatch_compliance_facts` takes the resolved counterparty as a
   parameter.** Keeps `DispatchComplianceFacts.counterparty` a non-optional
   `EntityId` exactly as pinned. Applicability (resolve + membership) is
   `campaign_compliance_gate`'s job.

5. **Receipt reasons ride the `counterparty_` family.** `store.rs` owns a CLOSED
   receipt-reason vocabulary (`counterparty_` / `connector_key_` /
   `effector_budget_` / `charter_`) and `store.rs` is a hard non-claim. These
   walls are counterparty-scoped legal facts, so they are spelled
   `counterparty_compliance_*`. See PACKET_AMEND candidate #2.

6. **`compliance_amendment_notices` + `validate_compliance_pack` +
   `compliance_proposal_hash` are public and were not in the pinned signature
   list.** The first makes the blueprint's "durable notice" observable (the
   done-means asserts it); the second is the door every activation passes and is
   worth exposing to a host that wants to check a pack before proposing it; the
   third is what a stamper must compute to bind a proposal.

7. **`ComplianceRuleKind` also derives `Ord`/`PartialOrd`.** Row evaluation
   order must be deterministic for the verdicts to be assertable.

8. **Amendment rejections use `Error::InvalidConfig`.** `error.rs` is a
   non-claim, so no dedicated variant was minted; a proposed pack is runtime
   configuration input, which is that variant's stated meaning.

9. **`verified_at_max_age_secs` is 365 days, not a number the blueprint fixed.**
   Annual re-verification is the plausible counsel cadence. Consequence, stated
   plainly: the oracle's compliant arms run against the real clock and WILL
   start failing after 2027-07-20 with `counterparty_compliance_stale_rule`.
   That is the designed tripwire — a pack past re-verification must refuse to
   send — and the fix is a data revision to `seed_v1.json`, not a code change.
   It is documented at the top of the oracle so nobody mistakes it for a flake.

10. **Evidence claims are read at ANY approval status (lifecycle `Active` is the
    filter).** Requiring `Approved` would put a human approval in front of every
    compliant send — precisely the blanket review step the blueprint forbids —
    and only on the permissive side. Matches CA-01's stated posture for the
    enforcement-read families.

11. **Inline `#[cfg(test)] mod tests` rather than a `compliance/tests.rs`
    file.** The packet lists only `seed_v1.json` under `compliance/`.

## PACKET_AMEND candidates (NOT taken — for the orchestrator to rule)

1. **`campaign/claims.rs`: a `pub(crate)` counterparty resolver.**
   `resolve_do_not_contact_subject_in_txn` is module-private, so this lane
   carries a THIRD read-only mirror of SPINE-COMM's `comm.party.v1:` index
   (`comm.rs` owns it, `campaign/claims.rs` already mirrors it once, and
   `resolve_comm_party_in_txn` here is the third). It is ~30 lines, re-validates
   against synced truth exactly as CA-01's does, and answering `None` only
   WITHDRAWS compliance — it can never mis-attribute. The consolidation is a
   one-word visibility widening in a file this lane does not claim. `ONE-1868`
   already owns completing this resolution and is the natural place to collapse
   all three.

2. **`store.rs`: a `campaign_compliance_` receipt-reason family.** The closed
   vocabulary in `valid_gate_receipt_reason` forced deviation #5. A dedicated
   family would read better in receipts; `store.rs` is a hard wall, so it was
   not touched.

Neither is required for this ticket to be correct.

## Known holes / notes for the reviewer

- **Compliance scope is campaign membership.** A campaign send to a person with
  no `campaign.member` head is not evaluated. CA-03's enrollment writes
  membership before its outward leg, so the production path is covered, but a
  future send-capable surface that skips membership would skip compliance.
  Deliberate: the alternative (evaluate every external effect) would apply legal
  rows to booking confirmations and support replies.
- **Consent basis itself is not a compliance fact.** `consent_class` rows
  evaluate EXEMPTION AVAILABILITY (is the claimed B2B exemption reachable), not
  whether consent exists — that lives in `campaign.member`'s per-channel consent
  basis (CA-01) and the outbound-consent seam. A `conditional` row with unknown
  evidence blocks; a `no`-exemption row contributes no dispatch-time check.
- **JP email requires publication context.** Per the blueprint's explicit
  strict-path instruction, a JP email send with no hydrated publication record
  blocks. This is the Act's published-business-address lane by design; a
  consent-based JP lane would need its own seeded row.
- The seed is a starting dataset, not universal legal coverage, and it is not
  legal advice. The pack's `warning` says so and travels with the rows.

## Gates run

- `cargo fmt -p oneiron -- --check` — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — clean (workspace
  lints include `unwrap_used`, `cognitive_complexity`, `too_many_lines`,
  `redundant_clone`, `unreachable_pub` at deny).
- `cargo test -p oneiron --all-features` — 46 binaries, 0 failures, 0 flakes.
  16 inline compliance tests + 4 oracle tests are new.
- `Cargo.lock` is modified in the worktree by cargo resolving the landed CAL
  dependency append; it is NOT staged and NOT committed.
