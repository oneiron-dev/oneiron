# WORKLOG — ONE-1412 [FED-05] relationship-tagged federation membership

- branch `ONE-1412` off `origin/main` 321a93926 (ONE-1409 #637 merged)
- worktree `/Volumes/Cinema/w5-lt/ed-1764`
- blueprint `/Users/olety/.claude-wave5/blueprints/FED-SYNC/ONE-1412.md`

## Commits

| sha | subject |
|---|---|
| dc289946e | `WIP: ONE-1412 [FED-05] relationship resolver + trust tables + writer sugar` |
| e5fdca98e | `ONE-1412 [FED-05]: relationship-tagged membership tests (done-means 1-9)` |

Later amendment to `resolve_member_relationship` (explicit `trust_class` binding
instead of order-dependent struct-literal evaluation) folded into e5fdca98e.

## Packet

`git diff --name-only 321a93926..HEAD`:

- `/Volumes/Cinema/w5-lt/ed-1764/crates/oneiron/src/federation.rs` (+325)
- `/Volumes/Cinema/w5-lt/ed-1764/crates/oneiron/src/federation/tests.rs` (+698 / -1)

Exactly the declared packet. No `claim.rs` / `gate.rs` / `eiri.rs` /
`companion.rs` / `selector.rs` / `registry.rs` / `Cargo.toml` edit.
`Cargo.lock` left uncommitted (see Observations).

## What landed

All in `crates/oneiron/src/federation.rs`, after the pact-scope section:

- `PREDICATE_RELATIONSHIP_PERSON_REF` = `"core.relationship.person_ref"`,
  `PREDICATE_RELATIONSHIP_LABEL` = `"core.relationship.label"`,
  `MAX_RELATIONSHIP_LABEL_BYTES` = 64. Neither predicate is appended to
  `CLAIM_PREDICATE_REGISTRY` (asserted negatively in test).
- `RelationshipTrustClass`, `MemberRelationshipContext`, `MemberRelationship`
  exactly as the keystone skeleton declares them (derives and field order
  verbatim; no `#[non_exhaustive]` added).
- `resolve_member_relationship(vault, member_ref)` — signature verbatim, no
  actor parameter. Reads only through `Vault::claims_for_subject`,
  `Vault::get_claim`, `Vault::get_learned_at`.
  - person-ref contest: max by `(learned_at, claim_id)`. Approval does NOT
    order this axis.
  - label contest on the bound person: max by `(approved, learned_at, claim_id)`
    — Approved outranks Auto regardless of age.
  - Proposed / Rejected / Superseded / Retracted / wrong-predicate /
    non-string / non-canonical-hex / off-grammar values never enter either
    contest.
- `relationship_trust_class` / `default_trust_tier` / `default_retrieval_bands`
  — trust word lists, tier table (3/3/2/1/1/0) and band table quoted verbatim
  from the blueprint, including `Client = [Semantic, Crm, Productivity]`.
- `bind_member_person` — `vault.entity_exists(&person)` first, `Error::EntityNotFound`
  before any write; then an Approved Active claim through `Vault::put_claim`.
  Self-binding legal.
- `put_member_relationship_label` — rejects anything but Auto/Approved and any
  label outside `[a-z_]{1,64}` with `Error::InvalidClaimBody`; writes through
  the existing typed claim door (never a reserved/bypass door).
- Private helpers: `relationship_claims` (shared candidate collector),
  `put_relationship_claim` + `RelationshipClaim` (shared mint/put),
  `is_relationship_label`, `invalid_relationship_claim`. Canonical-hex parsing
  reuses the existing `decode_canonical_entity_ref`.

## Tests (crates/oneiron/src/federation/tests.rs) — done-means map

| done-means | test |
|---|---|
| 1 | `member_relationship_binds_a_person_and_reports_unbound_without_one` |
| 2 | `member_relationship_label_prefers_approved_then_newest` |
| 2 (person-ref axis) | `member_relationship_person_ref_takes_the_newest_then_highest_id` |
| 3 | `relationship_trust_tier_and_band_tables_are_fixed` |
| 4 | `unknown_labels_stay_unlabeled_class_and_closed_claims_never_win` |
| 5 | `member_relationship_resolution_is_agent_independent` |
| 6 | `member_relationship_resolves_for_every_grant_role_including_delegate` |
| 7 (read) | `malformed_relationship_claims_are_ignored_on_read` |
| 7 (write) + 9 | `relationship_writer_sugar_refuses_malformed_input` |
| 8 | `bind_member_person_refuses_a_nonexistent_person_before_writing` |

## Gates

- `cargo fmt -p oneiron -- --check` clean
- `cargo clippy -p oneiron --all-features --all-targets` clean (zero warnings)
- `cargo test -p oneiron --all-features` — 52 test binaries, all
  `test result: ok`, zero FAILED
- federation module: 27/27 pass

## Notes / observations

1. **Fixture seed constraint (caught red, fixed).** The first cut used
   `test_util::entity(0x72)` for the person id; its hex is all digits, so the
   uppercase-hex canonicality case was a no-op and the "non-canonical ref must
   not bind" assertion false-passed. Seed moved to `0xBC` with an intent
   comment, plus a mechanical `assert_ne!(hex.to_uppercase(), hex)` fixture
   guard at the site.
2. **Claim ids pinned in precedence tests.** `EntityId::now()` (UUIDv7) is only
   millisecond-ordered, so the id-descending tiebreak is asserted with explicit
   `test_util::entity(seed)` claim ids, not writer-minted ones.
3. **Client band ordering is verbatim.** `[Semantic, Crm, Productivity]` is NOT
   in `FEDERATION_SCOPE_BAND_ORDER` order (that order places Productivity before
   Crm). Kept verbatim per the content-ratified table; flagged rather than
   silently normalized.
4. **Pre-existing `Cargo.lock` drift on origin/main 321a93926** (NOT caused by
   this lane): `crates/oneiron/Cargo.toml` requires `chrono-tz`, `icalendar`,
   `rrule`; the committed `Cargo.lock` has none of them, so any `cargo` command
   re-locks and dirties the file (+172 lines). A `--locked` leg on main fails
   today. Lock left uncommitted per lane law.
5. **Untracked `WORKLOG-ONE-1591.md`** was already present in this reused
   worktree; not touched.

## Deviations / PACKET_AMEND

None. No deviation from the blueprint; no PACKET_AMEND candidate.

## Simplify pass (K3, 2026-08-07)

Deletion-biased review of the +325 in `federation.rs`. Verdict: **NO EDIT
WARRANTED**. Candidates examined and rejected:

- Deleting the `RelationshipClaim` writer bundle: would either duplicate the
  fixed `1.0`-confidence / `Active`-lifecycle literals across both writer doors
  or force a 7-positional-arg helper — a layer removed, a worse one gained.
- Splitting the generic `relationship_claims` read path into per-axis loops:
  the parse-closure generic is the single shared read door; splitting is
  duplication, not simplicity.
- No dead code, no defensive branches, no speculative generality found; the
  read path reuses the pre-existing `decode_canonical_entity_ref`, and
  `invalid_relationship_claim` mirrors the module's `invalid_pact_scope`
  pattern. Public API, precedence order, and fixed tables untouched (frozen).

Cheap gates after pass: `cargo check -p oneiron --all-features` clean,
`cargo clippy -p oneiron --all-features` zero warnings,
`cargo test -p oneiron --all-features --lib federation::` 27/27 ok.
