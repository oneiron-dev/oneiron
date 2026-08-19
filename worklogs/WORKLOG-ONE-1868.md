# WORKLOG — ONE-1868 [CA-07] counterparty opt-out hydration repair

Branch `ONE-1868` off `origin/main` @ 9daac87f4 (ONE-1777 #616 merged; gate.rs writer
order 1772 -> 1777 -> 1868 honored).

Blueprint: `/Users/olety/.claude-wave5/blueprints/CA/ONE-1868.md`
Claims: `/Users/olety/.claude-wave5/blueprints/CA/CLAIMS.md`

## Ground truth found at HEAD

* `gate::hydrate_external_effect_contact` is the SINGLE hydration chokepoint. It is
  reached from exactly two callers — `gate::evaluate_external_effect_policy` (which
  `gate::check_external_effect_policy` and `outbound_chokepoint::execute_outbound_effect`
  both funnel through). Every shipping send path therefore flows through it.
* The dead-code bug: the type-132 read was guarded by
  `if let Some(identity_ref) = effect.channel_identity_ref` — and every shipping
  constructor leaves that field `None`:
  * `facade::MemoryFacade::schedule_outbound` -> `OutboundDispatchRequest::new(..)` (None)
  * `Vault::run_connector_task_executor` -> `OutboundDispatchRequest::new(..)` (None)
  * `Vault::dispatch_outbound_intent` -> caller-supplied, defaulted None
  so the wall never fired on any of them.
* The CA-01 `comm.do_not_contact` leg (ONE-1772) already ran identity-independently
  and already OR-folded; it was the only live source. This ticket completes the
  type-132 leg to the same standard.

## Legs implemented

**Leg 1 (correctness).** `counterparty` is now the ONLY required hydration input.
`(party_ref, channel_class)` decides; `channel_identity_ref` is enrichment that may
only ADD candidates.

**Leg 2 (enrichment).** `channel_identity_ref` is resolved from the governing
connector key at the outbound dispatch chokepoint.

## Deviations from the blueprint (declared, none silently absorbed)

1. **No index-completeness flag; the full type-132 scan is UNCONDITIONAL.**
   The blueprint's step 3 is "if party/channel index completeness is absent or false,
   full-scan". At HEAD completeness is not provable and nothing can set such a flag:
   records written before this change are unindexed, and records whose `identity_ref`
   resolves to no ChannelIdentity entity have no derivable channel class and are
   therefore *structurally* absent from the index. A flag that is always false is
   speculative machinery, so it is not built — the scan simply always runs, which is
   the strictly-safe end of the blueprint's own branch. ONE-1752's cutover owns
   proving completeness. No lazy repair is implemented either (hydration is read-only
   per the blueprint's `&RoTxn` skeleton, so it has no write txn to repair from, and
   the blueprint marks repair "optional / never correctness-critical").

2. **The party-channel index is a CANDIDATE source, never a verdict source.**
   Every index hit is re-validated through the same `(party, channel-class)` predicate
   the full scan uses. Consequence: no old-set removal is needed when a record's
   identity changes — a stale entry can never mis-attribute, it is filtered. This also
   makes the index self-healing rather than needing a second maintenance path.

3. **Helper return type is `Vec<(EntityId, CounterpartyContactRecord)>`, not
   `Vec<CounterpartyContactRecord>`.** The blueprint's own step 3 requires
   "de-duplicate by contact ref", which needs the ref. The pair shape also mirrors the
   module's existing `find_counterparty_contact` / `counterparty_contacts_for_identity`.
   `gate::counterparty_contacts_for_send` still returns bare records to the fold.

4. **Restrictive channel-class matching for records whose identity is unresolvable.**
   A type-132 record carries `identity_ref`, not a channel class; the class is derived
   by resolving the identity. When the identity resolves to no ChannelIdentity entity
   the record's class is UNKNOWN, and an unknown class MATCHES every queried class.
   This is the same uncertainty rule CA-01 already pins in
   `campaign::claims::do_not_contact_applies` ("a caller that does not know the channel
   cannot prove the suppression is irrelevant, so it matches"). Without it, an
   unresolvable identity would be a false negative — exactly the failure this ticket
   exists to kill.

5. **New receipt reason `counterparty_opt_out_do_not_contact`.** A do-not-contact-only
   deny previously carried `DenyCounterpartyOptOut` with an EMPTY receipt-reason list —
   unexplainable in the receipt. The blueprint's `fold_matching_comm_do_not_contact_heads`
   requires "preserve the deterministic restrictive receipt reason while folding"; this
   is that reason. It is inside `store.rs::valid_gate_receipt_reason`'s closed
   `counterparty_*` family (per the ONE-1777 note), lowercase/underscore only, 34 bytes
   (limit 128). A type-132 reason always wins it (first-wins, id-ordered).

6. **`facade.rs`, `task_verb.rs`, `outbound_consent.rs` claimed but NOT modified.**
   Claims are permissions, not obligations; under-use is safe, widening is not.
   * `facade::schedule_outbound` and `Vault::run_connector_task_executor` both build an
     `OutboundDispatchRequest` and hand it to `OutboundDispatchPipeline::dispatch_inner`.
     Enriching inside `dispatch_inner` covers BOTH plus every other dispatch caller.
     Enriching at each call site instead would be the `chokepoint-not-call-site` bug
     class this codebase already names. Leg 2 is therefore one chokepoint edit in
     `outbound.rs`.
   * `task_verb.rs`'s only `ExternalEffectGateInput` is the `tasks.cancel` gate
     (`channel: "tasks"`, `counterparty: None`). It is not a send, has no connector key
     and no channel identity; there is nothing to enrich. The real "task verb" send path
     is the connector-send TASK realization in `Vault::run_connector_task_executor`,
     which the oracle drives.
   * `outbound_consent.rs`'s only `ExternalEffectGateInput` is the scoped-MCP transport
     boundary: `channel: "mcp:<server>"`, `counterparty: None` by construction. The
     blueprint's own Notes rule this non-applicable ("outbound_consent samples with no
     counterparty remain non-applicable to a counterparty opt-out"). Giving it a
     counterparty would be inventing consent posture, which is forbidden.

7. **Oracle test-name mapping.** The blueprint names four path tests; the shipping
   paths that actually exist are three, and one blueprint name has no reachable subject:
   * `facade_bridge_recorded_opt_out_denies_send` — as specified.
   * `task_verb_recorded_opt_out_denies_send` + `connector_executor_recorded_opt_out_denies_send`
     are ONE path (the connector-send TASK executor); shipped as
     `connector_task_executor_recorded_opt_out_denies_send`, plus
     `dispatch_pipeline_recorded_opt_out_denies_send` for the direct
     `Vault::dispatch_outbound_intent` door so all three real doors are covered.
   * `outbound_consent_sample_recorded_opt_out_denies_send` — NOT shipped: its subject
     (`execute_scoped_mcp_outbound_call`) is `pub(crate)`, unreachable from an
     integration test, and carries no counterparty (deviation 6). The
     "no blanket wall" property it would have guarded is covered by
     `non_opted_out_contact_preserves_existing_gate_result`.
   * `proposed_and_stale_do_not_contact_heads_remain_restrictive` — the Proposed and
     stale-but-uncleared arms are shipped; the "authorized clear stamp" arm is CA-01's
     retract/supersede surface (`comm.rs` / `claim.rs` lifecycle), a NON-CLAIM here, and
     is already pinned by ONE-1772's own tests.

8. **The resolved channel identity participates in delivery-window subject resolution.**
   Leg 2 assigns the resolved identity onto `request.channel_identity_ref` before
   `outbound_delivery_window_decision_at_door` runs. `outbound_delivery_window_subjects`
   already lists `channel_identity_ref` as a subject — enrichment just stops that lookup
   from being permanently blind. Mutating the request mid-pipeline so that only the gate
   sees the identity would have left the receipt and the execution request lying about
   which identity sent.

9. **Ambiguous identity resolution yields `None`.** If more than one ACTIVE
   ChannelIdentity on the connector's channel is bound to the governing actor, Leg 2
   attaches nothing rather than picking arbitrarily — a nondeterministic receipt is
   worse than an absent one, and correctness never rests on this value.

10. **`external_effect_channel_class` collapsed into `normalize_channel_class`.** The
    blueprint names a gate-local wrapper; at implement time it had no body beyond
    delegating to the shared normalizer, so it was a second name for one rule at a
    single call site. The shared normalizer lives in `counterparty_contact.rs` next to
    the index writer that must agree with it. Deleted in the simplify pass.

11. **The oracle's `sending_vault` binds the PINNED actor `[0xE1; 16]`.** Constructed
    directly (not via `test_util::entity`) with an intent comment, per the seed-band
    law: under the seeded manifest only the first-party Eiri connector actor carries an
    Auto ceiling, so it is the only actor whose send can be OBSERVED reaching the
    connector. A generic seed pends on `gate.pending.actor_ceiling` and the control
    would prove nothing.

12. **The seeded-vault do-not-contact head is written `Proposed`, not `Approved`.** The
    seeded manifest's criticality floor pends an Approved `comm.do_not_contact` write.
    Proposed is also the harder assertion — restrictive-wins does not wait for approval.

## Anti-vacuity evidence

`cargo test --test counterparty_opt_out_shipping_paths_oracle` run with
`crates/oneiron/src/{gate,outbound,counterparty_contact}.rs` reverted to 9daac87f4:
**10 of 15 tests FAIL**, including every type-132 arm on all three shipping doors, the
executor arm, the scope-bleed arm, and the identity-enrichment arm. The 5 that pass
pre-fix are the intended controls and the CA-01 `comm.do_not_contact` regression guards
(that leg already worked; this ticket must not break it).

The executor arms specifically required a second fixture: on a fail-closed vault the
connector is never called either way, so `sink.calls == 0` was VACUOUSLY true against
pre-fix code. `sending_vault` + `connector_task_executor_control_reaches_the_connector`
measure a real send first, which is what makes the deny arm mean something.

## Known costs / follow-ups

* **The full type-132 scan now runs on EVERY external effect that names a
  counterparty**, where before it ran only on the (never-taken) identity-bearing branch.
  That is the price the blueprint sets for "never a false negative", and ONE-1752's
  cutover owns retiring it. Per-send cost is O(type-132 rows), plus one entity read per
  row to resolve its channel class.
* **The party-channel index has no test that distinguishes it from a no-op**, because
  the mandatory full scan returns a superset of its result at HEAD and `vault_meta` is
  not readable from an integration test. Direct coverage would need
  `crates/oneiron/src/counterparty_contact/tests.rs`, which is NOT on the ONE-1868
  manifest — flagged below as the one PACKET_AMEND candidate rather than taken
  unilaterally.

## PACKET_AMEND candidates

**One, NOT taken — owner/screener call:**
`/Users/olety/Desktop/code/oneiron/crates/oneiron/src/counterparty_contact/tests.rs`
(unit coverage that the party-channel index key/value round-trips and that the writer
indexes what it should). It is unlisted in `CLAIMS.md` — neither claimed nor named a
non-claim — so under "no CA ticket may edit an unlisted file" it stays untouched. The
index's user-visible behavior is fully covered by the integration oracle; only its
internal shape is uncovered.

Otherwise none. Every touched file is on the ONE-1868 MODIFY/CREATE list; three claimed
files are under-used (deviation 6). No NON-CLAIM was touched: `comm.rs`, `campaign/claims.rs`,
`outbound_chokepoint.rs`, `attempt_queue.rs`, `receipt.rs`, `channel_identity.rs`,
`registry.rs`, `connector_key.rs`, `store.rs`, `Cargo.toml`, `Cargo.lock` are all
untouched. `campaign::claims::counterparty_do_not_contact_in_txn` and
`connector_key::governing_connector_key` are IMPORTED, never edited.

## Gates

* Per-commit cheap gate: `cargo fmt --check` + `cargo clippy -p oneiron --all-features`.
* Final: `cargo test -p oneiron --all-features`.

## Simplify pass (K3, on tip 50a56b98a)

One deletion, nothing added:

* `gate::counterparty_contact_by_identity_index` no longer re-implements the
  type-132 entity read (raw get + header parse + type check + body decode); it
  calls the impl leg's own `read_counterparty_contact_in_txn`. Corruption paths
  still all return `Err(Error::CorruptedIndex(..))`; only the message strings of
  the two consolidated branches changed. `ENTITY_TYPE_COUNTERPARTY_CONTACT`
  moves to a `#[cfg(test)]` import — `gate/tests.rs` still uses it via
  `use super::*`, so the test module is untouched.

Deliberately kept (flagged, not done):

* The party-channel index READ in `counterparty_contacts_for_send` is
  observationally redundant at HEAD — the mandatory full scan returns a
  superset — but it is blueprint-keystone structure with a named future owner
  (ONE-1752 retires the scan, the index becomes the primary source). Deleting
  it is a redesign call, not a simplify call; the "index has no distinguishing
  test" follow-up above already tracks it.
* `outbound::enrich_dispatch_channel_identity` is a single-call-site wrapper,
  but it is the blueprint's named seam for the call sites that consolidated
  into `dispatch_inner` (deviation 6); kept as the documented shape.

Gates after the pass: `cargo fmt --check` clean; `cargo clippy -p oneiron
--all-features` clean; oracle 15/15 pass; scoped lib tests
(`gate:: counterparty_contact:: outbound::`) 209/209 pass.

## VERDICT-FIX (Opus, on tip 411ef13cc)

One verdict-verified REAL finding fixed; one banked with derivation and not
relitigated.

### P2 `channel-scope-correctness` — gate.rs `counterparty_contacts_for_send` (CONFIRMED)

`counterparty_contacts_for_send` merged three candidate sources, and only two of
them applied the channel-class predicate. The legacy identity+counterparty index
hit was pushed straight into the restrictive aggregate, and that index is keyed
by identity and party ALONE. A caller-pinned `channel_identity_ref` whose class
differs from the send's therefore dragged a foreign-channel opt-out row into the
fold: an email opt-out denied a TELEGRAM send merely because an email identity
rode along, while the otherwise identical identity-absent send allowed. That
makes enrichment a deny source of truth — the exact inversion the A9 contract
("`channel_identity_ref` is enrichment, never a requirement") and the
`party_channel_scope_does_not_bleed` done-means forbid. Reachable through the
public builder: `OutboundDispatchRequest::channel_identity_ref` →
`dispatch_outbound_intent`, where explicit identity wins over connector-key
resolution by design.

Fixed at the chokepoint, not the call site. Rather than adding the missing
predicate to the third source — leaving the next source one forgotten call from
the same bug — the class predicate now runs ONCE over the merged, de-duplicated
candidate set, and the two per-source filters are deleted:

* `counterparty_contact::counterparty_contacts_by_party_channel` and
  `counterparty_contacts_by_party_full_scan` re-validate the PARTY only; the
  full scan's now-unused `channel_class` parameter is gone.
* `gate::counterparty_contacts_for_send` applies
  `counterparty_contact_matches_channel_class` after the dedup, to every
  candidate whatever its source.

Sources find rows for the party; one fold decides which are in scope for the
class. No source can ship an unscoped row into the aggregate. UNKNOWN class
still matches every class, so the "never a false negative" law is untouched —
the fix can only ever remove a row that provably belongs to a different channel.

Mutation-verified both directions:

* Red-before: new oracle test
  `explicit_cross_channel_identity_never_changes_the_verdict` fails on the
  pre-fix tip with `["gate.deny.counterparty_opt_out"]` on a telegram send —
  the finder's trace reproduced exactly. Green after the fix.
* Predicate is load-bearing: neutralizing the single fold predicate turns BOTH
  `explicit_cross_channel_identity_never_changes_the_verdict` and the existing
  `party_channel_scope_does_not_bleed` red (14/16), proving the moved predicate
  now carries class scoping for all three sources rather than sitting dead
  beside surviving per-source filters.

Test support: `dispatch` was split into `dispatch` (identity absent, the
existing behaviour — every prior call site is unchanged) and
`dispatch_with_identity`, which pins an explicit `channel_identity_ref`. No
existing assertion or fixture was modified.

### P3 `test-coverage` (task-verb / outbound-consent oracle) — BANKED, no code action

Rejected with derivation by the verdict leg and not relitigated here: no
counterparty-carrying send constructor exists in `task_verb.rs` (only the
`tasks.cancel` gate, `counterparty: None`) or `outbound_consent.rs` (only the
scoped-MCP transport boundary, `counterparty: None` by construction, and the
blueprint Notes rule anonymous samples non-applicable). All real send doors are
covered with both the type-132-only and `comm.do_not_contact`-only arms at
`channel_identity_ref=None`. Builder deviations (facade/task_verb/outbound_consent
claims unmodified; test-name mapping; enrichment at the `dispatch_inner`
chokepoint) stay on the GATE-2 deviation board per items 6-7 above.

### Gates

* `cargo fmt -p oneiron --check` clean.
* `cargo clippy -p oneiron --all-features --all-targets` clean.
* `cargo test -p oneiron --all-features --test counterparty_opt_out_shipping_paths_oracle`
  16/16 pass.
* Full `cargo test -p oneiron --all-features`: 48 test binaries, all `ok`, zero
  failures (3809 lib tests + integration suites).
* Diff versus base 9daac87f4 is `gate.rs`, `counterparty_contact.rs`,
  `outbound.rs`, the oracle test, and this worklog. No `Cargo.toml`/`Cargo.lock`
  change (the lockfile is touched by cargo during builds and was restored, never
  staged).
