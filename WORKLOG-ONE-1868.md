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

## PACKET_AMEND candidates

None. Every touched file is on the ONE-1868 MODIFY/CREATE list; three claimed files are
under-used (deviation 6). No NON-CLAIM was touched: `comm.rs`, `campaign/claims.rs`,
`outbound_chokepoint.rs`, `attempt_queue.rs`, `receipt.rs`, `channel_identity.rs`,
`registry.rs`, `connector_key.rs`, `store.rs`, `Cargo.toml`, `Cargo.lock` are all
untouched. `campaign::claims::counterparty_do_not_contact_in_txn` and
`connector_key::governing_connector_key` are IMPORTED, never edited.

## Gates

* Per-commit cheap gate: `cargo fmt --check` + `cargo clippy -p oneiron --all-features`.
* Final: `cargo test -p oneiron --all-features`.
