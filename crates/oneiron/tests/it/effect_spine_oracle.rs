// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! Effect Spine forward test oracle (doc 13, ONE-1713 epic) — authored by the
//! ONE-1714 path opener.
//!
//! Every test here is a CONTRACT from a downstream ticket's acceptance
//! criteria plus the ratified doc-13 section it cites, and is parked behind
//! `#[ignore = "armed by ONE-XXXX"]`. Arming discipline (board ruling):
//! the arming ticket removes the ignore, swaps the `seam` stubs below for the
//! real engine APIs, and adapts signatures — it NEVER weakens, widens, or
//! deletes an assert. Counts stay counts.
//!
//! The `seam` module is the thinnest plausible surface each ticket must
//! provide; every stub is `unimplemented!` so an armed-but-unbuilt contract
//! fails RED instead of vacuously passing.

use oneiron::{
    HnswConfig, Vault, VaultConfig, connector_key::ConnectorKeyRecord,
    connector_key::ConnectorKeyStatus, connector_key::EffectorBudget,
    connector_key::EffectorBudgetDimension, connector_key::EffectorBudgetOnExhaust,
    connector_key::EffectorBudgetWindow,
};

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = Some("test/model@v1".to_owned());
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_config()).unwrap();
    (dir, vault)
}

/// ES-03 comm oracle opener. Skips the default policy manifest so the ARCH-0035
/// projector's comm.* claim writes land instead of flooring to Critical/Pending
/// under the default gate; the comm oracle runs cacheless without that gate.
/// Gate-integrated comm semantics (default-manifest seed + the Recorded
/// write-class door) re-arm in ONE-1752. Pre-existing spine legs (es02 send
/// pipeline, later-armed tests) keep the seeded manifest via open_vault().
fn open_comm_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    (dir, vault)
}

/// PROOF (ONE-1716 sweep-11): the production `Vault::open` path ALWAYS seeds the
/// default policy manifest — even with `test-support` compiled in — so an
/// unseeded vault is reachable ONLY through the explicit open_unseeded_for_test
/// seam, never through `open()` or a config field. Here a normally-opened vault
/// gates the comm projector's opt_out claim write under the default policy,
/// unlike `open_comm_vault` above.
#[test]
fn es03_production_open_seeds_the_default_policy_gate() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), test_config()).unwrap();
    oneiron::comm::record_comm_inbound_stop(&vault, "party-seed-proof", "email", 10).unwrap();
    // Seeded: the projector's Auto comm.opt_out CLAIM write is floored by the
    // default policy gate (criticality floor), so the pass returns that specific
    // gate rejection rather than any error.
    assert!(
        matches!(
            oneiron::comm::run_comm_projector(&vault),
            Err(oneiron::comm::CommError::Engine(
                oneiron::Error::GateWriteRejected { .. }
            ))
        ),
        "production Vault::open must seed the default policy gate (comm claim write must be gate-rejected)"
    );
}

/// Outcome of asking to CLEAR a `comm.opt_out` claim (doc 13 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // contract vocabulary; arming tickets construct the rest
enum ClearOptOutOutcome {
    /// Widening ruled by a human first — the only lawful path.
    PendingHumanRuling,
    /// Silent widening — must never happen.
    ClearedImmediately,
}

/// AUTO-mode classifier ruling space (doc 13 §5 amendment / GATE-16/17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // contract vocabulary; arming tickets construct the rest
enum AutoGateRuling {
    Run,
    Deny,
    EscalateToHuman,
}

/// Minimal decision-history entry the classifier conditions on (doc 13 §5).
/// Entries carry the PRESET identity and the human-approved cap so history
/// can never act as an unbounded allow token: same-preset within-cap asks may
/// run, everything else re-escalates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecisionHistoryEntry {
    HumanApproved { preset: &'static str, cap: u64 },
}

/// Pre-execution fan-out estimate (doc 13 §5: "ENGINE ESTIMATES FIRST").
#[derive(Debug, Clone, PartialEq, Eq)]
struct FanOutEstimate {
    total: u64,
    /// (peer id, planned consult count) breakdown, e.g. codex 180 / cc-2 60.
    per_peer: Vec<(String, u64)>,
}

/// Effector-side dispatch tally for a batch of peer consults (doc 13 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DispatchTally {
    sent: u64,
    refused: u64,
}

/// Thinnest plausible seams for the downstream ES tickets. Each stub names
/// the ticket that must replace it with the real engine API.
#[allow(dead_code)]
mod seam {
    use std::cell::Cell;

    use oneiron::connector_key::ConnectorDispatchTelemetry;

    use super::{
        AutoGateRuling, ClearOptOutOutcome, ConnectorKeyRecord, ConnectorKeyStatus,
        DecisionHistoryEntry, DispatchTally, EffectorBudget, EffectorBudgetDimension,
        EffectorBudgetOnExhaust, EffectorBudgetWindow, FanOutEstimate, Vault,
    };

    thread_local! {
        static ORACLE_SEND_INVOCATIONS: Cell<usize> = const { Cell::new(0) };
    }

    // ---- ONE-1715 (ES-02): OutboundIntent -> TASK subkind ----

    /// Schedules one outbound send for `party` over `channel`.
    pub(crate) fn schedule_send(vault: &Vault, party: &str, channel: &str) {
        ORACLE_SEND_INVOCATIONS.set(0);
        let actor = oneiron::EntityId::from_bytes([0x71; 16]).expect("connector-task actor id");
        if vault.get_entity_type(&actor).expect("read actor").is_none() {
            vault
                .put_entity(
                    &actor,
                    oneiron::registry::ENTITY_TYPE_PERSON,
                    oneiron::temporal::TimeRange {
                        start: 100,
                        end: 100,
                    },
                    100,
                    b"effect-spine actor",
                )
                .expect("put actor");
        }
        vault
            .memory(actor, oneiron::EdgeActorClass::Human)
            .schedule_outbound(&oneiron::OutboundDraftInput {
                verb: "send".to_owned(),
                channel: channel.to_owned(),
                target: party.to_owned(),
                on_behalf_of: None,
                content_ref: None,
                idempotency_key: Some(format!("es02:{channel}:{party}")),
                dedupe_key: None,
                trigger: "agent_immediate".to_owned(),
                trigger_ref: "effect-spine:es02".to_owned(),
                job_ref: None,
                occurred_at: Some(100),
            })
            .expect("schedule connector-send task");
        let grant_id = oneiron::EntityId::from_bytes([0x72; 16]).expect("grant id");
        vault
            .mint_standing_outbound_grant(
                &grant_id,
                &oneiron::genui::GrantMintIntent {
                    principal_ref: actor.to_hex(),
                    origin_component_id: "effect_spine_oracle".to_owned(),
                    origin_action_id: "execute_connector_send".to_owned(),
                    origin_receipt_ref: None,
                    scope: oneiron::genui::GrantMintIntentScope::Channel {
                        channel: channel.to_owned(),
                    },
                },
                100,
            )
            .expect("mint executor grant");
    }

    /// TASK rows whose assignee is a connector actor (doc 13 §1).
    pub(crate) fn count_connector_assigned_tasks(vault: &Vault) -> usize {
        vault
            .connector_send_tasks()
            .expect("query connector-send tasks")
            .len()
    }

    /// Standalone outbound-intent rows that are NOT task subkinds (must
    /// reach zero for new sends once the reparent lands).
    pub(crate) fn count_standalone_outbound_intents(vault: &Vault) -> usize {
        vault
            .standalone_outbound_intent_count()
            .expect("count standalone outbound intents")
    }

    /// Runs the ONE-1499 dispatch pipeline as the executor for
    /// connector-assigned tasks; returns how many tasks it executed.
    pub(crate) fn run_connector_task_executor(vault: &Vault) -> usize {
        struct OracleSendSink;
        impl oneiron::outbound::OutboundExecutionSink for OracleSendSink {
            fn execute(
                &mut self,
                _request: &oneiron::outbound::OutboundExecutionRequest<'_>,
            ) -> oneiron::outbound::OutboundExecutionOutcome {
                let count = ORACLE_SEND_INVOCATIONS.get();
                ORACLE_SEND_INVOCATIONS.set(count.saturating_add(1));
                oneiron::outbound::OutboundExecutionOutcome::delivered_to_channel(
                    "oracle:wire-send",
                )
            }
        }
        vault
            .run_connector_task_executor(&mut OracleSendSink, 101)
            .expect("execute connector-send tasks")
    }

    /// Send receipts recorded for executed connector tasks.
    pub(crate) fn count_send_receipts(vault: &Vault) -> usize {
        vault
            .receipts(
                oneiron::receipt::ReceiptQuery::new(100)
                    .with_kind(oneiron::receipt::ReceiptKind::Outbound),
            )
            .expect("query send receipts")
            .len()
    }

    /// Send receipts that carry lineage back to their originating TASK.
    pub(crate) fn count_send_receipts_with_task_lineage(vault: &Vault) -> usize {
        vault
            .receipts(
                oneiron::receipt::ReceiptQuery::new(100)
                    .with_kind(oneiron::receipt::ReceiptKind::Outbound),
            )
            .expect("query send receipts")
            .into_iter()
            .filter(|receipt| {
                receipt
                    .fields
                    .get(oneiron::receipt::FIELD_TASK_REF)
                    .and_then(|task_ref| oneiron::EntityId::from_hex(task_ref).ok())
                    .and_then(|task_ref| vault.connector_send_task(&task_ref).ok().flatten())
                    .is_some()
            })
            .count()
    }

    /// Sends actually dispatched over the wire (transport-level), regardless
    /// of receipt bookkeeping — must stay zero until the executor runs.
    pub(crate) fn count_dispatched_sends(_vault: &Vault) -> usize {
        ORACLE_SEND_INVOCATIONS.get()
    }

    // ---- ONE-1716 (ES-03): comm.* projector + contact-record demotion ----

    fn comm_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }

    /// Records a successful send receipt event for (party, channel).
    pub(crate) fn record_send_receipt(vault: &Vault, party: &str, channel: &str) {
        oneiron::comm::record_comm_send_receipt(vault, party, channel, comm_now()).unwrap();
    }

    /// Records an inbound STOP surface event from `party` on `channel`.
    pub(crate) fn record_inbound_stop(vault: &Vault, party: &str, channel: &str) {
        oneiron::comm::record_comm_inbound_stop(vault, party, channel, comm_now()).unwrap();
    }

    /// Records a thread join/leave event for `party` in `thread`.
    pub(crate) fn record_thread_event(vault: &Vault, thread: &str, party: &str, joined: bool) {
        oneiron::comm::record_comm_thread_event(vault, thread, party, joined, comm_now()).unwrap();
    }

    /// Runs the ARCH-0035 declarative projector pass over pending events.
    pub(crate) fn run_comm_projector(vault: &Vault) {
        oneiron::comm::run_comm_projector(vault).unwrap();
    }

    /// ACTIVE claims counted by the FULL §3 conflict key
    /// (predicate, party, channel_class) — never party-only.
    pub(crate) fn count_active_comm_claims(
        vault: &Vault,
        predicate: &str,
        party: &str,
        channel_class: &str,
    ) -> usize {
        oneiron::comm::count_active_comm_claims(vault, predicate, party, channel_class).unwrap()
    }

    /// TOTAL claim rows (active + superseded) for the same full conflict
    /// key — replay idempotence must hold on totals, not just actives.
    pub(crate) fn count_total_comm_claim_rows(
        vault: &Vault,
        predicate: &str,
        party: &str,
        channel_class: &str,
    ) -> usize {
        oneiron::comm::count_total_comm_claim_rows(vault, predicate, party, channel_class).unwrap()
    }

    /// ACTIVE `comm.thread_member` claims for the §3 (thread, party) key.
    pub(crate) fn count_active_thread_member_claims(
        vault: &Vault,
        thread: &str,
        party: &str,
    ) -> usize {
        oneiron::comm::count_active_thread_member_claims(vault, thread, party).unwrap()
    }

    /// Pending human-gate rows for comm consent transitions.
    pub(crate) fn count_pending_comm_consent_gates(vault: &Vault) -> usize {
        oneiron::comm::count_pending_comm_consent_gates(vault).unwrap()
    }

    /// Asks to clear (widen) `comm.opt_out` for (party, channel).
    pub(crate) fn request_opt_out_clear(
        vault: &Vault,
        party: &str,
        channel: &str,
    ) -> ClearOptOutOutcome {
        match oneiron::comm::request_opt_out_clear(vault, party, channel, comm_now()).unwrap() {
            oneiron::comm::CommClearOptOutOutcome::PendingHumanRuling => {
                ClearOptOutOutcome::PendingHumanRuling
            }
        }
    }

    /// Applies the human ruling approving a pending opt-out clear.
    pub(crate) fn approve_pending_opt_out_clear(vault: &Vault, party: &str, channel: &str) {
        let actor_ref = oneiron::comm::resolve_or_create_comm_party(vault, party).unwrap();
        let actor = oneiron::WriteActor::new(actor_ref, oneiron::EdgeActorClass::Human);
        oneiron::comm::approve_pending_opt_out_clear(vault, party, channel, actor, comm_now())
            .unwrap();
    }

    /// An AGENT principal attempts to approve the pending clear — §4 gates
    /// are human-gated, so this must be refused with no state change.
    pub(crate) fn attempt_agent_opt_out_clear_approval(vault: &Vault, party: &str, channel: &str) {
        let actor_ref = oneiron::comm::resolve_or_create_comm_party(vault, party).unwrap();
        let actor = oneiron::WriteActor::new(actor_ref, oneiron::EdgeActorClass::Agent);
        let error =
            oneiron::comm::approve_pending_opt_out_clear(vault, party, channel, actor, comm_now())
                .expect_err("agent principal must be refused");
        assert!(matches!(
            error,
            oneiron::comm::CommError::HumanApprovalRequired
        ));
    }

    /// Receipts recorded for consent-widening rulings.
    pub(crate) fn count_opt_out_clear_receipts(vault: &Vault, party: &str) -> usize {
        oneiron::comm::count_opt_out_clear_receipts(vault, party).unwrap()
    }

    /// Canonical serialized bytes of the CID-7 contact record for `party`.
    pub(crate) fn materialize_contact_record(vault: &Vault, party: &str) -> Vec<u8> {
        oneiron::comm::materialize_contact_record(vault, party).unwrap()
    }

    /// Drops the cached contact record for `party` (cache, not truth).
    pub(crate) fn drop_contact_record(vault: &Vault, party: &str) {
        oneiron::comm::drop_contact_record(vault, party).unwrap();
    }

    /// Claim-derived entries materialized in the CID-7 record for `party` —
    /// a constant/no-op materializer must not be able to satisfy REPAIR.
    pub(crate) fn count_contact_record_claim_entries(vault: &Vault, party: &str) -> usize {
        oneiron::comm::count_contact_record_claim_entries(vault, party).unwrap()
    }

    // ---- ONE-1719 (ES-06): fan-out estimate-then-approve gate ----

    /// Registers a consult plan: (peer id, consult count) per peer, under a
    /// named preset. Returns an opaque plan handle.
    pub(crate) fn submit_fan_out_plan(
        _vault: &Vault,
        _preset: &str,
        _per_peer: &[(&str, u64)],
    ) -> u64 {
        unimplemented!("armed by ONE-1719: submit fan-out plan")
    }

    /// Pre-execution estimate for a submitted plan (doc 13 §5).
    pub(crate) fn estimate_fan_out(_vault: &Vault, _plan: u64) -> FanOutEstimate {
        unimplemented!("armed by ONE-1719: estimate count + per-peer breakdown")
    }

    /// Runs the dispatch gate over the plan (threshold + ladder + detectors).
    pub(crate) fn run_fan_out_gate(_vault: &Vault, _plan: u64) {
        unimplemented!("armed by ONE-1719: estimate-then-approve gate")
    }

    /// Runs one executor tick over the plan WITHOUT re-running the gate —
    /// a paused/denied plan must keep dispatching nothing across ticks.
    pub(crate) fn tick_fan_out_executor(_vault: &Vault, _plan: u64) {
        unimplemented!("armed by ONE-1719: executor tick over a gated plan")
    }

    /// Consults actually dispatched so far for the plan.
    pub(crate) fn count_dispatched_consults(_vault: &Vault, _plan: u64) -> u64 {
        unimplemented!("armed by ONE-1719: count dispatched consults")
    }

    /// `needs_input` approval rows surfaced for fan-out plans.
    pub(crate) fn count_needs_input_rows(_vault: &Vault) -> usize {
        unimplemented!("armed by ONE-1719: count needs_input rows")
    }

    /// Fan-out plans currently PAUSED (never silently killed).
    pub(crate) fn count_paused_fan_outs(_vault: &Vault) -> usize {
        unimplemented!("armed by ONE-1719: count paused plans")
    }

    /// Fan-out plans cancelled/killed by the engine without a human ruling.
    pub(crate) fn count_engine_killed_fan_outs(_vault: &Vault) -> usize {
        unimplemented!("armed by ONE-1719: count engine-killed plans (must stay 0)")
    }

    /// Board/metering rows rendered for fan-out runs (legibility lane).
    pub(crate) fn count_fan_out_board_rows(_vault: &Vault) -> usize {
        unimplemented!("armed by ONE-1719: count board metering rows")
    }

    /// Current fan-out approval threshold (consult count).
    pub(crate) fn fan_out_threshold(_vault: &Vault) -> u64 {
        unimplemented!("armed by ONE-1719: threshold knob read")
    }

    /// Tunes the fan-out approval threshold.
    pub(crate) fn set_fan_out_threshold(_vault: &Vault, _threshold: u64) {
        unimplemented!("armed by ONE-1719: threshold knob write")
    }

    /// Human approves a pending plan; `persist_cap` optionally records the
    /// choice as a receipted standing policy row ("always <= cap").
    pub(crate) fn approve_fan_out(_vault: &Vault, _plan: u64, _persist_cap: Option<u64>) {
        unimplemented!("armed by ONE-1719: approval ladder ruling")
    }

    /// Receipted standing fan-out policy rows.
    pub(crate) fn count_fan_out_policy_rows(_vault: &Vault) -> usize {
        unimplemented!("armed by ONE-1719: count persisted policy rows")
    }

    /// Receipts recorded for persisted standing-policy rows (spine law:
    /// a standing policy without a receipt is invisible authority).
    pub(crate) fn count_fan_out_policy_receipts(_vault: &Vault) -> usize {
        unimplemented!("armed by ONE-1719: count policy-row receipts")
    }

    /// Human DENIES a pending plan (doc 13 §5 ladder "[deny]").
    pub(crate) fn deny_fan_out(_vault: &Vault, _plan: u64) {
        unimplemented!("armed by ONE-1719: approval ladder deny ruling")
    }

    /// Plans parked in an EXPLICIT denied state (visible, not killed).
    pub(crate) fn count_denied_fan_outs(_vault: &Vault) -> usize {
        unimplemented!("armed by ONE-1719: count explicitly denied plans")
    }

    /// Receipts recorded for deny rulings.
    pub(crate) fn count_fan_out_denial_receipts(_vault: &Vault) -> usize {
        unimplemented!("armed by ONE-1719: count denial receipts")
    }

    /// Injects a consult cycle signature (A -> B -> A, same ask) into a
    /// submitted plan — before or during gating — so the pathology detector
    /// can trip at dispatch time.
    pub(crate) fn inject_consult_cycle(_vault: &Vault, _plan: u64) {
        unimplemented!("armed by ONE-1719: cycle-signature detector input")
    }

    /// Injects a per-peer rate spike into a submitted plan — before or
    /// during gating.
    pub(crate) fn inject_peer_rate_spike(_vault: &Vault, _plan: u64, _peer: &str) {
        unimplemented!("armed by ONE-1719: rate-spike detector input")
    }

    /// Consults dispatched AFTER the plan entered its paused state.
    pub(crate) fn count_consults_dispatched_while_paused(_vault: &Vault, _plan: u64) -> u64 {
        unimplemented!("armed by ONE-1719: dispatch-while-paused counter")
    }

    /// Resumes a paused plan on human approve (doc 13 §5: resume on approve).
    pub(crate) fn resume_fan_out(_vault: &Vault, _plan: u64) {
        unimplemented!("armed by ONE-1719: resume paused plan")
    }

    // ---- ONE-1720 (ES-07): AUTO-mode escalation learning (thin) ----

    /// AUTO-mode small-model classification of a fan-out ask of `consults`
    /// size. `uncertain` marks the fixture as outside standing policy / low
    /// confidence.
    pub(crate) fn classify_fan_out_ask(
        _vault: &Vault,
        _preset: &str,
        _consults: u64,
        _uncertain: bool,
        _history: &[DecisionHistoryEntry],
    ) -> AutoGateRuling {
        unimplemented!("armed by ONE-1720: GATE-16/17 classifier third output")
    }

    /// Applies a human ruling on an escalated ask: `approve` rules the plan
    /// runnable or denied; `persist` optionally stores the ruling as a
    /// policy row (storage schema deferred to workbench #6). Application is
    /// NOT optional — the pending escalation is consumed either way.
    pub(crate) fn apply_escalation_ruling(
        _vault: &Vault,
        _plan: u64,
        _approve: bool,
        _persist: bool,
    ) {
        unimplemented!("armed by ONE-1720: human ruling on escalation")
    }

    /// Pending (unruled) escalation rows.
    pub(crate) fn count_pending_escalations(_vault: &Vault) -> usize {
        unimplemented!("armed by ONE-1720: count pending escalation rows")
    }

    // ---- ONE-1721 (ES-08): optional per-peer EffectorBudget ----

    thread_local! {
        static PEER_BUDGET_NOW: Cell<u64> = const { Cell::new(1_000) };
    }

    fn peer_key(vault: &Vault, peer: &str) -> (oneiron::EntityId, ConnectorKeyRecord) {
        vault
            .connector_key_for(peer, None)
            .unwrap()
            .expect("peer connector key")
    }

    /// Mints a peer connector key (BYOA link).
    pub(crate) fn mint_peer_connector_key(vault: &Vault, peer: &str) -> ConnectorKeyRecord {
        PEER_BUDGET_NOW.with(|now| now.set(1_000));
        vault
            .mint_unbudgeted_connector_key(peer, None, 1_000)
            .unwrap()
    }

    /// Owner adds an optional per-peer budget row to a peer key.
    pub(crate) fn add_peer_budget_row(vault: &Vault, peer: &str, row: EffectorBudget) {
        let (id, _) = peer_key(vault, peer);
        vault
            .add_connector_key_budget(&id, row, PEER_BUDGET_NOW.with(Cell::get))
            .unwrap();
    }

    /// Dispatches `count` consults through the peer key's effector gate.
    ///
    /// Admission accounting belongs to the engine clock (ONE-1875), so the
    /// oracle freezes that clock through the test-only seam instead of
    /// handing the door a caller-picked time; the caller's own observation
    /// rides along as telemetry that must not move any budget window.
    pub(crate) fn dispatch_peer_consults(vault: &Vault, peer: &str, count: u64) -> DispatchTally {
        let (id, _) = peer_key(vault, peer);
        let accounting_now = PEER_BUDGET_NOW.with(Cell::get);
        let tally = vault
            .admit_connector_key_dispatches_at(
                &id,
                "peer",
                count,
                ConnectorDispatchTelemetry {
                    caller_observed_at: Some(accounting_now.saturating_sub(1)),
                },
                accounting_now,
            )
            .unwrap();
        assert_eq!(tally.accounted_at, accounting_now);
        DispatchTally {
            sent: tally.admitted,
            refused: tally.refused,
        }
    }

    /// BYOA handshake suggests a cap; it may only PRE-FILL the optional row.
    pub(crate) fn receive_handshake_cap_suggestion(vault: &Vault, peer: &str, cap: u64) {
        let (id, _) = peer_key(vault, peer);
        let row = EffectorBudget {
            dimension: EffectorBudgetDimension::Sends,
            channel_class: Some("peer".to_owned()),
            limit: cap,
            unit: None,
            window: EffectorBudgetWindow::Rolling { duration_s: 3_600 },
            on_exhaust: EffectorBudgetOnExhaust::Refuse,
            reserve_policy: None,
        };
        vault
            .suggest_connector_key_budget(&id, row, PEER_BUDGET_NOW.with(Cell::get))
            .unwrap();
    }

    /// Budget rows ACTIVE (enforced) on the peer key.
    pub(crate) fn count_active_peer_budget_rows(vault: &Vault, peer: &str) -> usize {
        peer_key(vault, peer).1.budgets.len()
    }

    /// Suggested-but-unaccepted (pre-filled) budget rows on the peer key.
    pub(crate) fn count_suggested_peer_budget_rows(vault: &Vault, peer: &str) -> usize {
        peer_key(vault, peer).1.suggested_budgets.len()
    }

    /// Human accepts the pre-filled suggested cap.
    pub(crate) fn accept_suggested_cap(vault: &Vault, peer: &str) {
        let (id, _) = peer_key(vault, peer);
        vault
            .accept_connector_key_budget_suggestion(&id, 0, PEER_BUDGET_NOW.with(Cell::get))
            .unwrap();
    }

    /// True while the peer key is ACTIVE (not suspended) — Refuse must
    /// never flip the key to Suspended.
    pub(crate) fn peer_key_active(vault: &Vault, peer: &str) -> bool {
        peer_key(vault, peer).1.status == ConnectorKeyStatus::Active
    }

    /// Advances/rolls the peer key's budget windows so exhausted rolling
    /// windows free up — the ENGINE accounting clock is what moves here; no
    /// caller-supplied observation can roll a window (ONE-1875).
    pub(crate) fn advance_budget_window(_vault: &Vault, _peer: &str) {
        PEER_BUDGET_NOW.with(|now| now.set(now.get().saturating_add(3_600)));
    }

    // ---- ONE-1722 (ES-09): read-time confidence for provider priors ----

    /// Writes `actor.confidence_prior = prior` as a claim on the provider
    /// actor, carrying `evidence` provenance (evidence-carrying, superseding
    /// — doc 13 §7).
    pub(crate) fn write_provider_prior(vault: &Vault, provider: &str, prior: f32, evidence: &str) {
        oneiron::provider_confidence::write_provider_prior(vault, provider, prior, evidence)
            .unwrap();
    }

    /// Writes one enrichment claim from `provider` with stored `confidence`;
    /// returns the claim ref.
    pub(crate) fn write_enrichment_claim(vault: &Vault, provider: &str, confidence: f32) -> String {
        oneiron::provider_confidence::write_enrichment_claim(vault, provider, confidence)
            .unwrap()
            .to_hex()
    }

    /// Read-time confidence: f(claim confidence, actor.confidence_prior).
    pub(crate) fn effective_confidence(vault: &Vault, claim_ref: &str) -> f32 {
        let claim_ref = oneiron::EntityId::from_hex(claim_ref).unwrap();
        oneiron::provider_confidence::effective_confidence(vault, &claim_ref).unwrap()
    }

    /// Stored (unmodified) claim confidence — read-time wiring must never
    /// rewrite the claim row.
    pub(crate) fn stored_confidence(vault: &Vault, claim_ref: &str) -> f32 {
        let claim_ref = oneiron::EntityId::from_hex(claim_ref).unwrap();
        oneiron::provider_confidence::stored_confidence(vault, &claim_ref).unwrap()
    }

    /// ACTIVE `actor.confidence_prior` claims for the provider actor.
    pub(crate) fn count_active_prior_claims(vault: &Vault, provider: &str) -> usize {
        oneiron::provider_confidence::count_active_prior_claims(vault, provider).unwrap()
    }

    /// SUPERSEDED `actor.confidence_prior` claims (history stays free).
    pub(crate) fn count_superseded_prior_claims(vault: &Vault, provider: &str) -> usize {
        oneiron::provider_confidence::count_superseded_prior_claims(vault, provider).unwrap()
    }

    /// ACTIVE `actor.confidence_prior` claims carrying exactly `evidence` —
    /// §7 priors are evidence-attached, never bare numbers.
    pub(crate) fn count_active_prior_claims_with_evidence(
        vault: &Vault,
        provider: &str,
        evidence: &str,
    ) -> usize {
        oneiron::provider_confidence::count_active_prior_claims_with_evidence(
            vault, provider, evidence,
        )
        .unwrap()
    }
}

// ===== ONE-1715 (ES-02) — OutboundIntent -> TASK subkind reparent =====

/// Doc 13 §1: "send email = TASK{assignee: connector actor}". A scheduled
/// send creates exactly one connector-assigned TASK and zero standalone
/// (non-task) outbound intents — the semantic twin dies.
#[test]
fn es02_send_becomes_exactly_one_connector_assigned_task() {
    let (_dir, vault) = open_vault();
    seam::schedule_send(&vault, "party-yura", "email");
    assert_eq!(seam::count_connector_assigned_tasks(&vault), 1);
    assert_eq!(seam::count_standalone_outbound_intents(&vault), 0);
}

/// Doc 13 §9.2: the ONE-1499 dispatch pipeline survives as the EXECUTOR for
/// connector-assigned tasks — executing the one task emits exactly one send
/// receipt, and that receipt carries TASK lineage (spine: RECEIPT is the
/// only record).
#[test]
fn es02_dispatch_pipeline_executes_task_and_emits_lineaged_receipt() {
    let (_dir, vault) = open_vault();
    seam::schedule_send(&vault, "party-yura", "email");
    // Scheduling alone must not send: zero receipts and zero wire
    // dispatches until the EXECUTOR runs (doc 13 §1/§9.2 — the pipeline is
    // the executor, not a bystander to an immediate send).
    assert_eq!(seam::count_send_receipts(&vault), 0);
    assert_eq!(seam::count_dispatched_sends(&vault), 0);
    let executed = seam::run_connector_task_executor(&vault);
    assert_eq!(executed, 1);
    assert_eq!(seam::count_send_receipts(&vault), 1);
    assert_eq!(seam::count_send_receipts_with_task_lineage(&vault), 1);
}

// ===== ONE-1795 — one TASK owns N node-local ATTEMPT tries =====

/// Retries the one connector-send ATTEMPT `times` times, returning the id of
/// every try in order (source first). Each retry finalizes the leased try and
/// mints the next one, so the returned ids are all distinct.
fn retry_send_attempt_chain(vault: &Vault, times: usize) -> Vec<oneiron::AttemptId> {
    let queue = oneiron::AttemptQueue::new(vault);
    let mut chain: Vec<oneiron::AttemptId> = queue
        .list()
        .expect("list attempt rows")
        .into_iter()
        .map(|attempt| attempt.id)
        .collect();
    assert_eq!(chain.len(), 1, "one scheduled send starts one try");

    let mut now = 200;
    for _ in 0..times {
        let oneiron::attempt_queue::ClaimOutcome::Claimed(claimed) = queue
            .claim(oneiron::attempt_queue::ClaimAttempt {
                lease_owner: "oracle-worker".to_owned(),
                now,
            })
            .expect("claim the pending try")
        else {
            panic!("the pending try must be claimable at {now}");
        };
        assert_eq!(claimed.id, *chain.last().expect("chain is never empty"));
        let oneiron::attempt_queue::RetryOutcome::Retried(next) = queue
            .retry(oneiron::attempt_queue::RetryAttempt {
                id: claimed.id,
                lease_owner: "oracle-worker".to_owned(),
                attempt_count: claimed.attempt_count,
                backoff_until: now + 10,
                last_error: Some("provider unavailable".to_owned()),
                now: now + 1,
            })
            .expect("retry the leased try")
        else {
            panic!("retry must return the newly scheduled try");
        };
        chain.push(next.id);
        now += 10;
    }
    chain
}

/// Doc 13 (effect-spine r2 grammar): one synced TASK owns N node-local ATTEMPT
/// rows. Retrying never resurrects a failed try — each try keeps its own id and
/// its own terminal history, and the chain is explicit through `retry_of`.
#[test]
fn es02_one_task_owns_many_attempt_ids_with_per_try_terminal_history() {
    let (_dir, vault) = open_vault();
    seam::schedule_send(&vault, "party-yura", "email");
    assert_eq!(seam::count_connector_assigned_tasks(&vault), 1);

    let chain = retry_send_attempt_chain(&vault, 3);

    // Three retries -> four tries, all distinct, under the SAME one task.
    assert_eq!(chain.len(), 4);
    assert_eq!(
        chain.iter().collect::<std::collections::HashSet<_>>().len(),
        4
    );
    assert_eq!(seam::count_connector_assigned_tasks(&vault), 1);

    let queue = oneiron::AttemptQueue::new(&vault);
    let rows = queue.list().expect("list attempt rows");
    assert_eq!(rows.len(), 4);
    for (index, id) in chain.iter().enumerate() {
        let row = queue
            .get(*id)
            .expect("read attempt row")
            .expect("every try stays independently queryable");
        assert_eq!(row.retry_of, index.checked_sub(1).map(|prev| chain[prev]));
        // Every try but the newest is terminal history with its own reason.
        if index + 1 == chain.len() {
            assert_eq!(row.state, oneiron::attempt_queue::AttemptState::Scheduled);
            assert_eq!(row.last_error, None);
        } else {
            assert_eq!(row.state, oneiron::attempt_queue::AttemptState::Failed);
            assert_eq!(row.last_error.as_deref(), Some("provider unavailable"));
        }
        // The whole logical send stays one paid intent: no try was sent.
        assert_eq!(seam::count_send_receipts(&vault), 0);
    }
}

/// Doc 13 §9.2: ATTEMPT rows are node-local execution state, never synced. The
/// synced surface is entities/edges; an attempt id is not an entity, so retry
/// churn cannot cross the wire — only the owning TASK is authoritative.
#[test]
fn es02_attempt_retry_churn_is_device_local_while_the_task_is_authoritative() {
    let (_dir_a, vault_a) = open_vault();
    let (_dir_b, vault_b) = open_vault();
    seam::schedule_send(&vault_a, "party-yura", "email");
    seam::schedule_send(&vault_b, "party-yura", "email");

    // Device A churns through four tries; device B stays on its first.
    let churned = retry_send_attempt_chain(&vault_a, 3);
    assert_eq!(churned.len(), 4);

    let rows_a = oneiron::AttemptQueue::new(&vault_a)
        .list()
        .expect("list device-A attempt rows");
    let rows_b = oneiron::AttemptQueue::new(&vault_b)
        .list()
        .expect("list device-B attempt rows");
    assert_eq!(rows_a.len(), 4);
    assert_eq!(
        rows_b.len(),
        1,
        "retry churn never crosses to another vault"
    );

    // No id is shared between the two devices' attempt stores.
    let ids_a: std::collections::HashSet<_> = rows_a.iter().map(|row| row.id).collect();
    let ids_b: std::collections::HashSet<_> = rows_b.iter().map(|row| row.id).collect();
    assert_eq!(ids_a.intersection(&ids_b).count(), 0);

    // Each device still has exactly one owning TASK — the synced authority.
    assert_eq!(seam::count_connector_assigned_tasks(&vault_a), 1);
    assert_eq!(seam::count_connector_assigned_tasks(&vault_b), 1);

    // Attempt ids live only in the node-local job tables: none of them is an
    // entity, so nothing about a try is reachable by the entity/edge sync
    // surface on either device.
    for row in rows_a.iter().chain(rows_b.iter()) {
        let as_entity = oneiron::EntityId::from_bytes(*row.id.as_bytes()).expect("16-byte id");
        assert_eq!(
            vault_a.get_entity_type(&as_entity).expect("read entity"),
            None
        );
        assert_eq!(
            vault_b.get_entity_type(&as_entity).expect("read entity"),
            None
        );
    }
}

// ===== ONE-1716 (ES-03) — comm.* projector + contact-record demotion =====

/// Doc 13 §3: "on receipt(send, ok) -> upsert comm.last_touch". One send
/// projects exactly one active claim; replaying the projector upserts (still
/// one), never duplicates.
#[test]
fn es03_send_receipt_projects_one_last_touch_claim_idempotently() {
    let (_dir, vault) = open_comm_vault();
    seam::record_send_receipt(&vault, "party-yura", "email");
    // Meaning-by-projection (§3): recording the event writes NO comm.*
    // claim — only the projector may.
    assert_eq!(
        seam::count_active_comm_claims(&vault, "comm.last_touch", "party-yura", "email"),
        0
    );
    seam::run_comm_projector(&vault);
    assert_eq!(
        seam::count_active_comm_claims(&vault, "comm.last_touch", "party-yura", "email"),
        1
    );
    assert_eq!(
        seam::count_total_comm_claim_rows(&vault, "comm.last_touch", "party-yura", "email"),
        1
    );
    seam::run_comm_projector(&vault);
    assert_eq!(
        seam::count_active_comm_claims(&vault, "comm.last_touch", "party-yura", "email"),
        1
    );
    // Replay idempotence holds on TOTAL rows (active + superseded): a
    // supersede-per-replay projector must fail here.
    assert_eq!(
        seam::count_total_comm_claim_rows(&vault, "comm.last_touch", "party-yura", "email"),
        1
    );
}

/// Doc 13 §4 (consent asymmetry, restrictive half): inbound STOP sets
/// `comm.opt_out` INSTANTLY — one active claim, zero pending human gates.
/// Safety tightens itself.
#[test]
fn es03_inbound_stop_sets_opt_out_automatically_without_human_gate() {
    let (_dir, vault) = open_comm_vault();
    seam::record_inbound_stop(&vault, "party-yura", "email");
    // Meaning-by-projection (§3): the raw STOP event alone is not a claim.
    assert_eq!(
        seam::count_active_comm_claims(&vault, "comm.opt_out", "party-yura", "email"),
        0
    );
    seam::run_comm_projector(&vault);
    assert_eq!(
        seam::count_active_comm_claims(&vault, "comm.opt_out", "party-yura", "email"),
        1
    );
    // §3 conflict key is (predicate, party, channel_class): the EMAIL stop
    // must not opt the party out of any other channel.
    assert_eq!(
        seam::count_active_comm_claims(&vault, "comm.opt_out", "party-yura", "linkedin"),
        0
    );
    assert_eq!(seam::count_pending_comm_consent_gates(&vault), 0);
}

/// Doc 13 §4 (widening half, FAIL-CLOSED): clearing opt_out is human-gated +
/// receipted. The clear request alone must NOT clear the claim — it parks as
/// a pending ruling; only the human approval clears it, with a receipt.
#[test]
fn es03_clearing_opt_out_is_human_gated_and_receipted() {
    let (_dir, vault) = open_comm_vault();
    seam::record_inbound_stop(&vault, "party-yura", "email");
    seam::run_comm_projector(&vault);

    let outcome = seam::request_opt_out_clear(&vault, "party-yura", "email");
    assert_eq!(outcome, ClearOptOutOutcome::PendingHumanRuling);
    // fail closed: still opted out, one pending gate row, nothing receipted.
    assert_eq!(
        seam::count_active_comm_claims(&vault, "comm.opt_out", "party-yura", "email"),
        1
    );
    assert_eq!(seam::count_pending_comm_consent_gates(&vault), 1);
    assert_eq!(seam::count_opt_out_clear_receipts(&vault, "party-yura"), 0);

    // §4 human-gated means HUMAN (authorization, not just sequencing): an
    // agent principal's approval is REFUSED — nothing clears, the gate
    // stays pending, nothing is receipted.
    seam::attempt_agent_opt_out_clear_approval(&vault, "party-yura", "email");
    assert_eq!(
        seam::count_active_comm_claims(&vault, "comm.opt_out", "party-yura", "email"),
        1
    );
    assert_eq!(seam::count_pending_comm_consent_gates(&vault), 1);
    assert_eq!(seam::count_opt_out_clear_receipts(&vault, "party-yura"), 0);

    seam::approve_pending_opt_out_clear(&vault, "party-yura", "email");
    assert_eq!(
        seam::count_active_comm_claims(&vault, "comm.opt_out", "party-yura", "email"),
        0
    );
    // §4 one-shot: the human approval CONSUMES the pending gate.
    assert_eq!(seam::count_pending_comm_consent_gates(&vault), 0);
    assert_eq!(seam::count_opt_out_clear_receipts(&vault, "party-yura"), 1);
}

/// Doc 13 §3: thread join/leave projects `comm.thread_member` as a standing
/// STATE — join yields one active membership claim, leave retires it.
#[test]
fn es03_thread_join_and_leave_project_membership_state() {
    let (_dir, vault) = open_comm_vault();
    seam::record_thread_event(&vault, "thread-1", "party-yura", true);
    // Meaning-by-projection (§3): the raw join event alone is not a claim.
    assert_eq!(
        seam::count_active_thread_member_claims(&vault, "thread-1", "party-yura"),
        0
    );
    seam::run_comm_projector(&vault);
    assert_eq!(
        seam::count_active_thread_member_claims(&vault, "thread-1", "party-yura"),
        1
    );
    // §3 conflict key is (thread, party): membership is per thread.
    assert_eq!(
        seam::count_active_thread_member_claims(&vault, "thread-2", "party-yura"),
        0
    );
    seam::record_thread_event(&vault, "thread-1", "party-yura", false);
    seam::run_comm_projector(&vault);
    assert_eq!(
        seam::count_active_thread_member_claims(&vault, "thread-1", "party-yura"),
        0
    );
}

/// Doc 13 §3 REPAIR law: "drop record, replay projector -> byte-identical".
/// The CID-7 contact record is a cache over claims — rebuilding it from
/// claims reproduces the exact bytes, and claims are untouched by the drop.
#[test]
fn es03_contact_record_rebuilds_byte_identical_from_claims() {
    let (_dir, vault) = open_comm_vault();
    seam::record_send_receipt(&vault, "party-yura", "email");
    seam::record_inbound_stop(&vault, "party-yura", "email");
    seam::run_comm_projector(&vault);

    let before = seam::materialize_contact_record(&vault, "party-yura");
    // A constant/no-op materializer must not pass REPAIR: the record has
    // real bytes and reflects BOTH claim-derived entries.
    assert!(!before.is_empty());
    assert_eq!(
        seam::count_contact_record_claim_entries(&vault, "party-yura"),
        2
    );
    let claims_before =
        seam::count_active_comm_claims(&vault, "comm.opt_out", "party-yura", "email")
            + seam::count_active_comm_claims(&vault, "comm.last_touch", "party-yura", "email");

    seam::drop_contact_record(&vault, "party-yura");
    // REPAIR law (§3): drop record, RE-RUN the projector/materializer pass,
    // rebuild from claims -> byte-identical.
    seam::run_comm_projector(&vault);
    let after = seam::materialize_contact_record(&vault, "party-yura");
    assert_eq!(
        seam::count_contact_record_claim_entries(&vault, "party-yura"),
        2
    );
    let claims_after =
        seam::count_active_comm_claims(&vault, "comm.opt_out", "party-yura", "email")
            + seam::count_active_comm_claims(&vault, "comm.last_touch", "party-yura", "email");

    assert_eq!(before, after);
    assert_eq!(claims_before, 2);
    assert_eq!(claims_after, 2);
}

// ===== ONE-1719 (ES-06) — fan-out estimate-then-approve gate =====

/// Doc 13 §5: the engine estimates FIRST — total plus per-peer breakdown
/// ("240 consults — codex 180, cc-2 60") — before anything dispatches.
#[test]
#[ignore = "armed by ONE-1719"]
fn es06_estimate_precedes_execution_with_per_peer_breakdown() {
    let (_dir, vault) = open_vault();
    let plan =
        seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 180), ("cc-2", 60)]);
    let estimate = seam::estimate_fan_out(&vault, plan);
    assert_eq!(estimate.total, 240);
    // The breakdown is pinned to the PLAN's peers — names AND counts, not
    // just a sum (a "codex 240 / cc-2 0" breakdown must fail).
    let mut per_peer = estimate.per_peer;
    per_peer.sort();
    assert_eq!(
        per_peer,
        vec![("cc-2".to_owned(), 60), ("codex".to_owned(), 180)]
    );
    // estimate-THEN-approve: nothing dispatched during estimation.
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 0);
}

/// Ticket ONE-1719: "silent under threshold knob (default 25)". A 24-consult
/// plan runs without any approval row — but still meters (board row).
#[test]
#[ignore = "armed by ONE-1719"]
fn es06_under_threshold_runs_silent_with_board_row_only() {
    let (_dir, vault) = open_vault();
    let plan = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 24)]);
    seam::run_fan_out_gate(&vault, plan);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 24);
    assert_eq!(seam::count_needs_input_rows(&vault), 0);
    assert_eq!(seam::count_fan_out_board_rows(&vault), 1);
}

/// Ticket ONE-1719: the threshold defaults to 25 and is tunable — and the
/// tuned value actually GOVERNS the gate (not just a getter roundtrip).
#[test]
#[ignore = "armed by ONE-1719"]
fn es06_threshold_defaults_to_25_and_is_tunable() {
    let (_dir, vault) = open_vault();
    assert_eq!(seam::fan_out_threshold(&vault), 25);
    seam::set_fan_out_threshold(&vault, 100);
    assert_eq!(seam::fan_out_threshold(&vault), 100);

    // 60 <= 100: runs silent under the raised threshold.
    let under = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 60)]);
    seam::run_fan_out_gate(&vault, under);
    assert_eq!(seam::count_dispatched_consults(&vault, under), 60);
    assert_eq!(seam::count_needs_input_rows(&vault), 0);

    // 150 > 100: pauses for approval.
    let over = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 150)]);
    seam::run_fan_out_gate(&vault, over);
    assert_eq!(seam::count_dispatched_consults(&vault, over), 0);
    assert_eq!(seam::count_needs_input_rows(&vault), 1);
}

/// FAIL-CLOSED core (doc 13 §5): an over-threshold plan PAUSES for approval.
/// It must never silently kill the plan AND never silently send — zero
/// consults out, zero engine kills, exactly one needs_input row, one pause.
#[test]
#[ignore = "armed by ONE-1719"]
fn es06_over_threshold_pauses_never_kills_never_sends() {
    let (_dir, vault) = open_vault();
    let plan =
        seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 180), ("cc-2", 60)]);
    seam::run_fan_out_gate(&vault, plan);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 0);
    assert_eq!(seam::count_needs_input_rows(&vault), 1);
    assert_eq!(seam::count_paused_fan_outs(&vault), 1);
    assert_eq!(seam::count_engine_killed_fan_outs(&vault), 0);

    // The pause is a DURABLE barrier, not an instantaneous check: a further
    // executor tick while paused still dispatches nothing.
    seam::tick_fan_out_executor(&vault, plan);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 0);
    assert_eq!(seam::count_paused_fan_outs(&vault), 1);
}

/// Doc 13 §5: approval unblocks the plan, and the "[always <= 500 for this
/// preset]" choice persists as ONE receipted policy row; a later 300-consult
/// plan under the same preset then runs silent (no second needs_input row).
#[test]
#[ignore = "armed by ONE-1719"]
fn es06_approval_persists_policy_row_and_later_plans_run_silent() {
    let (_dir, vault) = open_vault();
    let plan =
        seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 180), ("cc-2", 60)]);
    seam::run_fan_out_gate(&vault, plan);
    assert_eq!(seam::count_needs_input_rows(&vault), 1);

    seam::approve_fan_out(&vault, plan, Some(500));
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 240);
    assert_eq!(seam::count_fan_out_policy_rows(&vault), 1);
    // Standing policy is spine substrate: the policy row itself is
    // receipted, never invisible authority.
    assert_eq!(seam::count_fan_out_policy_receipts(&vault), 1);

    let second = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 300)]);
    seam::run_fan_out_gate(&vault, second);
    assert_eq!(seam::count_dispatched_consults(&vault, second), 300);
    assert_eq!(seam::count_needs_input_rows(&vault), 1); // no new row

    // The policy is PRESET-scoped, not a global allow: a different preset
    // still asks (needs_input increments, nothing dispatches).
    let other_preset = seam::submit_fan_out_plan(&vault, "outreach-preset", &[("codex", 300)]);
    seam::run_fan_out_gate(&vault, other_preset);
    assert_eq!(seam::count_dispatched_consults(&vault, other_preset), 0);
    assert_eq!(seam::count_needs_input_rows(&vault), 2);

    // And the cap is a CAP: 501 > "[always <= 500 for this preset]" asks
    // again under the SAME preset.
    let over_cap = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 501)]);
    seam::run_fan_out_gate(&vault, over_cap);
    assert_eq!(seam::count_dispatched_consults(&vault, over_cap), 0);
    assert_eq!(seam::count_needs_input_rows(&vault), 3);
}

/// Doc 13 §5 pathology lane: a consult cycle (A -> B -> A, same ask) PAUSES
/// the plan and surfaces a row — never a silent kill, no dispatch while
/// paused — and the plan resumes on approve.
#[test]
#[ignore = "armed by ONE-1719"]
fn es06_consult_cycle_pauses_surfaces_and_resumes_on_approve() {
    let (_dir, vault) = open_vault();
    let plan = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 10)]);
    // The pathology signal is present BEFORE gating: the gate must catch it
    // at dispatch time, not only observe it after the fact.
    seam::inject_consult_cycle(&vault, plan);
    seam::run_fan_out_gate(&vault, plan);
    // §5 "PAUSE + surface row": both, exactly once — and the barrier holds.
    assert_eq!(seam::count_paused_fan_outs(&vault), 1);
    assert_eq!(seam::count_needs_input_rows(&vault), 1);
    assert_eq!(seam::count_engine_killed_fan_outs(&vault), 0);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 0);
    assert_eq!(
        seam::count_consults_dispatched_while_paused(&vault, plan),
        0
    );

    seam::resume_fan_out(&vault, plan);
    assert_eq!(seam::count_paused_fan_outs(&vault), 0);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 10);
}

/// Doc 13 §5 pathology lane: a per-peer rate spike gets the same PAUSE
/// semantics — pause + surface, never kill — and resumes on approve.
#[test]
#[ignore = "armed by ONE-1719"]
fn es06_peer_rate_spike_pauses_not_kills() {
    let (_dir, vault) = open_vault();
    let plan = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 10)]);
    // Signal present BEFORE gating (same ordering as the cycle test).
    seam::inject_peer_rate_spike(&vault, plan, "codex");
    seam::run_fan_out_gate(&vault, plan);
    // §5 "PAUSE + surface row": both, exactly once — and the barrier holds.
    assert_eq!(seam::count_paused_fan_outs(&vault), 1);
    assert_eq!(seam::count_needs_input_rows(&vault), 1);
    assert_eq!(seam::count_engine_killed_fan_outs(&vault), 0);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 0);
    assert_eq!(
        seam::count_consults_dispatched_while_paused(&vault, plan),
        0
    );

    seam::resume_fan_out(&vault, plan);
    assert_eq!(seam::count_paused_fan_outs(&vault), 0);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 10);
}

/// Doc 13 §5 ladder "[deny]": a human deny ruling on an over-threshold plan
/// dispatches NOTHING (including on later executor ticks), consumes the
/// pending needs_input row, records the denial as a receipt, and parks the
/// plan in an EXPLICIT denied state — never a silent engine kill.
#[test]
#[ignore = "armed by ONE-1719"]
fn es06_deny_ruling_dispatches_nothing_and_records_denial() {
    let (_dir, vault) = open_vault();
    let plan =
        seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 180), ("cc-2", 60)]);
    seam::run_fan_out_gate(&vault, plan);
    assert_eq!(seam::count_needs_input_rows(&vault), 1);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 0);

    seam::deny_fan_out(&vault, plan);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 0);
    // The denial is durable across executor ticks.
    seam::tick_fan_out_executor(&vault, plan);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 0);
    // The pending ask is consumed, the ruling receipted, the plan visibly
    // denied — and NOT silently killed by the engine.
    assert_eq!(seam::count_needs_input_rows(&vault), 0);
    assert_eq!(seam::count_fan_out_denial_receipts(&vault), 1);
    assert_eq!(seam::count_denied_fan_outs(&vault), 1);
    assert_eq!(seam::count_engine_killed_fan_outs(&vault), 0);
}

// ===== ONE-1720 (ES-07) — AUTO-mode escalation learning (thin oracle) =====

/// Doc 13 §5 amendment: the GATE-16/17 classifier gains a THIRD output —
/// uncertain / over-policy asks ESCALATE TO HUMAN instead of forcing an
/// allow/deny.
#[test]
#[ignore = "armed by ONE-1720"]
fn es07_classifier_escalates_uncertain_asks_to_human() {
    let (_dir, vault) = open_vault();
    let ruling = seam::classify_fan_out_ask(&vault, "research-preset", 60, true, &[]);
    assert_eq!(ruling, AutoGateRuling::EscalateToHuman);
}

/// Doc 13 §5 amendment: "the classifier conditions on decision history — it
/// learns from escalations". History entries carry preset identity and the
/// approved cap, so history is a SCOPED license, not an unbounded allow
/// token: same-preset within-cap runs; different-preset and over-cap asks
/// re-escalate.
#[test]
#[ignore = "armed by ONE-1720"]
fn es07_classifier_conditions_on_decision_history() {
    let (_dir, vault) = open_vault();
    let history = [DecisionHistoryEntry::HumanApproved {
        preset: "research-preset",
        cap: 500,
    }];

    // Same preset, within the approved cap: the uncertain ask may Run.
    let ruling = seam::classify_fan_out_ask(&vault, "research-preset", 300, true, &history);
    assert_eq!(ruling, AutoGateRuling::Run);

    // DIFFERENT preset with the same history: re-escalate.
    let ruling = seam::classify_fan_out_ask(&vault, "outreach-preset", 300, true, &history);
    assert_eq!(ruling, AutoGateRuling::EscalateToHuman);

    // Same preset but OVER the approved cap: re-escalate.
    let ruling = seam::classify_fan_out_ask(&vault, "research-preset", 501, true, &history);
    assert_eq!(ruling, AutoGateRuling::EscalateToHuman);
}

/// Ticket ONE-1720: "human rulings OPTIONALLY persist as policy rows"
/// (storage schema deferred to workbench ask #6). Persistence is optional —
/// APPLICATION is not: every ruling consumes its pending escalation and has
/// the observable outcome it ruled (approved plans run their full count,
/// denied plans run nothing). persist=false writes no policy row;
/// persist=true writes exactly one.
#[test]
#[ignore = "armed by ONE-1720"]
fn es07_human_ruling_persistence_is_optional() {
    let (_dir, vault) = open_vault();
    let plan = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 60)]);
    seam::run_fan_out_gate(&vault, plan);
    assert_eq!(seam::count_pending_escalations(&vault), 1);

    // Approved, unpersisted: escalation consumed, the plan actually runs,
    // no policy row.
    seam::apply_escalation_ruling(&vault, plan, true, false);
    assert_eq!(seam::count_pending_escalations(&vault), 0);
    assert_eq!(seam::count_dispatched_consults(&vault, plan), 60);
    assert_eq!(seam::count_fan_out_policy_rows(&vault), 0);

    // Denied, unpersisted: escalation consumed, ZERO consults run.
    let second = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 60)]);
    seam::run_fan_out_gate(&vault, second);
    assert_eq!(seam::count_pending_escalations(&vault), 1);
    seam::apply_escalation_ruling(&vault, second, false, false);
    assert_eq!(seam::count_pending_escalations(&vault), 0);
    assert_eq!(seam::count_dispatched_consults(&vault, second), 0);
    assert_eq!(seam::count_fan_out_policy_rows(&vault), 0);

    // Approved, persisted: applied AND exactly one policy row written.
    let third = seam::submit_fan_out_plan(&vault, "research-preset", &[("codex", 60)]);
    seam::run_fan_out_gate(&vault, third);
    seam::apply_escalation_ruling(&vault, third, true, true);
    assert_eq!(seam::count_pending_escalations(&vault), 0);
    assert_eq!(seam::count_dispatched_consults(&vault, third), 60);
    assert_eq!(seam::count_fan_out_policy_rows(&vault), 1);
}

// ===== ONE-1721 (ES-08) — optional per-peer EffectorBudget + handshake =====

/// Ticket ONE-1721: "Peer keys ship budgets: [] (default OFF)".
#[test]
fn es08_peer_keys_ship_with_empty_budgets() {
    let (_dir, vault) = open_vault();
    let key = seam::mint_peer_connector_key(&vault, "peer-codex");
    assert_eq!(key.budgets.len(), 0);
}

/// Doc 13 §6 "free hands" / DEC-0005 empty-table law: an empty budget table
/// means UNCAPPED — 500 consults all dispatch, zero refused. Catches any
/// hidden default cap.
#[test]
fn es08_empty_budget_table_is_uncapped() {
    let (_dir, vault) = open_vault();
    let _key = seam::mint_peer_connector_key(&vault, "peer-codex");
    let tally = seam::dispatch_peer_consults(&vault, "peer-codex", 500);
    assert_eq!(tally.sent, 500);
    assert_eq!(tally.refused, 0);
}

/// Ticket ONE-1721: the owner MAY add `{dimension: rate|sends,
/// channel_class: "peer"}` rows — once added, the row enforces at the
/// dispatch gate (10 allowed, the 11th refused; on_exhaust = Refuse keeps
/// the key active).
#[test]
fn es08_owner_added_rate_row_enforces_at_dispatch_gate() {
    let (_dir, vault) = open_vault();
    let _key = seam::mint_peer_connector_key(&vault, "peer-codex");
    seam::add_peer_budget_row(
        &vault,
        "peer-codex",
        EffectorBudget {
            dimension: EffectorBudgetDimension::Rate,
            channel_class: Some("peer".to_owned()),
            limit: 10,
            unit: None,
            window: EffectorBudgetWindow::Rolling { duration_s: 3_600 },
            on_exhaust: EffectorBudgetOnExhaust::Refuse,
            reserve_policy: None,
        },
    );
    let tally = seam::dispatch_peer_consults(&vault, "peer-codex", 11);
    assert_eq!(tally.sent, 10);
    assert_eq!(tally.refused, 1);
}

/// Ticket ONE-1721: budgets are "{dimension: rate|sends}" — the SENDS
/// dimension enforces at the dispatch gate too, and on_exhaust = Refuse
/// refuses WITHOUT suspending the key: the key stays active and a
/// within-budget send succeeds once the window rolls over.
#[test]
fn es08_owner_added_sends_row_enforces_and_refuse_does_not_suspend() {
    let (_dir, vault) = open_vault();
    let _key = seam::mint_peer_connector_key(&vault, "peer-codex");
    seam::add_peer_budget_row(
        &vault,
        "peer-codex",
        EffectorBudget {
            dimension: EffectorBudgetDimension::Sends,
            channel_class: Some("peer".to_owned()),
            limit: 5,
            unit: None,
            window: EffectorBudgetWindow::Rolling { duration_s: 3_600 },
            on_exhaust: EffectorBudgetOnExhaust::Refuse,
            reserve_policy: None,
        },
    );
    let tally = seam::dispatch_peer_consults(&vault, "peer-codex", 6);
    assert_eq!(tally.sent, 5);
    assert_eq!(tally.refused, 1);
    // Refuse != Suspend: the key stays ACTIVE after exhaustion…
    assert!(seam::peer_key_active(&vault, "peer-codex"));
    // …and a within-budget send dispatches again after the window rolls.
    seam::advance_budget_window(&vault, "peer-codex");
    let tally = seam::dispatch_peer_consults(&vault, "peer-codex", 1);
    assert_eq!(tally.sent, 1);
    assert_eq!(tally.refused, 0);
}

/// Ticket ONE-1721 (fail-closed on widening the cap INTO existence): a BYOA
/// handshake cap suggestion only PRE-FILLS the optional row — zero active
/// rows, dispatch stays uncapped, until the human accepts; acceptance
/// activates exactly one row.
#[test]
fn es08_handshake_cap_suggestion_prefills_but_never_activates_itself() {
    let (_dir, vault) = open_vault();
    let _key = seam::mint_peer_connector_key(&vault, "peer-codex");
    seam::receive_handshake_cap_suggestion(&vault, "peer-codex", 200);
    assert_eq!(seam::count_active_peer_budget_rows(&vault, "peer-codex"), 0);
    assert_eq!(
        seam::count_suggested_peer_budget_rows(&vault, "peer-codex"),
        1
    );
    // still uncapped past the suggested cap while unaccepted.
    let tally = seam::dispatch_peer_consults(&vault, "peer-codex", 201);
    assert_eq!(tally.sent, 201);
    assert_eq!(tally.refused, 0);

    seam::accept_suggested_cap(&vault, "peer-codex");
    assert_eq!(seam::count_active_peer_budget_rows(&vault, "peer-codex"), 1);
    assert_eq!(
        seam::count_suggested_peer_budget_rows(&vault, "peer-codex"),
        0
    );
    // The accepted cap is ENFORCED at the dispatch gate: 201 against the
    // accepted 200 sends 200 and refuses 1. (Weakest form per the oracle
    // rules: debits are asserted from activation onward — pre-acceptance
    // uncapped sends do not retroactively count against the row.)
    let tally = seam::dispatch_peer_consults(&vault, "peer-codex", 201);
    assert_eq!(tally.sent, 200);
    assert_eq!(tally.refused, 1);
}

// ===== ONE-1722 (ES-09) — read-time confidence for provider priors =====

/// Doc 13 §7: "read-time confidence = f(claim confidence, actor prior)".
/// The composition responds to BOTH inputs: same stored confidence with
/// different priors orders by prior, and same prior with different stored
/// confidences orders by claim confidence. No stored row is rewritten, and
/// priors carry their evidence (§7 evidence-attached priors).
#[test]
fn es09_read_time_confidence_composes_claim_confidence_and_prior() {
    let (_dir, vault) = open_vault();
    seam::write_provider_prior(&vault, "provider_clearbit", 0.72, "evidence:audit-2026-07");
    seam::write_provider_prior(
        &vault,
        "provider_scraper",
        0.30,
        "evidence:spotcheck-2026-06",
    );
    let claim_a = seam::write_enrichment_claim(&vault, "provider_clearbit", 0.9);
    let claim_b = seam::write_enrichment_claim(&vault, "provider_scraper", 0.9);

    // Prior axis: same stored confidence, higher prior reads higher.
    let eff_a = seam::effective_confidence(&vault, &claim_a);
    let eff_b = seam::effective_confidence(&vault, &claim_b);
    assert!(
        eff_a > eff_b,
        "prior 0.72 must read more confident than prior 0.30 (got {eff_a} vs {eff_b})"
    );

    // Claim-confidence axis: same provider/prior, higher stored confidence
    // reads higher — a prior-only composition must fail here.
    let claim_c = seam::write_enrichment_claim(&vault, "provider_clearbit", 0.4);
    let eff_c = seam::effective_confidence(&vault, &claim_c);
    assert!(
        eff_a > eff_c,
        "stored 0.9 must read more confident than stored 0.4 under the same \
         prior (got {eff_a} vs {eff_c})"
    );

    // read-TIME wiring: stored claim rows are untouched.
    assert!((seam::stored_confidence(&vault, &claim_a) - 0.9).abs() < 1e-6);
    assert!((seam::stored_confidence(&vault, &claim_b) - 0.9).abs() < 1e-6);
    assert!((seam::stored_confidence(&vault, &claim_c) - 0.4).abs() < 1e-6);

    // §7: the prior claim row carries its evidence — exactly one active
    // prior with exactly the provenance it was written with.
    assert_eq!(
        seam::count_active_prior_claims_with_evidence(
            &vault,
            "provider_clearbit",
            "evidence:audit-2026-07"
        ),
        1
    );
}

/// Doc 13 §7: priors are superseding claims with free history ("supersedes:
/// 0.65 (06-30)"). After superseding 0.65 -> 0.72, reads use the NEW prior,
/// exactly one prior claim is active and exactly one superseded.
#[test]
fn es09_superseding_a_prior_changes_subsequent_reads() {
    let (_dir, vault) = open_vault();
    seam::write_provider_prior(
        &vault,
        "provider_clearbit",
        0.65,
        "evidence:initial-2026-06",
    );
    let claim = seam::write_enrichment_claim(&vault, "provider_clearbit", 0.9);
    let eff_before = seam::effective_confidence(&vault, &claim);

    seam::write_provider_prior(&vault, "provider_clearbit", 0.72, "evidence:audit-2026-07");
    let eff_after = seam::effective_confidence(&vault, &claim);

    assert!(
        eff_after > eff_before,
        "raised prior must raise read-time confidence (got {eff_before} -> {eff_after})"
    );
    assert_eq!(
        seam::count_active_prior_claims(&vault, "provider_clearbit"),
        1
    );
    assert_eq!(
        seam::count_superseded_prior_claims(&vault, "provider_clearbit"),
        1
    );
    // The ACTIVE prior is the superseding one, carrying the NEW evidence.
    assert_eq!(
        seam::count_active_prior_claims_with_evidence(
            &vault,
            "provider_clearbit",
            "evidence:audit-2026-07"
        ),
        1
    );
}

// ── CAL-04 (ONE-1786): calendar.invite on the effect spine ──────────────
//
// The invite is not a second spine. It is one more channel verb through the
// SAME chokepoint, so what this leg pins is that the spine's own guarantees —
// gate first, exactly one durable intent, exactly-once transport — hold for it
// unchanged, and that the calendar-specific state (the UID/SEQUENCE passport)
// obeys them too: a gate-denied invite advances no sequence, and a retry
// replays frozen bytes instead of minting anything.

mod calendar_invite_fixture {
    use super::{Vault, open_vault};

    pub(super) const UID: &str = "one-1786-oracle@oneiron.test";
    pub(super) const RECIPIENT: &str = "guest@example.test";

    fn id(seed: u8) -> oneiron::EntityId {
        oneiron::EntityId::from_bytes([seed; 16]).expect("fixture id")
    }

    pub(super) fn actor_ref() -> oneiron::EntityId {
        id(0x91)
    }

    pub(super) fn event_ref() -> oneiron::EntityId {
        id(0x92)
    }

    /// A vault carrying every precondition one lawful REQUEST stands on: the
    /// EVENT its UID names, an ACTIVE dedicated sending identity on the primary
    /// domain, the R7 booking-page standing grant, and the rendered invitation
    /// in the blob store.
    pub(super) fn admitted_vault() -> (tempfile::TempDir, Vault, String) {
        let (dir, vault) = open_vault();
        let actor = actor_ref();
        vault
            .put_entity(
                &actor,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::temporal::TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
                b"cal-04 oracle actor",
            )
            .expect("put actor");
        vault
            .put_entity(
                &event_ref(),
                oneiron::registry::ENTITY_TYPE_EVENT,
                oneiron::temporal::TimeRange {
                    start: 1_800_003_600,
                    end: 1_800_007_200,
                },
                100,
                b"cal-04 oracle event",
            )
            .expect("put event");
        oneiron::calendar::index_passport_uid(&vault, UID, &event_ref()).expect("index uid");

        let mut identity = oneiron::channel_identity::ChannelIdentity::requested(
            "email",
            "me@primary.test",
            oneiron::channel_identity::ChannelIdentityShape::DedicatedAddress,
            oneiron::channel_identity::ChannelIdentityBinding::agent(actor),
            100,
        );
        identity.state = oneiron::channel_identity::ChannelIdentityState::Active;
        vault
            .create_channel_identity(&id(0x93), &identity)
            .expect("create sending identity");

        vault
            .mint_standing_outbound_grant(
                &id(0x94),
                &oneiron::genui::GrantMintIntent {
                    principal_ref: actor.to_hex(),
                    origin_component_id: "effect_spine_oracle".to_owned(),
                    origin_action_id: "confirm_booking".to_owned(),
                    origin_receipt_ref: None,
                    scope: oneiron::genui::GrantMintIntentScope::Contact {
                        contact_ref: RECIPIENT.to_owned(),
                    },
                },
                100,
            )
            .expect("mint booking grant");

        let ics = oneiron::emit_imip_ics(&oneiron::ImipEmitRequest {
            method: oneiron::CalendarInviteMethod::Request,
            uid: UID.to_owned(),
            sequence: 0,
            organizer: "me@primary.test".to_owned(),
            attendees: vec![RECIPIENT.to_owned()],
            summary: "Confirmed booking".to_owned(),
            starts_at_utc: 1_800_003_600,
            ends_at_utc: 1_800_007_200,
            tz_label: "Europe/Warsaw".to_owned(),
            dtstamp_utc: 1_800_000_000,
        })
        .expect("emit invitation");
        let blob_ref = oneiron::persist_imip_blob(
            &vault,
            &id(0x95),
            "one-1786 oracle invitation",
            &ics,
            &oneiron::blob_artifact::BlobVersionProvenance::AgentRun {
                run_ref: "one-1786-oracle".to_owned(),
            },
            oneiron::WriteActor::new(actor, oneiron::EdgeActorClass::Human),
            100,
        )
        .expect("persist invitation blob");
        (dir, vault, blob_ref)
    }

    pub(super) fn invite(blob_ref: &str) -> oneiron::CalendarInviteSurfaceInput {
        oneiron::CalendarInviteSurfaceInput {
            method: oneiron::CalendarInviteSurfaceMethod::Request,
            uid: UID.to_owned(),
            sequence: 0,
            ics_blob_ref: blob_ref.to_owned(),
            recipient: RECIPIENT.to_owned(),
        }
    }

    /// Records the `text/calendar` part every dispatched invite carries.
    #[derive(Default)]
    pub(super) struct InviteSink {
        pub(super) parts: Vec<(String, Vec<u8>)>,
    }

    impl oneiron::outbound::OutboundExecutionSink for InviteSink {
        fn execute(
            &mut self,
            request: &oneiron::outbound::OutboundExecutionRequest<'_>,
        ) -> oneiron::outbound::OutboundExecutionOutcome {
            let part = request
                .calendar_invite
                .as_ref()
                .expect("a calendar.invite send carries its iMIP part");
            self.parts
                .push((part.content_type.clone(), part.ics.clone()));
            oneiron::outbound::OutboundExecutionOutcome::delivered_to_channel("oracle:imip-send")
        }
    }

    pub(super) fn live_sequence(vault: &Vault) -> Option<u32> {
        oneiron::calendar::live_passports_for_event(vault, &event_ref())
            .expect("passports")
            .into_iter()
            .find(|(_, value)| value.uid == UID)
            .map(|(_, value)| value.last_sequence)
    }
}

/// CAL-04's spine oracle: gate first, one durable intent, exactly once.
#[test]
fn calendar_invite_gate_and_intent_ledger_oracle() {
    use calendar_invite_fixture as fixture;

    // ── admitted: one gate decision, one intent, one wire send ──────────
    let (_dir, vault, blob_ref) = fixture::admitted_vault();
    let facade = vault.memory(fixture::actor_ref(), oneiron::EdgeActorClass::Human);

    let receipt = facade
        .calendar_invite(&fixture::invite(&blob_ref))
        .expect("a lawful invite schedules");
    assert_eq!(receipt.outcome, "held");
    assert_eq!(receipt.gate_outcome.as_deref(), Some("allow"));
    assert!(receipt.gate_decision_ref.is_some());
    assert_eq!(vault.connector_send_tasks().expect("tasks").len(), 1);
    // The SEQUENCE bump landed with the attempt/TASK, not before it.
    assert_eq!(fixture::live_sequence(&vault), Some(0));
    // The schedule side never touches transport, so no intent exists yet.
    assert!(
        oneiron::outbound_intent_ledger::intent_ledger_records(&vault)
            .expect("ledger")
            .is_empty()
    );

    let mut sink = fixture::InviteSink::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, 200)
            .expect("execute"),
        1
    );
    assert_eq!(sink.parts.len(), 1, "exactly one wire send");
    assert_eq!(
        sink.parts[0].0,
        "text/calendar; method=REQUEST; charset=utf-8"
    );
    assert!(
        String::from_utf8(sink.parts[0].1.clone())
            .expect("utf-8")
            .contains("METHOD:REQUEST\r\n"),
        "the connector resolved the frozen blob into the real iMIP document"
    );

    // EXACTLY one intent-ledger record, on the ordinary channel/verb pair.
    let records = oneiron::outbound_intent_ledger::intent_ledger_records(&vault).expect("ledger");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].server, "calendar");
    assert_eq!(records[0].tool, "calendar.invite");
    assert!(records[0].idempotency_supported, "iMIP replay is a no-op");

    // Retry is exactly-once and mints nothing: the queue row is done, the
    // ledger is unchanged, and the SEQUENCE has not moved.
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, 300)
            .expect("re-run"),
        0
    );
    assert_eq!(sink.parts.len(), 1, "a retry sends no second invite");
    assert_eq!(
        oneiron::outbound_intent_ledger::intent_ledger_records(&vault)
            .expect("ledger")
            .len(),
        1
    );
    assert_eq!(fixture::live_sequence(&vault), Some(0));

    // Re-scheduling the same revision coalesces on the durable delivered-send
    // index rather than sending a second invitation.
    let again = facade
        .calendar_invite(&fixture::invite(&blob_ref))
        .expect("a re-schedule of a delivered revision coalesces");
    assert!(again.deduped);
    assert_eq!(again.outcome, "already_sent");
    assert_eq!(fixture::live_sequence(&vault), Some(0));

    // ── denied: the gate stops it before anything durable happens ───────
    let (_dir2, denied_vault, denied_blob) = fixture::admitted_vault();
    denied_vault
        .mint_unbudgeted_connector_key("calendar", None, 100)
        .expect("mint calendar connector key");
    let (key_id, _) = denied_vault
        .connector_key_for("calendar", None)
        .expect("read key")
        .expect("calendar connector key");
    denied_vault
        .suspend_connector_key(&key_id, "oracle_suspension", 100)
        .expect("suspend calendar connector key");

    let denied_facade = denied_vault.memory(fixture::actor_ref(), oneiron::EdgeActorClass::Human);
    let denied = denied_facade
        .calendar_invite(&fixture::invite(&denied_blob))
        .expect("a gate denial is an audited receipt, not an error");
    assert_eq!(denied.outcome, "suppressed");
    assert_eq!(denied.gate_outcome.as_deref(), Some("deny"));
    assert!(
        denied.gate_decision_ref.is_some(),
        "a denial is still a queryable governance receipt"
    );

    // Nothing executable, nothing durable, and — the calendar-specific half —
    // no UID minted and no SEQUENCE advanced behind a refused send.
    assert!(
        denied_vault
            .connector_send_tasks()
            .expect("tasks")
            .is_empty()
    );
    assert!(
        oneiron::outbound_intent_ledger::intent_ledger_records(&denied_vault)
            .expect("ledger")
            .is_empty()
    );
    assert_eq!(fixture::live_sequence(&denied_vault), None);

    let mut denied_sink = fixture::InviteSink::default();
    assert_eq!(
        denied_vault
            .run_connector_task_executor(&mut denied_sink, 200)
            .expect("execute"),
        0
    );
    assert!(
        denied_sink.parts.is_empty(),
        "a gate denial produces no connector execution"
    );
}

// ===== ONE-1891 (ES-09 production integration) — effective confidence as an
// entity-resolution INPUT =====
//
// ADDITIVE ONLY. Nothing above this banner is edited: the ONE-1720 sites and
// the ONE-1722 ES-09 legs keep every assert they were armed with. What this
// section adds is the production reads ONE-1722 stopped short of — the
// `provider.enrichment` write validator, the DISPOSABLE prior indexes, and the
// ARCH-0024 candidate waterfall that ranks on `effective_confidence`.
//
// DEFAULT-FEATURE WRITE SURFACE. A `provider.enrichment` claim can be written
// on the default feature set through exactly three doors — the targeted put,
// the batch put, and the transaction-composable batch — and the validator
// tests below drive all three. `Vault::put_replicated` is deliberately NOT a
// fourth: both of its definitions are `pub(crate)` and feature-gated
// (`sync` / `any(test, all(sync, test-hooks))`), i.e. an origin-validated
// replay door for bytes a peer already authored, not a public write door.
// `one1891_put_replicated_is_not_a_fourth_write_door` pins that by source, so
// "three doors" cannot quietly become "three doors plus a hole".

mod one1891 {
    use super::{Vault, test_config};
    use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
    use oneiron::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
        EntityResolutionCandidate, EntityResolutionWaterfallDecision, TimeRange,
    };
    use rmpv::Value;

    pub(super) const INGEST_SOURCE: &str = include_str!("../../src/ingest.rs");
    pub(super) const CLAIM_CORE_TYPES_SOURCE: &str = include_str!("../../src/claim/core_types.rs");
    pub(super) const PROVIDER_CONFIDENCE_SOURCE: &str =
        include_str!("../../src/provider_confidence.rs");
    pub(super) const BATCH_TXN_BUILDER_SOURCE: &str =
        include_str!("../../src/batch/txn_builder.rs");
    pub(super) const BATCH_BUILDER_SOURCE: &str = include_str!("../../src/batch/builder.rs");

    /// A vault WITHOUT the default policy manifest, for the two legs whose
    /// subject is a claim WRITE rather than the waterfall read: the Gate's
    /// criticality ladder is ES-03/ONE-1752 scope, and letting it floor an
    /// unrelated candidate write would prove nothing about ONE-1891. The
    /// waterfall legs themselves run on the ordinary seeded `open_vault()` —
    /// they write nothing, so there is nothing for a gate to decide.
    pub(super) fn open_unseeded_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
        (dir, vault)
    }

    pub(super) fn at(ts: u64) -> TimeRange {
        TimeRange { start: ts, end: ts }
    }

    /// A fixture id whose FIRST byte drives `EntityId`'s byte-lexicographic
    /// order, so a test can pin which of two actors is "smallest" instead of
    /// hoping.
    pub(super) fn fixture_id(lead: u8) -> EntityId {
        let mut bytes = [0x5a_u8; 16];
        bytes[0] = lead;
        EntityId::from_bytes(bytes).expect("fixture id")
    }

    pub(super) fn msgpack(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, value).expect("encode fixture body");
        bytes
    }

    /// A plain PERSON with an opaque body — never a provider actor.
    pub(super) fn put_person(vault: &Vault, lead: u8) -> EntityId {
        let id = fixture_id(lead);
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, at(100), 100, b"one1891 person")
            .expect("put person");
        id
    }

    /// A PERSON carrying exactly the `provider_key` body the truth scan looks
    /// for. Minting actors HERE — rather than letting `write_provider_prior`
    /// mint them — is what lets these tests own the ids the shortcut rows are
    /// supposed to be disposable about.
    pub(super) fn put_provider_actor(vault: &Vault, lead: u8, provider: &str) -> EntityId {
        let id = fixture_id(lead);
        let body = msgpack(&Value::Map(vec![(
            Value::from("provider_key"),
            Value::from(provider),
        )]));
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, at(100), 100, &body)
            .expect("put provider actor");
        id
    }

    /// The `provider.enrichment` value map: the attribution key plus whatever
    /// payload keys the provider shipped alongside it.
    pub(super) fn enrichment_value(provider: &str, siblings: &[(&str, &str)]) -> Value {
        let mut entries = vec![(Value::from("provider"), Value::from(provider))];
        for (key, value) in siblings {
            entries.push((Value::from(*key), Value::from(*value)));
        }
        Value::Map(entries)
    }

    pub(super) fn enrichment_body(
        subject: ClaimSubject,
        value: Value,
        confidence: f32,
    ) -> ClaimBody {
        let mut body = ClaimBody::new(
            oneiron::PREDICATE_PROVIDER_ENRICHMENT,
            subject,
            value,
            confidence,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.valid_from = Some(200);
        body.source = Some(ClaimSource::Observed);
        body
    }

    /// Writes one enrichment claim through the ordinary targeted put door.
    pub(super) fn put_enrichment(
        vault: &Vault,
        lead: u8,
        subject: EntityId,
        provider: &str,
        confidence: f32,
    ) -> EntityId {
        let id = fixture_id(lead);
        let body = enrichment_body(
            ClaimSubject::Entity(subject),
            enrichment_value(provider, &[]),
            confidence,
        );
        vault
            .put_claim(&id, &body, at(200), 200)
            .expect("put enrichment claim");
        id
    }

    /// A subject entity plus its enrichment claim: one waterfall candidate.
    pub(super) fn candidate(
        vault: &Vault,
        subject_lead: u8,
        claim_lead: u8,
        provider: &str,
        confidence: f32,
    ) -> EntityResolutionCandidate {
        let subject = put_person(vault, subject_lead);
        let confidence_claim_ref = put_enrichment(vault, claim_lead, subject, provider, confidence);
        EntityResolutionCandidate {
            subject,
            confidence_claim_ref,
        }
    }

    pub(super) fn write_prior(
        vault: &Vault,
        provider: &str,
        prior: f32,
        evidence: &str,
    ) -> EntityId {
        oneiron::provider_confidence::write_provider_prior(vault, provider, prior, evidence)
            .expect("write provider prior")
    }

    pub(super) fn effective(vault: &Vault, claim: &EntityId) -> f32 {
        oneiron::provider_confidence::effective_confidence(vault, claim).expect("effective")
    }

    pub(super) fn stored(vault: &Vault, claim: &EntityId) -> f32 {
        oneiron::provider_confidence::stored_confidence(vault, claim).expect("stored")
    }

    pub(super) fn decide(
        vault: &Vault,
        candidates: &[EntityResolutionCandidate],
        high_collision: bool,
    ) -> EntityResolutionWaterfallDecision {
        oneiron::evaluate_entity_resolution_waterfall(vault, candidates, high_collision)
            .expect("waterfall")
    }

    pub(super) fn close(actual: f32, expected: f32) -> bool {
        (actual - expected).abs() < 1e-6
    }

    /// `(PERSON entities, CLAIM entities)` — the two counts a read must never
    /// move.
    pub(super) fn counts(vault: &Vault) -> (u64, u64) {
        (
            vault
                .count_entities_by_type(ENTITY_TYPE_PERSON)
                .expect("person count"),
            vault
                .count_entities_by_type(ENTITY_TYPE_CLAIM)
                .expect("claim count"),
        )
    }

    pub(super) fn active_priors(vault: &Vault, provider: &str) -> usize {
        oneiron::provider_confidence::count_active_prior_claims(vault, provider)
            .expect("active prior count")
    }

    pub(super) fn superseded_priors(vault: &Vault, provider: &str) -> usize {
        oneiron::provider_confidence::count_superseded_prior_claims(vault, provider)
            .expect("superseded prior count")
    }

    pub(super) fn priors_with_evidence(vault: &Vault, provider: &str, evidence: &str) -> usize {
        oneiron::provider_confidence::count_active_prior_claims_with_evidence(
            vault, provider, evidence,
        )
        .expect("evidence-carrying prior count")
    }

    pub(super) fn index_presence(vault: &Vault, provider: &str) -> (bool, bool) {
        oneiron::provider_confidence_index_presence(vault, provider).expect("index presence")
    }

    pub(super) fn clear_indexes(vault: &Vault, provider: &str) {
        oneiron::clear_provider_confidence_indexes(vault, provider).expect("clear indexes");
    }

    pub(super) fn set_indexes(
        vault: &Vault,
        provider: &str,
        actor_row: Option<&[u8]>,
        prior_head_row: Option<&[u8]>,
    ) {
        oneiron::set_provider_confidence_index_raw(vault, provider, actor_row, prior_head_row)
            .expect("set raw index rows");
    }

    /// Extracts `[start_marker, end_marker)` from a source file, for the
    /// assertions whose subject is a property of the CODE — how many
    /// transactions a function opens, which validator arm sits where. A
    /// behavioural test cannot see either.
    pub(super) fn source_slice<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
    ) -> &'a str {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("start marker absent: {start_marker}"));
        let rest = &source[start..];
        let end = rest
            .find(end_marker)
            .unwrap_or_else(|| panic!("end marker absent: {end_marker}"));
        &rest[..end]
    }

    pub(super) fn waterfall_body() -> &'static str {
        source_slice(
            INGEST_SOURCE,
            "pub fn evaluate_entity_resolution_waterfall",
            "\npub type IngestResult",
        )
    }
}

/// The three DEFAULT-FEATURE doors a `provider.enrichment` claim can be
/// written through. The validator sits at the shared chokepoint
/// (`validate_claim_body_and_decode`, reached from `apply_put` BEFORE the
/// write gate), so all three must reject the same bytes for the same reason.
mod one1891_doors {
    use super::Vault;
    use super::one1891::{at, enrichment_body, fixture_id};
    use oneiron::{
        ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
        WriteActor, WriteEnvelope, WriteProvenance,
    };
    use rmpv::Value;

    #[derive(Clone, Copy, Debug)]
    pub(super) enum WriteDoor {
        TargetedPut,
        BatchPut,
        TransactionalBatch,
    }

    pub(super) const WRITE_DOORS: [WriteDoor; 3] = [
        WriteDoor::TargetedPut,
        WriteDoor::BatchPut,
        WriteDoor::TransactionalBatch,
    ];

    impl WriteDoor {
        pub(super) fn label(self) -> &'static str {
            match self {
                Self::TargetedPut => "put_claim",
                Self::BatchPut => "batch().claim_candidate().commit()",
                Self::TransactionalBatch => "batch_in().claim_candidate().apply()",
            }
        }
    }

    fn envelope(actor: EntityId) -> WriteEnvelope {
        WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::Observed,
            WriteProvenance::new(Value::from("one1891 enrichment fixture"))
                .expect("fixture provenance"),
            ClaimApprovalStatus::Approved,
        )
    }

    /// Writes `value` under `provider.enrichment` through `door`, returning
    /// whatever that door returns.
    pub(super) fn write_enrichment_through(
        vault: &Vault,
        door: WriteDoor,
        claim_lead: u8,
        subject: ClaimSubject,
        actor: EntityId,
        value: Value,
    ) -> oneiron::Result<()> {
        let id = fixture_id(claim_lead);
        match door {
            WriteDoor::TargetedPut => {
                vault.put_claim(&id, &enrichment_body(subject, value, 0.8), at(200), 200)
            }
            WriteDoor::BatchPut => vault
                .batch()
                .claim_candidate(
                    &id,
                    ClaimCandidate::new(
                        oneiron::PREDICATE_PROVIDER_ENRICHMENT,
                        subject,
                        value,
                        0.8,
                    ),
                    &envelope(actor),
                    at(200),
                    200,
                )
                .commit(),
            WriteDoor::TransactionalBatch => vault.with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .claim_candidate(
                        &id,
                        ClaimCandidate::new(
                            oneiron::PREDICATE_PROVIDER_ENRICHMENT,
                            subject,
                            value,
                            0.8,
                        ),
                        &envelope(actor),
                        at(200),
                        200,
                    )
                    .apply(wtxn)
            }),
        }
    }
}

// ── ARCH-0024: ranking, banding, routing ───────────────────────────────────

/// The whole reason this leg exists: the candidate with the highest STORED
/// confidence loses to the one with the highest EFFECTIVE confidence.
///
/// A stored 0.90 from a provider the vault has learned to trust at 0.50 reads
/// 0.45; a stored 0.60 from a provider with no prior reads 0.60 and wins. A
/// ranking that consulted `body.confidence` would pick the other one.
#[test]
fn one1891_waterfall_ranks_by_effective_confidence_not_stored_confidence() {
    let (_dir, vault) = open_vault();
    one1891::write_prior(
        &vault,
        "provider_discounted",
        0.50,
        "evidence:audit-2026-08",
    );

    let a = one1891::candidate(&vault, 0x31, 0x41, "provider_discounted", 0.90);
    let b = one1891::candidate(&vault, 0x32, 0x42, "provider_untouched", 0.60);

    let decision = one1891::decide(&vault, &[a, b], false);

    assert_eq!(
        decision.ranked.len(),
        2,
        "every candidate is scored and reported, winner or not"
    );
    assert_eq!(
        decision.ranked[0].candidate, b,
        "effective 0.60 must out-rank effective 0.45 despite the stored 0.90"
    );
    assert!(
        one1891::close(decision.ranked[0].effective_confidence, 0.60),
        "B reads its stored confidence under a neutral prior: {}",
        decision.ranked[0].effective_confidence
    );
    assert!(
        one1891::close(decision.ranked[1].effective_confidence, 0.45),
        "A is discounted by its provider's 0.50 prior: {}",
        decision.ranked[1].effective_confidence
    );
    assert_eq!(decision.selected, Some(b.subject));
    assert!(one1891::close(
        decision
            .selected_effective_confidence
            .expect("a non-provisional route reports its score"),
        0.60
    ));
    assert_eq!(decision.route, oneiron::EntityResolutionRoute::SoftLinkLow);
    assert!(
        decision.requires_async_verification,
        "the [0.50, 0.70) band always verifies asynchronously"
    );

    // read-TIME, exactly as ONE-1722 pinned it: scoring rewrites no stored row.
    assert!(one1891::close(
        one1891::stored(&vault, &a.confidence_claim_ref),
        0.90
    ));
    assert!(one1891::close(
        one1891::stored(&vault, &b.confidence_claim_ref),
        0.60
    ));
}

/// BOTH axes stay live inside the waterfall, not just the prior: under one
/// shared prior the ranking still orders by stored confidence, and under one
/// shared stored confidence it still orders by prior. A composition that had
/// collapsed to either axis alone fails one of these two orderings.
#[test]
fn one1891_waterfall_keeps_both_confidence_axes_live() {
    let (_dir, vault) = open_vault();
    one1891::write_prior(&vault, "provider_axis_high", 0.80, "evidence:axis-high");
    one1891::write_prior(&vault, "provider_axis_low", 0.40, "evidence:axis-low");

    // Prior axis: same stored 0.90, different priors -> 0.72 vs 0.36.
    let high = one1891::candidate(&vault, 0x21, 0x22, "provider_axis_high", 0.90);
    let low = one1891::candidate(&vault, 0x23, 0x24, "provider_axis_low", 0.90);
    let by_prior = one1891::decide(&vault, &[low, high], false);
    assert_eq!(by_prior.ranked[0].candidate, high);
    assert!(one1891::close(
        by_prior.ranked[0].effective_confidence,
        0.72
    ));
    assert!(one1891::close(
        by_prior.ranked[1].effective_confidence,
        0.36
    ));

    // Claim-confidence axis: same provider/prior, different stored values.
    let strong = one1891::candidate(&vault, 0x25, 0x26, "provider_axis_high", 0.90);
    let weak = one1891::candidate(&vault, 0x27, 0x28, "provider_axis_high", 0.50);
    let by_stored = one1891::decide(&vault, &[weak, strong], false);
    assert_eq!(by_stored.ranked[0].candidate, strong);
    assert!(one1891::close(
        by_stored.ranked[0].effective_confidence,
        0.72
    ));
    assert!(one1891::close(
        by_stored.ranked[1].effective_confidence,
        0.40
    ));

    // Every stored byte is exactly what was written.
    for (claim, expected) in [
        (high.confidence_claim_ref, 0.90),
        (low.confidence_claim_ref, 0.90),
        (strong.confidence_claim_ref, 0.90),
        (weak.confidence_claim_ref, 0.50),
    ] {
        assert!(
            one1891::close(one1891::stored(&vault, &claim), expected),
            "stored confidence must survive scoring unchanged"
        );
    }
}

/// Every band and every verification flag, including the one axis a hard link
/// is allowed to care about: a high-collision mention is a confident score
/// about a surface form many referents share, so it re-arms the async check.
#[test]
fn one1891_waterfall_band_flags_pin_every_route() {
    let (_dir, vault) = open_vault();

    let hard = one1891::candidate(&vault, 0x35, 0x45, "provider_hard", 0.95);
    let hard_decision = one1891::decide(&vault, &[hard], false);
    assert_eq!(
        hard_decision.route,
        oneiron::EntityResolutionRoute::HardLink
    );
    assert!(
        !hard_decision.requires_async_verification,
        ">= 0.90 over an unambiguous mention stands on its own"
    );
    let collided = one1891::decide(&vault, &[hard], true);
    assert_eq!(collided.route, oneiron::EntityResolutionRoute::HardLink);
    assert_eq!(collided.selected, Some(hard.subject));
    assert!(
        collided.requires_async_verification,
        "a high-collision mention re-arms verification even at a hard link"
    );

    // The bands are closed below and open above, exactly at the boundaries.
    for (subject_lead, claim_lead, provider, confidence, route, async_expected) in [
        (
            0x36,
            0x46,
            "provider_edge_090",
            0.90,
            oneiron::EntityResolutionRoute::HardLink,
            false,
        ),
        (
            0x37,
            0x47,
            "provider_edge_070",
            0.70,
            oneiron::EntityResolutionRoute::SoftLink,
            true,
        ),
        (
            0x38,
            0x48,
            "provider_edge_080",
            0.80,
            oneiron::EntityResolutionRoute::SoftLink,
            true,
        ),
        (
            0x39,
            0x49,
            "provider_edge_050",
            0.50,
            oneiron::EntityResolutionRoute::SoftLinkLow,
            true,
        ),
    ] {
        let c = one1891::candidate(&vault, subject_lead, claim_lead, provider, confidence);
        let decision = one1891::decide(&vault, &[c], false);
        assert_eq!(decision.route, route, "band at {confidence}");
        assert_eq!(decision.selected, Some(c.subject), "band at {confidence}");
        assert!(
            one1891::close(
                decision.selected_effective_confidence.expect("score"),
                confidence
            ),
            "band at {confidence}"
        );
        assert_eq!(
            decision.requires_async_verification, async_expected,
            "async flag at {confidence}"
        );
    }
}

/// Below 0.50 — and with no candidates at all — the waterfall selects NOTHING,
/// verifies nothing, and MINTS nothing. Provisional entities belong to whatever
/// path creates them; this function's contract is that it does not quietly
/// become that path.
#[test]
fn one1891_provisional_route_selects_nothing_and_mints_nothing() {
    let (_dir, vault) = open_vault();
    let weak = one1891::candidate(&vault, 0x3a, 0x4a, "provider_weak", 0.40);
    let before = one1891::counts(&vault);

    let decision = one1891::decide(&vault, &[weak], false);
    assert_eq!(
        decision.route,
        oneiron::EntityResolutionRoute::ProvisionalEntity
    );
    assert_eq!(decision.selected, None);
    assert_eq!(decision.selected_effective_confidence, None);
    assert!(!decision.requires_async_verification);
    assert_eq!(
        decision.ranked.len(),
        1,
        "the candidate is still scored — it just does not win"
    );
    assert!(one1891::close(
        decision.ranked[0].effective_confidence,
        0.40
    ));

    let empty = one1891::decide(&vault, &[], false);
    assert_eq!(
        empty.route,
        oneiron::EntityResolutionRoute::ProvisionalEntity
    );
    assert_eq!(empty.selected, None);
    assert_eq!(empty.selected_effective_confidence, None);
    assert!(!empty.requires_async_verification);
    assert!(empty.ranked.is_empty());

    // Even with the collision flag raised: there is no link to verify.
    assert!(
        !one1891::decide(&vault, &[weak], true).requires_async_verification,
        "a provisional route verifies nothing"
    );

    assert_eq!(
        one1891::counts(&vault),
        before,
        "a provisional decision creates no PERSON and no CLAIM"
    );
}

/// A prior that drops the best candidate below the floor moves it out of every
/// linking band: the composition routes, not the stored column.
#[test]
fn one1891_prior_can_demote_a_candidate_into_the_provisional_route() {
    let (_dir, vault) = open_vault();
    one1891::write_prior(&vault, "provider_distrusted", 0.40, "evidence:spotcheck");
    let c = one1891::candidate(&vault, 0x3b, 0x4b, "provider_distrusted", 0.95);
    let before = one1891::counts(&vault);

    let decision = one1891::decide(&vault, &[c], false);
    assert!(one1891::close(
        decision.ranked[0].effective_confidence,
        0.38
    ));
    assert_eq!(
        decision.route,
        oneiron::EntityResolutionRoute::ProvisionalEntity,
        "a stored 0.95 from a 0.40 provider reads 0.38 and links to nothing"
    );
    assert_eq!(decision.selected, None);
    assert_eq!(one1891::counts(&vault), before);
}

/// Two devices ranking the same candidate set must agree. Ties break on
/// subject id then claim id — both total, both clock-free — so the ranking is
/// a pure function of the set and NOT of the order it was handed in.
#[test]
fn one1891_ranking_is_a_deterministic_function_of_the_candidate_set() {
    let (_dir, vault) = open_vault();
    // Three candidates at the SAME effective confidence: 0.80 stored under a
    // neutral prior, and 0.90 stored under a 0.888... prior would be fragile —
    // identical stored values under one shared provider is the exact tie.
    let first = one1891::candidate(&vault, 0x11, 0x12, "provider_tied", 0.80);
    let second = one1891::candidate(&vault, 0x13, 0x14, "provider_tied", 0.80);
    let third = one1891::candidate(&vault, 0x15, 0x16, "provider_tied", 0.80);

    let ordered = one1891::decide(&vault, &[first, second, third], false);
    let shuffled = one1891::decide(&vault, &[third, first, second], false);
    let reversed = one1891::decide(&vault, &[third, second, first], false);

    assert_eq!(
        ordered.ranked, shuffled.ranked,
        "input order must not shape the ranking"
    );
    assert_eq!(ordered.ranked, reversed.ranked);
    assert_eq!(
        ordered
            .ranked
            .iter()
            .map(|scored| scored.candidate.subject)
            .collect::<Vec<_>>(),
        vec![first.subject, second.subject, third.subject],
        "ties break on ascending subject id"
    );
    assert_eq!(ordered.selected, Some(first.subject));
    assert_eq!(shuffled.selected, Some(first.subject));
    assert_eq!(reversed.selected, Some(first.subject));
}

// ── The waterfall's own fail-closed inputs ─────────────────────────────────

/// A candidate scored by a confidence claim about SOMEBODY ELSE is refused with
/// the exact contract string, and nothing is written behind the refusal. Without
/// this, a caller could borrow an unrelated provider's confidence to hard-link
/// any subject it liked.
#[test]
fn one1891_candidate_claim_subject_mismatch_is_closed_with_no_write() {
    let (_dir, vault) = open_vault();
    let subject = one1891::put_person(&vault, 0x51);
    let other = one1891::put_person(&vault, 0x52);
    let claim = one1891::put_enrichment(&vault, 0x53, subject, "provider_mismatch", 0.95);
    let before = one1891::counts(&vault);

    let error = oneiron::evaluate_entity_resolution_waterfall(
        &vault,
        &[oneiron::EntityResolutionCandidate {
            subject: other,
            confidence_claim_ref: claim,
        }],
        false,
    )
    .expect_err("a borrowed confidence claim must not score a candidate");

    assert_eq!(
        error.to_string(),
        oneiron::Error::InvalidClaimBody(
            "waterfall candidate subject does not match confidence claim subject"
        )
        .to_string()
    );
    assert_eq!(
        one1891::counts(&vault),
        before,
        "a refused waterfall writes nothing"
    );
}

/// Closed history may not route a live mention. Rejected, proposed, superseded,
/// retracted, and stale score claims all fail with the SAME typed string — no
/// selection, no route, no write. (`Proposed` is included because
/// surfaceability, not mere existence, is the admission test: an unreviewed
/// claim must not link an identity while it waits.)
#[test]
fn one1891_unsurfaceable_score_claims_never_route_a_mention() {
    let (_dir, vault) = open_vault();
    let subject = one1891::put_person(&vault, 0x54);
    let expected =
        oneiron::Error::InvalidClaimBody("waterfall confidence claim is not active").to_string();

    for (index, label) in ["rejected", "proposed", "superseded", "retracted", "stale"]
        .into_iter()
        .enumerate()
    {
        let claim_id = one1891::fixture_id(0x60 + u8::try_from(index).expect("small index"));
        let mut body = one1891::enrichment_body(
            oneiron::ClaimSubject::Entity(subject),
            one1891::enrichment_value("provider_closed", &[]),
            0.95,
        );
        match label {
            "rejected" => body.approval = oneiron::ClaimApprovalStatus::Rejected,
            "proposed" => body.approval = oneiron::ClaimApprovalStatus::Proposed,
            "superseded" => body.lifecycle = oneiron::ClaimLifecycleStatus::Superseded,
            "retracted" => body.lifecycle = oneiron::ClaimLifecycleStatus::Retracted,
            _ => body.stale = true,
        }
        vault
            .put_claim(&claim_id, &body, one1891::at(200), 200)
            .unwrap_or_else(|error| panic!("store the {label} fixture: {error}"));

        let before = one1891::counts(&vault);
        let error = oneiron::evaluate_entity_resolution_waterfall(
            &vault,
            &[oneiron::EntityResolutionCandidate {
                subject,
                confidence_claim_ref: claim_id,
            }],
            false,
        )
        .expect_err("closed history must not route a mention");
        assert_eq!(error.to_string(), expected, "{label} fixture");
        assert_eq!(one1891::counts(&vault), before, "{label} fixture");
    }
}

/// A candidate pointing at a claim that is not provider-attributed at all — or
/// at no claim — is refused by the SAME validator the write door uses, rather
/// than being scored on whatever confidence the body happened to carry.
#[test]
fn one1891_non_enrichment_and_missing_score_claims_are_refused() {
    let (_dir, vault) = open_vault();
    let subject = one1891::put_person(&vault, 0x55);

    // A perfectly valid claim under a DIFFERENT predicate.
    let foreign = one1891::fixture_id(0x56);
    let mut body = oneiron::ClaimBody::new(
        "profile.name",
        oneiron::ClaimSubject::Entity(subject),
        rmpv::Value::from("Ada"),
        0.95,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(200);
    vault
        .put_claim(&foreign, &body, one1891::at(200), 200)
        .expect("store a non-provider claim");

    let error = oneiron::evaluate_entity_resolution_waterfall(
        &vault,
        &[oneiron::EntityResolutionCandidate {
            subject,
            confidence_claim_ref: foreign,
        }],
        false,
    )
    .expect_err("a non-enrichment claim carries no provider to score with");
    assert_eq!(
        error.to_string(),
        oneiron::Error::InvalidClaimBody("unknown provider enrichment predicate").to_string()
    );

    // And a dangling reference is EntityNotFound, never a silent 0.0.
    let missing = oneiron::evaluate_entity_resolution_waterfall(
        &vault,
        &[oneiron::EntityResolutionCandidate {
            subject,
            confidence_claim_ref: one1891::fixture_id(0x57),
        }],
        false,
    )
    .expect_err("a dangling score claim is not a zero score");
    assert_eq!(
        missing.to_string(),
        oneiron::Error::EntityNotFound.to_string()
    );
}

// ── One transaction, not one per candidate ─────────────────────────────────

/// STRUCTURAL: the waterfall opens EXACTLY ONE write transaction, around the
/// whole candidate loop.
///
/// This cannot be observed from outside — a per-candidate transaction returns
/// the same numbers — but it is the difference between one consistent snapshot
/// and N snapshots a concurrent prior write can slide between, and (given
/// `with_write_txn` takes the LMDB writer mutex first) between a scoring pass
/// and a deadlock when a caller already holds the writer.
#[test]
fn one1891_waterfall_scores_every_candidate_in_one_write_transaction() {
    let body = one1891::waterfall_body();

    assert_eq!(
        body.matches("with_write_txn").count(),
        1,
        "the waterfall must open exactly one transaction, not one per candidate"
    );
    let txn_at = body.find("with_write_txn").expect("the single transaction");
    let loop_at = body
        .find("for candidate in candidates")
        .expect("the candidate loop");
    assert!(
        txn_at < loop_at,
        "the loop must run INSIDE the transaction, not open one per iteration"
    );
    assert!(
        body.contains("effective_confidence_in_txn"),
        "scoring must compose inside the caller's transaction"
    );
    assert!(
        !body.contains("provider_confidence::effective_confidence("),
        "the transaction-opening read door would nest a writer per candidate"
    );
    assert!(
        !body.contains("body.confidence"),
        "ranking on the stored confidence is the exact bug this leg exists to \
         prevent"
    );
    assert!(
        !body.contains("read_txn"),
        "a second, separate read snapshot would defeat the single-transaction \
         guarantee"
    );
}

/// The admission door consumes the waterfall's ANSWER: the claim lands against
/// the SELECTED subject — the effective-confidence winner — not the loudest
/// stored number, and not a subject the caller picked for itself.
#[test]
fn one1891_admission_writes_against_the_waterfall_selected_subject() {
    let (_dir, vault) = one1891::open_unseeded_vault();
    one1891::write_prior(&vault, "provider_admit_discounted", 0.50, "evidence:audit");
    let loud = one1891::candidate(&vault, 0x31, 0x41, "provider_admit_discounted", 0.90);
    let winner = one1891::candidate(&vault, 0x32, 0x42, "provider_admit_plain", 0.60);

    let decision = one1891::decide(&vault, &[loud, winner], false);
    let selected = decision
        .selected
        .expect("a non-provisional decision selects a subject");
    assert_eq!(selected, winner.subject);

    let import_actor = one1891::put_person(&vault, 0x33);
    let admitted_id = one1891::fixture_id(0x43);
    oneiron::ingest::admit_imported_evidence_claim(
        &vault,
        &oneiron::ingest::NormalizedIngestClaim {
            source_record_id: "one1891-turn-1".to_owned(),
            predicate: "profile.name".to_owned(),
            value: serde_json::Value::String("Ada".to_owned()),
        },
        oneiron::ingest::ImportedEvidenceAdmission::proposed(
            oneiron::ingest::JSONL_TRANSCRIPT_SOURCE_ID,
            admitted_id,
            oneiron::ingest::ImportedEvidenceEntityResolution::subject(selected),
            oneiron::WriteActor::new(import_actor, oneiron::EdgeActorClass::Human),
            one1891::at(300),
            300,
        ),
    )
    .expect("admit against the selected subject");

    let admitted = vault
        .get_claim(&admitted_id)
        .expect("read the admitted claim")
        .expect("the admitted claim exists");
    assert_eq!(
        admitted.subject,
        oneiron::ClaimSubject::Entity(winner.subject),
        "the mention resolves to the effective-confidence winner"
    );
    assert_ne!(
        admitted.subject,
        oneiron::ClaimSubject::Entity(loud.subject),
        "the stored-confidence leader must not collect the mention"
    );
}

/// The facade's caller-asserted admit path is UNCHANGED by this wave: the
/// waterfall has no production call site yet, and the admission door still
/// takes the subject its caller resolved. Pinning it here keeps a later wave
/// from quietly turning the door into a second resolver.
#[test]
fn one1891_admission_door_stays_caller_asserted() {
    let resolution = one1891::source_slice(
        one1891::INGEST_SOURCE,
        "pub struct ImportedEvidenceEntityResolution",
        "\n/// Write metadata",
    );
    assert!(
        resolution.contains("pub subject: EntityId"),
        "the admission door still takes an already-resolved subject"
    );
    assert!(
        !resolution.contains("evaluate_entity_resolution_waterfall("),
        "the admission door must not call the waterfall itself"
    );
    let admit = one1891::source_slice(
        one1891::INGEST_SOURCE,
        "pub fn admit_imported_evidence_claim_typed",
        "\n/// Persists a normalized asset-text entity",
    );
    assert!(
        !admit.contains("evaluate_entity_resolution_waterfall"),
        "admission consumes a decision; it does not make one"
    );
    assert!(
        admit.contains("ClaimSubject::Entity(admission.entity_resolution.subject)"),
        "the admitted claim is subject-ed to exactly what the caller resolved"
    );
}

// ── The write-time validator ───────────────────────────────────────────────

/// A `provider.enrichment` claim whose attribution cannot be read is refused at
/// WRITE time, on every default-feature door, with the exact typed reason.
///
/// This is what makes the read side's `provider_from_claim_body` total: the
/// waterfall never has to decide what an unattributable enrichment claim is
/// worth, because one cannot be stored.
#[test]
fn one1891_enrichment_validator_rejects_unattributable_bodies_on_every_door() {
    let (_dir, vault) = one1891::open_unseeded_vault();
    let actor = one1891::put_person(&vault, 0xa1);
    let subject = one1891::put_person(&vault, 0xb1);
    let oversized = "p".repeat(513);
    let key_rule = "provider key must be trimmed, non-empty, and at most 512 bytes";

    let cases: [(&str, rmpv::Value, &str); 7] = [
        (
            "non-map value",
            rmpv::Value::from("clearbit"),
            "provider-attributed claim value must be a map",
        ),
        (
            "missing provider key",
            rmpv::Value::Map(vec![(rmpv::Value::from("vendor"), rmpv::Value::from("x"))]),
            "provider-attributed claim value is missing provider",
        ),
        (
            "duplicate provider keys",
            rmpv::Value::Map(vec![
                (rmpv::Value::from("provider"), rmpv::Value::from("clearbit")),
                (rmpv::Value::from("provider"), rmpv::Value::from("scraper")),
            ]),
            "provider-attributed claim value has duplicate provider keys",
        ),
        (
            "non-string provider",
            rmpv::Value::Map(vec![(
                rmpv::Value::from("provider"),
                rmpv::Value::from(7_u64),
            )]),
            "provider-attributed claim provider must be a string",
        ),
        (
            "blank provider",
            one1891::enrichment_value("", &[]),
            key_rule,
        ),
        (
            "untrimmed provider",
            one1891::enrichment_value(" clearbit ", &[]),
            key_rule,
        ),
        (
            "oversized provider",
            one1891::enrichment_value(oversized.as_str(), &[]),
            key_rule,
        ),
    ];

    let mut lead = 0x80_u8;
    for (label, value, expected) in cases {
        for door in one1891_doors::WRITE_DOORS {
            let before = one1891::counts(&vault);
            let error = one1891_doors::write_enrichment_through(
                &vault,
                door,
                lead,
                oneiron::ClaimSubject::Entity(subject),
                actor,
                value.clone(),
            )
            .expect_err("an unattributable enrichment claim must not persist");
            assert_eq!(
                error.to_string(),
                oneiron::Error::InvalidClaimBody(expected).to_string(),
                "{label} through {}",
                door.label()
            );
            assert_eq!(
                one1891::counts(&vault),
                before,
                "{label} through {} left bytes behind",
                door.label()
            );
            lead += 1;
        }
    }
}

/// The enrichment claim must be ABOUT an entity. An edge-subject claim carries
/// a provider but nothing the waterfall could ever select, so it is refused at
/// write time rather than scored and then dropped.
#[test]
fn one1891_enrichment_validator_rejects_edge_subjects_on_every_door() {
    let (_dir, vault) = one1891::open_unseeded_vault();
    let actor = one1891::put_person(&vault, 0xa2);
    let source = one1891::put_person(&vault, 0xb2);
    let target = one1891::put_person(&vault, 0xb3);
    let edge_subject = oneiron::ClaimSubject::Edge {
        source,
        kind: oneiron::EdgeKind::Mentions,
        target,
    };

    for (lead, door) in (0xc0_u8..).zip(one1891_doors::WRITE_DOORS) {
        let before = one1891::counts(&vault);
        let error = one1891_doors::write_enrichment_through(
            &vault,
            door,
            lead,
            edge_subject,
            actor,
            one1891::enrichment_value("provider_edge", &[]),
        )
        .expect_err("an edge-subject enrichment claim must not persist");
        assert_eq!(
            error.to_string(),
            oneiron::Error::InvalidClaimBody("provider enrichment subject must be an entity")
                .to_string(),
            "through {}",
            door.label()
        );
        assert_eq!(one1891::counts(&vault), before, "through {}", door.label());
    }
}

/// What the validator ACCEPTS, so "reject the malformed" cannot quietly become
/// "reject everything": the minimal one-key attribution, and the same
/// attribution carrying sibling payload keys the provider chose to ship. The
/// value round-trips byte-for-byte and scores normally.
#[test]
fn one1891_enrichment_validator_accepts_minimal_and_sibling_bearing_bodies() {
    let (_dir, vault) = one1891::open_unseeded_vault();
    let actor = one1891::put_person(&vault, 0xa3);
    let subject = one1891::put_person(&vault, 0xb4);

    let shapes = [
        ("minimal", one1891::enrichment_value("provider_accept", &[])),
        (
            "with sibling payload keys",
            one1891::enrichment_value(
                "provider_accept",
                &[("title", "Staff Engineer"), ("company", "Example")],
            ),
        ),
    ];

    let mut lead = 0xd0_u8;
    for (label, value) in shapes {
        for door in one1891_doors::WRITE_DOORS {
            one1891_doors::write_enrichment_through(
                &vault,
                door,
                lead,
                oneiron::ClaimSubject::Entity(subject),
                actor,
                value.clone(),
            )
            .unwrap_or_else(|error| {
                panic!("{label} must persist through {}: {error}", door.label())
            });
            let id = one1891::fixture_id(lead);
            let body = vault
                .get_claim(&id)
                .expect("read back")
                .expect("the accepted claim persisted");
            assert_eq!(body.value, value, "{label} round-trips unchanged");
            assert!(
                one1891::close(
                    one1891::effective(&vault, &id),
                    one1891::stored(&vault, &id)
                ),
                "{label} scores like any other enrichment claim — stored \
                 confidence under this provider's neutral prior"
            );
            lead += 1;
        }
    }
}

/// The prior validator is UNCHANGED by the new arm beside it: the same
/// acceptances, the same typed refusals, and `actor.confidence_prior` still
/// reachable only through its owning door.
#[test]
fn one1891_prior_validator_is_untouched_by_the_enrichment_arm() {
    let (_dir, vault) = open_vault();

    // Accepts, exactly as ONE-1722 armed it.
    one1891::write_prior(&vault, "provider_prior_ok", 0.65, "evidence:initial");
    assert_eq!(one1891::active_priors(&vault, "provider_prior_ok"), 1);
    assert_eq!(
        one1891::priors_with_evidence(&vault, "provider_prior_ok", "evidence:initial"),
        1
    );

    // Refuses, with the same strings.
    for (label, prior, evidence, expected) in [
        (
            "above one",
            1.5_f32,
            "evidence:x",
            "provider confidence prior must be in 0..1",
        ),
        (
            "below zero",
            -0.1,
            "evidence:x",
            "provider confidence prior must be in 0..1",
        ),
        (
            "not finite",
            f32::NAN,
            "evidence:x",
            "provider confidence prior must be in 0..1",
        ),
        (
            "bare number",
            0.5,
            "",
            "provider confidence prior evidence must be non-empty",
        ),
    ] {
        let error = oneiron::provider_confidence::write_provider_prior(
            &vault,
            "provider_prior_ok",
            prior,
            evidence,
        )
        .expect_err("the prior door stays fail-closed");
        assert_eq!(
            error.to_string(),
            oneiron::Error::InvalidClaimBody(expected).to_string(),
            "{label}"
        );
    }
    assert_eq!(
        one1891::active_priors(&vault, "provider_prior_ok"),
        1,
        "a refused prior write leaves the live head alone"
    );

    // The reserved namespace still holds: a generic claim write cannot plant a
    // trust multiplier, whatever the enrichment arm now admits next to it.
    let actor = one1891::put_provider_actor(&vault, 0xe1, "provider_prior_ok");
    let mut body = oneiron::ClaimBody::new(
        "actor.confidence_prior",
        oneiron::ClaimSubject::Entity(actor),
        rmpv::Value::F32(1.0),
        1.0,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(200);
    let error = vault
        .put_claim(&one1891::fixture_id(0xe2), &body, one1891::at(200), 200)
        .expect_err("actor.* is reserved");
    assert!(
        matches!(&error, oneiron::Error::ReservedPredicate { .. }),
        "expected a reserved-predicate refusal, got {error}"
    );
}

/// STRUCTURAL: the enrichment arm sits exactly between the prior arm and the
/// `actor_claims` arm, and every neighbour arm below it survives the
/// insertion in its original order.
///
/// The chokepoint is one long `else if` chain, so an arm inserted in the wrong
/// place does not fail loudly — it silently shadows or is shadowed. Order IS
/// the semantics here.
#[test]
fn one1891_enrichment_arm_is_seated_without_disturbing_its_neighbours() {
    let chain = one1891::source_slice(
        one1891::CLAIM_CORE_TYPES_SOURCE,
        "pub(crate) fn validate_claim_body_and_decode(",
        "\npub(crate) fn validate_claim_body_bytes",
    );

    let prior_arm = chain
        .find("is_actor_confidence_prior_claim_predicate")
        .expect("the ONE-1722 prior arm");
    let enrichment_arm = chain
        .find("is_provider_enrichment_claim_predicate")
        .expect("the ONE-1891 enrichment arm");
    let actor_arm = chain
        .find("actor_claims::is_actor_claim_predicate")
        .expect("the actor-claims arm");
    assert!(
        prior_arm < enrichment_arm && enrichment_arm < actor_arm,
        "the enrichment arm belongs between the prior arm and actor_claims"
    );
    assert_eq!(
        chain
            .matches("is_provider_enrichment_claim_predicate")
            .count(),
        1,
        "a second enrichment arm would be unreachable and untested"
    );
    assert!(
        chain.contains("validate_provider_enrichment_claim_structure(&body)?"),
        "the arm must call the validator, not merely recognise the predicate"
    );

    // Every neighbour that used to follow still follows, in order.
    let mut cursor = enrichment_arm;
    for neighbour in [
        "actor_claims::is_actor_claim_predicate",
        "counterparty_contact::is_counterparty_contact_claim_predicate",
        "commitment::is_commitment_claim_predicate",
        "calendar::claims::is_calendar_claim_predicate",
        "campaign::claims::is_campaign_pack_claim_predicate",
        "comm::is_comm_claim_predicate",
        "disclosure::is_disclosure_claim_predicate",
        "delivery_window::is_delivery_window_claim_predicate",
        "booking::config::is_booking_claim_predicate",
        "voice_segment::is_voice_segment_claim_predicate",
    ] {
        let at = chain
            .find(neighbour)
            .unwrap_or_else(|| panic!("neighbour arm lost: {neighbour}"));
        assert!(at > cursor, "neighbour arm reordered: {neighbour}");
        cursor = at;
    }
}

/// STRUCTURAL: `put_replicated` is not a fourth write door. Both definitions
/// are `pub(crate)` and feature-gated, so the three doors exercised above are
/// the whole default-feature write surface for an enrichment claim — and a
/// replicated body still meets the same validator inside `apply_put`, so this
/// is a statement about REACH, not about a bypass.
#[test]
fn one1891_put_replicated_is_not_a_fourth_write_door() {
    for (label, source) in [
        ("txn_builder", one1891::BATCH_TXN_BUILDER_SOURCE),
        ("builder", one1891::BATCH_BUILDER_SOURCE),
    ] {
        assert!(
            !source.contains("pub fn put_replicated"),
            "{label}: put_replicated must never become public"
        );
        let Some(door_at) = source.find("fn put_replicated") else {
            continue;
        };
        assert!(
            source.contains("pub(crate) fn put_replicated"),
            "{label}: the replay door must stay crate-private"
        );
        // The gate must sit on the door ITSELF, not merely somewhere in the
        // file: nothing but the visibility keyword may separate them.
        let gate_at = source[..door_at]
            .rfind("#[cfg(")
            .expect("a feature gate above the replay door");
        assert!(
            !source[gate_at..door_at].contains("fn "),
            "{label}: the feature gate must sit on the replay door itself"
        );
    }
}

// ── The two DISPOSABLE shortcut rows ───────────────────────────────────────

/// The shortcut rows are a cache over one truth, so deleting them may change
/// COST and nothing else. The first touch after a clear is a COUNT — taken
/// before any read could have rebuilt anything — and it is already correct.
#[test]
fn one1891_cleared_indexes_answer_from_truth_before_any_rebuild() {
    let (_dir, vault) = open_vault();
    let provider = "provider_rebuild";
    one1891::write_prior(&vault, provider, 0.50, "evidence:rebuild");
    let subject = one1891::put_person(&vault, 0x71);
    let claim = one1891::put_enrichment(&vault, 0x72, subject, provider, 0.60);

    let composed = one1891::effective(&vault, &claim);
    assert!(one1891::close(composed, 0.30));
    assert_eq!(one1891::index_presence(&vault, provider), (true, true));
    let before = one1891::counts(&vault);

    one1891::clear_indexes(&vault, provider);
    assert_eq!(
        one1891::index_presence(&vault, provider),
        (false, false),
        "the clear must actually remove both rows"
    );

    // FIRST touch after the clear, with nothing in between: the counts come
    // from the full scan and are already right.
    assert_eq!(one1891::active_priors(&vault, provider), 1);
    assert_eq!(one1891::superseded_priors(&vault, provider), 0);
    assert_eq!(
        one1891::priors_with_evidence(&vault, provider, "evidence:rebuild"),
        1
    );
    assert_eq!(
        one1891::index_presence(&vault, provider),
        (true, false),
        "resolving the actor repairs the actor row and nothing else — the \
         prior-head row is rebuilt by the read that needs it"
    );

    assert!(
        one1891::close(one1891::effective(&vault, &claim), composed),
        "the composed read is identical before and after the cache was lost"
    );
    assert_eq!(one1891::counts(&vault), before, "a rebuild mints nothing");
}

/// An upgraded vault has never written these rows. The first read rebuilds
/// EXACTLY the two of them — no migration, no startup pass, no bulk sweep —
/// and answers exactly what the pre-clear read answered.
#[test]
fn one1891_upgraded_vault_rebuilds_exactly_two_rows_on_first_read() {
    let (_dir, vault) = open_vault();
    let provider = "provider_upgrade";
    one1891::write_prior(&vault, provider, 0.80, "evidence:upgrade");
    let subject = one1891::put_person(&vault, 0x73);
    let claim = one1891::put_enrichment(&vault, 0x74, subject, provider, 0.50);
    let before_read = one1891::effective(&vault, &claim);

    one1891::clear_indexes(&vault, provider);
    assert_eq!(one1891::index_presence(&vault, provider), (false, false));
    let before = one1891::counts(&vault);

    assert!(
        one1891::close(one1891::effective(&vault, &claim), before_read),
        "a cold index answers exactly what a warm one did"
    );
    assert_eq!(
        one1891::index_presence(&vault, provider),
        (true, true),
        "exactly the two rows reappear"
    );
    assert_eq!(
        one1891::counts(&vault),
        before,
        "no PERSON and no CLAIM is created by a lazy rebuild"
    );
}

/// Reading one provider rebuilds ONE provider's rows. There is no bulk pass
/// hiding behind the lazy one.
#[test]
fn one1891_reading_one_provider_never_builds_another_providers_rows() {
    let (_dir, vault) = open_vault();
    one1891::write_prior(&vault, "provider_read", 0.50, "evidence:read");
    // Truth for a second provider exists and is never asked about.
    one1891::put_provider_actor(&vault, 0x75, "provider_unread");
    let subject = one1891::put_person(&vault, 0x76);
    let claim = one1891::put_enrichment(&vault, 0x77, subject, "provider_read", 0.80);
    one1891::clear_indexes(&vault, "provider_read");

    assert!(one1891::close(one1891::effective(&vault, &claim), 0.40));
    assert_eq!(
        one1891::index_presence(&vault, "provider_read"),
        (true, true)
    );
    assert_eq!(
        one1891::index_presence(&vault, "provider_unread"),
        (false, false),
        "an unrelated provider's rows must not be built by someone else's read"
    );
}

/// A provider with no prior reads NEUTRAL — the stored confidence, unchanged —
/// and the miss is never cached. A negative/absence sentinel would be a second
/// thing that can go stale, invalidated by exactly the writes it exists to
/// avoid reading.
#[test]
fn one1891_absent_prior_reads_neutral_and_caches_no_absence() {
    let (_dir, vault) = open_vault();
    let provider = "provider_neutral";
    let subject = one1891::put_person(&vault, 0x78);
    let claim = one1891::put_enrichment(&vault, 0x79, subject, provider, 0.70);

    assert_eq!(one1891::index_presence(&vault, provider), (false, false));
    assert!(
        one1891::close(one1891::effective(&vault, &claim), 0.70),
        "no prior means the neutral 1.0, i.e. the stored confidence"
    );
    assert_eq!(
        one1891::index_presence(&vault, provider),
        (false, false),
        "absence is not cached"
    );
    assert_eq!(one1891::active_priors(&vault, provider), 0);
    assert_eq!(
        one1891::index_presence(&vault, provider),
        (false, false),
        "counting an unknown provider caches nothing either"
    );
    assert!(one1891::close(one1891::effective(&vault, &claim), 0.70));

    // A prior learned LATER lands on the very next read: nothing was cached
    // that would have to be invalidated first.
    one1891::write_prior(&vault, provider, 0.50, "evidence:learned-later");
    assert!(
        one1891::close(one1891::effective(&vault, &claim), 0.35),
        "0.70 stored x the newly learned 0.50 prior"
    );
    assert_eq!(
        one1891::index_presence(&vault, provider),
        (true, true),
        "the prior write seats both shortcut rows"
    );
    assert!(
        one1891::close(one1891::stored(&vault, &claim), 0.70),
        "learning a prior never rewrites the stored column"
    );
}

/// The provider whose shortcut rows the stale matrix corrupts.
const ONE1891_STALE_PROVIDER: &str = "provider_stale";

/// Everything a shortcut row could wrongly name, in one vault.
struct One1891StaleFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    /// The real provider actor: an active PERSON carrying the key.
    actor: oneiron::EntityId,
    /// The enrichment claim under test (stored 0.80, prior 0.50 -> 0.40).
    claim: oneiron::EntityId,
    /// A prior that was superseded and is no longer a head.
    superseded_prior: oneiron::EntityId,
    /// An active actor and prior belonging to a DIFFERENT provider.
    foreign_actor: oneiron::EntityId,
    foreign_prior: oneiron::EntityId,
    /// A former actor for this same provider, merged away into a survivor.
    shell: oneiron::EntityId,
}

fn one1891_stale_fixture() -> One1891StaleFixture {
    let (dir, vault) = open_vault();
    let provider = ONE1891_STALE_PROVIDER;

    let actor = one1891::put_provider_actor(&vault, 0x81, provider);
    let superseded_prior = one1891::write_prior(&vault, provider, 0.40, "evidence:first");
    one1891::write_prior(&vault, provider, 0.50, "evidence:second");

    // A twin actor for the same provider, then merged away — the exact
    // ARCH-0035 reconciliation, leaving a redirect shell that still carries
    // the provider key in its body.
    let shell = one1891::put_provider_actor(&vault, 0x82, provider);
    let survivor = one1891::put_person(&vault, 0x83);
    vault
        .apply_identity_topology_op(
            &oneiron::identity_topology::IdentityTopologyOp::Merge(
                oneiron::identity_topology::MergeOp {
                    sources: vec![shell],
                    survivor,
                    evidence: oneiron::identity_topology::IdentityOpEvidence {
                        refs: Vec::new(),
                        rationale: "one1891 stale-index fixture merge".to_owned(),
                    },
                    survivorship_plan: oneiron::identity_topology::SurvivorshipPlan::ReadThrough,
                },
            ),
            &oneiron::identity_topology::IdentityOpWrite::auto(oneiron::ClaimSource::Inferred),
            400,
        )
        .expect("apply the fixture merge");
    assert_ne!(
        vault
            .entity_lifecycle_state(&shell)
            .expect("shell lifecycle"),
        oneiron::identity_topology::EntityLifecycleState::Active,
        "the fixture shell must really be a redirect shell"
    );

    let foreign_actor = one1891::put_provider_actor(&vault, 0x84, "provider_stale_other");
    let foreign_prior =
        one1891::write_prior(&vault, "provider_stale_other", 0.10, "evidence:other");

    let subject = one1891::put_person(&vault, 0x85);
    let claim = one1891::put_enrichment(&vault, 0x86, subject, provider, 0.80);

    One1891StaleFixture {
        _dir: dir,
        vault,
        actor,
        claim,
        superseded_prior,
        foreign_actor,
        foreign_prior,
        shell,
    }
}

/// NO FALSE ABSENCE. Whatever the two shortcut rows are made to say — nothing,
/// nonsense, the wrong entity type, another provider's actor and prior, a
/// superseded head, or a merged-away redirect shell — the composed read is the
/// same number truth supports, no actor is minted to paper over it, and the
/// rows come back valid.
///
/// A cache that could turn a stray byte into "this provider has no prior" would
/// silently promote every one of that provider's claims to the neutral 1.0,
/// which is the most dangerous direction this module can fail in.
#[test]
fn one1891_stale_index_rows_never_produce_a_false_absence() {
    type StaleIndexCase<'a> = (&'a str, Option<&'a [u8]>, Option<&'a [u8]>);

    let fixture = one1891_stale_fixture();
    let vault = &fixture.vault;
    let provider = ONE1891_STALE_PROVIDER;
    let malformed_short: &[u8] = &[0x01, 0x02];
    let malformed_long: &[u8] = &[0xff; 24];

    let cases: [StaleIndexCase<'_>; 6] = [
        ("both rows absent", None, None),
        (
            "malformed row lengths",
            Some(malformed_short),
            Some(malformed_long),
        ),
        (
            "rows name the wrong entity types",
            Some(fixture.claim.as_bytes()),
            Some(fixture.actor.as_bytes()),
        ),
        (
            "rows name another provider's actor and prior",
            Some(fixture.foreign_actor.as_bytes()),
            Some(fixture.foreign_prior.as_bytes()),
        ),
        (
            "head row names a superseded prior",
            Some(fixture.actor.as_bytes()),
            Some(fixture.superseded_prior.as_bytes()),
        ),
        (
            "rows name a merged-away redirect shell",
            Some(fixture.shell.as_bytes()),
            Some(fixture.shell.as_bytes()),
        ),
    ];

    for (label, actor_row, head_row) in cases {
        one1891::set_indexes(vault, provider, actor_row, head_row);
        let before = one1891::counts(vault);

        let composed = one1891::effective(vault, &fixture.claim);
        assert!(
            one1891::close(composed, 0.40),
            "{label}: expected the truth-supported 0.40, got {composed}"
        );
        assert_eq!(
            one1891::counts(vault),
            before,
            "{label}: a stale row must not mint a second actor"
        );
        assert_eq!(
            one1891::index_presence(vault, provider),
            (true, true),
            "{label}: both rows are repaired by the read that noticed"
        );
        assert_eq!(
            one1891::active_priors(vault, provider),
            1,
            "{label}: the actor row was repaired to the live actor"
        );
        assert_eq!(
            one1891::superseded_priors(vault, provider),
            1,
            "{label}: history stays free and stays visible"
        );
        // Repairing one provider's rows never disturbs its neighbour's truth.
        assert_eq!(
            one1891::active_priors(vault, "provider_stale_other"),
            1,
            "{label}: the neighbouring provider keeps its own live prior"
        );
    }
}

/// Two twins for one provider, and the prior living on the LARGER-id twin.
/// The composed read sweeps every twin, so the prior is found; the actor
/// shortcut is repaired to the lexicographically SMALLEST twin, because
/// "smallest" is a pure function of the set that two devices can agree on
/// without consulting a clock either of them owns.
///
/// The asymmetry that pins which twin the row names is deliberate and is the
/// documented ARCH-0035 bound: the actor-scoped COUNTS follow the shortcut,
/// while the composed read sweeps every actor carrying the key. A twin is a
/// forked belief history; the fix is a merge, not a wider count.
#[test]
fn one1891_cross_actor_priors_resolve_deterministically() {
    let outcomes = std::iter::repeat_with(one1891_cross_actor_outcome)
        .take(2)
        .collect::<Vec<_>>();
    assert!(
        one1891::close(outcomes[0].0, 0.24),
        "0.80 stored x 0.30 prior found on the other twin: {}",
        outcomes[0].0
    );
    assert_eq!(
        outcomes[0], outcomes[1],
        "two identically-built vaults must agree exactly"
    );
}

/// Builds the twin fixture and returns
/// `(effective confidence, actor-scoped active priors, index presence)`.
fn one1891_cross_actor_outcome() -> (f32, usize, (bool, bool)) {
    let (_dir, vault) = open_vault();
    let provider = "provider_twins";

    // The FAR twin is minted first, so it is the one the prior lands on.
    one1891::put_provider_actor(&vault, 0x22, provider);
    one1891::write_prior(&vault, provider, 0.30, "evidence:far-twin");
    assert_eq!(
        one1891::active_priors(&vault, provider),
        1,
        "before the twin appears, the counts see the only actor there is"
    );

    // The NEAR twin appears later — a sync from another device, an extraction
    // that did not recognise the existing actor — and is lexicographically
    // smaller.
    one1891::put_provider_actor(&vault, 0x11, provider);
    let subject = one1891::put_person(&vault, 0x23);
    let claim = one1891::put_enrichment(&vault, 0x24, subject, provider, 0.80);

    // The cross-actor head is discovered on the next stale/miss, exactly as
    // the module's staleness bound promises.
    one1891::clear_indexes(&vault, provider);
    let before = one1891::counts(&vault);
    let composed = one1891::effective(&vault, &claim);
    assert_eq!(
        one1891::counts(&vault),
        before,
        "discovering a twin's prior mints nothing"
    );
    assert!(
        one1891::close(one1891::effective(&vault, &claim), composed),
        "the second read agrees with the first"
    );

    (
        composed,
        one1891::active_priors(&vault, provider),
        one1891::index_presence(&vault, provider),
    )
}

/// A prior written LOCALLY after a twin's becomes the cached head, and the
/// twin's claim is kept rather than overwritten: the shortcut is a pointer into
/// history, never a replacement for it.
#[test]
fn one1891_a_later_local_prior_becomes_the_cached_head() {
    let (_dir, vault) = open_vault();
    let provider = "provider_twins_later";

    one1891::put_provider_actor(&vault, 0x2a, provider);
    one1891::write_prior(&vault, provider, 0.30, "evidence:far-twin");
    one1891::put_provider_actor(&vault, 0x1a, provider);
    let subject = one1891::put_person(&vault, 0x2b);
    let claim = one1891::put_enrichment(&vault, 0x2c, subject, provider, 0.80);

    one1891::clear_indexes(&vault, provider);
    assert!(
        one1891::close(one1891::effective(&vault, &claim), 0.24),
        "0.80 stored x the twin's 0.30 — all truth has to offer so far"
    );

    // That read repaired the actor row to the SMALLEST active twin, so the
    // local write lands there and seats its own claim as the head in the same
    // transaction.
    let before = one1891::counts(&vault);
    one1891::write_prior(&vault, provider, 0.60, "evidence:local");
    assert!(
        one1891::close(one1891::effective(&vault, &claim), 0.48),
        "0.80 stored x the local 0.60 head"
    );
    assert_eq!(
        one1891::active_priors(&vault, provider),
        1,
        "the shortcut actor carries exactly its own new head"
    );
    assert_eq!(
        one1891::counts(&vault),
        (before.0, before.1 + 1),
        "history is appended to: no actor minted, no earlier prior removed"
    );
}

/// STRUCTURAL: a structurally invalid CLAIM under the exact prior predicate is
/// a TYPED ERROR, never a silent neutral.
///
/// `1.0` is a load-bearing trust multiplier, so "this vault holds a prior we
/// cannot read" must not be reported as "this provider is fully trusted". The
/// state is unreachable through any default-feature door — the write chokepoint
/// validates `actor.confidence_prior` bodies, and `write_provider_prior` is the
/// only local writer of that predicate — so the guarantee is pinned where it
/// lives: in the code that would have to skip the claim to lose it.
#[test]
fn one1891_an_unreadable_prior_raises_instead_of_reading_neutral() {
    let scan = one1891::source_slice(
        one1891::PROVIDER_CONFIDENCE_SOURCE,
        "fn active_priors_for_actor_in_txn",
        "\n/// The newest active prior",
    );
    assert!(
        scan.contains("validate_actor_confidence_prior_claim_structure(&body)?;"),
        "a matching prior must be structurally validated, not assumed"
    );
    assert!(
        scan.contains("\"active provider confidence prior must be in 0..1\""),
        "an out-of-range prior value must raise its own typed reason"
    );
    assert!(
        scan.contains(".ok_or(Error::InvalidClaimBody("),
        "the unit-interval read must raise, never default"
    );
    for forbidden in [
        "unwrap_or(1.0)",
        "unwrap_or_default()",
        ".ok();",
        "is_err()",
    ] {
        assert!(
            !scan.contains(forbidden),
            "a broken prior must not be swallowed by `{forbidden}`"
        );
    }

    // The reachability argument the assertion above stands on.
    let chain = one1891::source_slice(
        one1891::CLAIM_CORE_TYPES_SOURCE,
        "pub(crate) fn validate_claim_body_and_decode(",
        "\npub(crate) fn validate_claim_body_bytes",
    );
    assert!(
        chain.contains("validate_actor_confidence_prior_claim_structure(&body)?"),
        "the write chokepoint validates prior bodies, which is why the read \
         path's raise is a belt-and-braces guarantee rather than a live branch"
    );
    assert_eq!(
        one1891::PROVIDER_CONFIDENCE_SOURCE
            .matches("PREDICATE_ACTOR_CONFIDENCE_PRIOR,")
            .count(),
        1,
        "exactly one writer may mint an actor.confidence_prior claim"
    );
}
