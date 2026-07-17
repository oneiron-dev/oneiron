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
    ConnectorKeyRecord, ConnectorKeyStatus, EffectorBudget, EffectorBudgetDimension,
    EffectorBudgetOnExhaust, EffectorBudgetWindow, HnswConfig, Vault, VaultConfig,
};

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = Some("test-model-v1".to_owned());
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
    oneiron::record_comm_inbound_stop(&vault, "party-seed-proof", "email", 10).unwrap();
    // Seeded: the projector's Auto comm.opt_out CLAIM write is floored by the
    // default gate, so the pass returns an error instead of a live standing head.
    assert!(
        oneiron::run_comm_projector(&vault).is_err(),
        "production Vault::open must seed the default policy gate"
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
            .memory_facade(actor, oneiron::EdgeActorClass::Human)
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
                &oneiron::GrantMintIntent {
                    principal_ref: actor.to_hex(),
                    origin_component_id: "effect_spine_oracle".to_owned(),
                    origin_action_id: "execute_connector_send".to_owned(),
                    origin_receipt_ref: None,
                    scope: oneiron::GrantMintIntentScope::Channel {
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
        impl oneiron::OutboundExecutionSink for OracleSendSink {
            fn execute(
                &mut self,
                _request: &oneiron::OutboundExecutionRequest<'_>,
            ) -> oneiron::OutboundExecutionOutcome {
                let count = ORACLE_SEND_INVOCATIONS.get();
                ORACLE_SEND_INVOCATIONS.set(count.saturating_add(1));
                oneiron::OutboundExecutionOutcome::delivered_to_channel("oracle:wire-send")
            }
        }
        vault
            .run_connector_task_executor(&mut OracleSendSink, 101)
            .expect("execute connector-send tasks")
    }

    /// Send receipts recorded for executed connector tasks.
    pub(crate) fn count_send_receipts(vault: &Vault) -> usize {
        vault
            .receipts(oneiron::ReceiptQuery::new(100).with_kind(oneiron::ReceiptKind::Outbound))
            .expect("query send receipts")
            .len()
    }

    /// Send receipts that carry lineage back to their originating TASK.
    pub(crate) fn count_send_receipts_with_task_lineage(vault: &Vault) -> usize {
        vault
            .receipts(oneiron::ReceiptQuery::new(100).with_kind(oneiron::ReceiptKind::Outbound))
            .expect("query send receipts")
            .into_iter()
            .filter(|receipt| {
                receipt
                    .fields
                    .get(oneiron::FIELD_TASK_REF)
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
        oneiron::record_comm_send_receipt(vault, party, channel, comm_now()).unwrap();
    }

    /// Records an inbound STOP surface event from `party` on `channel`.
    pub(crate) fn record_inbound_stop(vault: &Vault, party: &str, channel: &str) {
        oneiron::record_comm_inbound_stop(vault, party, channel, comm_now()).unwrap();
    }

    /// Records a thread join/leave event for `party` in `thread`.
    pub(crate) fn record_thread_event(vault: &Vault, thread: &str, party: &str, joined: bool) {
        oneiron::record_comm_thread_event(vault, thread, party, joined, comm_now()).unwrap();
    }

    /// Runs the ARCH-0035 declarative projector pass over pending events.
    pub(crate) fn run_comm_projector(vault: &Vault) {
        oneiron::run_comm_projector(vault).unwrap();
    }

    /// ACTIVE claims counted by the FULL §3 conflict key
    /// (predicate, party, channel_class) — never party-only.
    pub(crate) fn count_active_comm_claims(
        vault: &Vault,
        predicate: &str,
        party: &str,
        channel_class: &str,
    ) -> usize {
        oneiron::count_active_comm_claims(vault, predicate, party, channel_class).unwrap()
    }

    /// TOTAL claim rows (active + superseded) for the same full conflict
    /// key — replay idempotence must hold on totals, not just actives.
    pub(crate) fn count_total_comm_claim_rows(
        vault: &Vault,
        predicate: &str,
        party: &str,
        channel_class: &str,
    ) -> usize {
        oneiron::count_total_comm_claim_rows(vault, predicate, party, channel_class).unwrap()
    }

    /// ACTIVE `comm.thread_member` claims for the §3 (thread, party) key.
    pub(crate) fn count_active_thread_member_claims(
        vault: &Vault,
        thread: &str,
        party: &str,
    ) -> usize {
        oneiron::count_active_thread_member_claims(vault, thread, party).unwrap()
    }

    /// Pending human-gate rows for comm consent transitions.
    pub(crate) fn count_pending_comm_consent_gates(vault: &Vault) -> usize {
        oneiron::count_pending_comm_consent_gates(vault).unwrap()
    }

    /// Asks to clear (widen) `comm.opt_out` for (party, channel).
    pub(crate) fn request_opt_out_clear(
        vault: &Vault,
        party: &str,
        channel: &str,
    ) -> ClearOptOutOutcome {
        match oneiron::request_opt_out_clear(vault, party, channel, comm_now()).unwrap() {
            oneiron::CommClearOptOutOutcome::PendingHumanRuling => {
                ClearOptOutOutcome::PendingHumanRuling
            }
        }
    }

    /// Applies the human ruling approving a pending opt-out clear.
    pub(crate) fn approve_pending_opt_out_clear(vault: &Vault, party: &str, channel: &str) {
        let actor_ref = oneiron::resolve_or_create_comm_party(vault, party).unwrap();
        let actor = oneiron::WriteActor::new(actor_ref, oneiron::EdgeActorClass::Human);
        oneiron::approve_pending_opt_out_clear(vault, party, channel, actor, comm_now()).unwrap();
    }

    /// An AGENT principal attempts to approve the pending clear — §4 gates
    /// are human-gated, so this must be refused with no state change.
    pub(crate) fn attempt_agent_opt_out_clear_approval(vault: &Vault, party: &str, channel: &str) {
        let actor_ref = oneiron::resolve_or_create_comm_party(vault, party).unwrap();
        let actor = oneiron::WriteActor::new(actor_ref, oneiron::EdgeActorClass::Agent);
        let error =
            oneiron::approve_pending_opt_out_clear(vault, party, channel, actor, comm_now())
                .expect_err("agent principal must be refused");
        assert!(matches!(error, oneiron::CommError::HumanApprovalRequired));
    }

    /// Receipts recorded for consent-widening rulings.
    pub(crate) fn count_opt_out_clear_receipts(vault: &Vault, party: &str) -> usize {
        oneiron::count_opt_out_clear_receipts(vault, party).unwrap()
    }

    /// Canonical serialized bytes of the CID-7 contact record for `party`.
    pub(crate) fn materialize_contact_record(vault: &Vault, party: &str) -> Vec<u8> {
        oneiron::materialize_contact_record(vault, party).unwrap()
    }

    /// Drops the cached contact record for `party` (cache, not truth).
    pub(crate) fn drop_contact_record(vault: &Vault, party: &str) {
        oneiron::drop_contact_record(vault, party).unwrap();
    }

    /// Claim-derived entries materialized in the CID-7 record for `party` —
    /// a constant/no-op materializer must not be able to satisfy REPAIR.
    pub(crate) fn count_contact_record_claim_entries(vault: &Vault, party: &str) -> usize {
        oneiron::count_contact_record_claim_entries(vault, party).unwrap()
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
    pub(crate) fn dispatch_peer_consults(vault: &Vault, peer: &str, count: u64) -> DispatchTally {
        let (id, _) = peer_key(vault, peer);
        let now = PEER_BUDGET_NOW.with(Cell::get);
        let tally = vault
            .admit_connector_key_dispatches(&id, "peer", count, now)
            .unwrap();
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
    /// windows free up (test clock seam).
    pub(crate) fn advance_budget_window(_vault: &Vault, _peer: &str) {
        PEER_BUDGET_NOW.with(|now| now.set(now.get().saturating_add(3_600)));
    }

    // ---- ONE-1722 (ES-09): read-time confidence for provider priors ----

    /// Writes `actor.confidence_prior = prior` as a claim on the provider
    /// actor, carrying `evidence` provenance (evidence-carrying, superseding
    /// — doc 13 §7).
    pub(crate) fn write_provider_prior(
        _vault: &Vault,
        _provider: &str,
        _prior: f32,
        _evidence: &str,
    ) {
        unimplemented!("armed by ONE-1722: actor.confidence_prior claim write")
    }

    /// Writes one enrichment claim from `provider` with stored `confidence`;
    /// returns the claim ref.
    pub(crate) fn write_enrichment_claim(
        _vault: &Vault,
        _provider: &str,
        _confidence: f32,
    ) -> String {
        unimplemented!("armed by ONE-1722: provider enrichment claim write")
    }

    /// Read-time confidence: f(claim confidence, actor.confidence_prior).
    pub(crate) fn effective_confidence(_vault: &Vault, _claim_ref: &str) -> f32 {
        unimplemented!("armed by ONE-1722: read-time confidence wiring")
    }

    /// Stored (unmodified) claim confidence — read-time wiring must never
    /// rewrite the claim row.
    pub(crate) fn stored_confidence(_vault: &Vault, _claim_ref: &str) -> f32 {
        unimplemented!("armed by ONE-1722: stored confidence read")
    }

    /// ACTIVE `actor.confidence_prior` claims for the provider actor.
    pub(crate) fn count_active_prior_claims(_vault: &Vault, _provider: &str) -> usize {
        unimplemented!("armed by ONE-1722: count active prior claims")
    }

    /// SUPERSEDED `actor.confidence_prior` claims (history stays free).
    pub(crate) fn count_superseded_prior_claims(_vault: &Vault, _provider: &str) -> usize {
        unimplemented!("armed by ONE-1722: count superseded prior claims")
    }

    /// ACTIVE `actor.confidence_prior` claims carrying exactly `evidence` —
    /// §7 priors are evidence-attached, never bare numbers.
    pub(crate) fn count_active_prior_claims_with_evidence(
        _vault: &Vault,
        _provider: &str,
        _evidence: &str,
    ) -> usize {
        unimplemented!("armed by ONE-1722: count evidence-attached prior claims")
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
#[ignore = "armed by ONE-1722"]
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
#[ignore = "armed by ONE-1722"]
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
