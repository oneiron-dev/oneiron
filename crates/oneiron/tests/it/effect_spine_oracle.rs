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

use oneiron::{HnswConfig, Vault, VaultConfig};

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
    seam::reset_fan_out_oracle();
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
            Err(oneiron::comm::CommError::Engine(oneiron::Error::Gate(
                oneiron::error::GateError::GateWriteRejected { .. }
            )))
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
#[allow(dead_code)] // contract vocabulary; arming tickets construct the rest
enum DecisionHistoryEntry {
    HumanApproved { preset: &'static str, cap: u64 },
}

/// Thinnest plausible seams for the downstream ES tickets. Each stub names
/// the ticket that must replace it with the real engine API.
#[allow(dead_code)]
mod seam {
    use std::cell::Cell;

    use super::{ClearOptOutOutcome, Vault};

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

    /// Records an inbound STOP surface event from `party` on `channel`.
    pub(crate) fn record_inbound_stop(vault: &Vault, party: &str, channel: &str) {
        oneiron::comm::record_comm_inbound_stop(vault, party, channel, comm_now()).unwrap();
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

    use oneiron::edit_distance::escalation::{EscalationTrigger, standing_policy_for};
    use oneiron::receipt::{ReceiptKind, ReceiptQuery};
    use oneiron::task_verb::{
        ConsultFanOutChoice, ConsultFanOutReceipt, ConsultFanOutSpec, ConsultPayloadRef,
    };
    use std::cell::RefCell;

    #[derive(Clone)]
    struct OraclePlan {
        input: ConsultFanOutSpec,
        preset: String,
        receipt: Option<ConsultFanOutReceipt>,
        surfaced: bool,
        /// Snapshot before admission, after any real history fixture was added.
        owned_tasks_before: usize,
        /// Catches even an incorrectly owned TASK during estimate-only calls.
        all_tasks_before: u64,
    }
    thread_local! {
        static FAN_OUT_PLANS: RefCell<Vec<OraclePlan>> = const { RefCell::new(Vec::new()) };
    }
    pub(crate) fn reset_fan_out_oracle() {
        FAN_OUT_PLANS.with(|plans| plans.borrow_mut().clear());
    }
    fn id(seed: u8) -> oneiron::EntityId {
        oneiron::EntityId::from_bytes([seed; 16]).expect("oracle actor id")
    }
    fn actor() -> oneiron::EntityId {
        id(0xE1)
    }
    fn owner(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
        let owner = id(0xF0);
        put_person(vault, owner);
        vault
            .authenticate_owner(
                owner,
                &owner.to_hex(),
                true,
                oneiron::store::GateDecisionId::now(),
            )
            .expect("authenticated owner")
    }
    fn put_person(vault: &Vault, person: oneiron::EntityId) {
        if vault
            .get_entity_type(&person)
            .expect("read person")
            .is_none()
        {
            vault
                .put_entity(
                    &person,
                    oneiron::registry::ENTITY_TYPE_PERSON,
                    oneiron::temporal::TimeRange {
                        start: 100,
                        end: 100,
                    },
                    100,
                    b"oracle actor",
                )
                .expect("put person");
        }
    }
    fn question(vault: &Vault) -> ConsultPayloadRef {
        let turn = id(0x7A);
        if vault
            .get_entity_type(&turn)
            .expect("read question")
            .is_none()
        {
            let mut body = Vec::new();
            rmpv::encode::write_value(
                &mut body,
                &rmpv::Value::Map(vec![(
                    rmpv::Value::from("role"),
                    rmpv::Value::from("question"),
                )]),
            )
            .expect("encode question");
            vault
                .put_entity(
                    &turn,
                    oneiron::registry::ENTITY_TYPE_TURN,
                    oneiron::temporal::TimeRange {
                        start: 100,
                        end: 100,
                    },
                    100,
                    &body,
                )
                .expect("put question");
        }
        ConsultPayloadRef::parse(vault, &format!("tn_{}", turn.to_hex())).unwrap()
    }
    fn peer_id(peer: &str) -> oneiron::EntityId {
        match peer {
            "codex" => id(0xE2),
            "cc-2" => id(0xE3),
            _ => panic!("unknown oracle peer: {peer}"),
        }
    }
    fn owned_task_count(vault: &Vault) -> usize {
        let mut count = 0;
        let mut after = None;
        loop {
            let page = vault
                .tasks_by_owner(actor(), after, 256)
                .expect("query TASK owner index");
            count += page.len();
            after = page.last().copied();
            if page.len() < 256 {
                return count;
            }
        }
    }
    fn all_task_count(vault: &Vault) -> u64 {
        vault
            .count_entities_by_type(oneiron::registry::ENTITY_TYPE_TASK)
            .expect("count actual TASK entities")
    }
    fn plan(handle: u64) -> OraclePlan {
        FAN_OUT_PLANS.with(|plans| plans.borrow()[handle as usize].clone())
    }
    fn recorded(vault: &Vault, handle: u64) -> ConsultFanOutReceipt {
        let plan = plan(handle);
        let receipt = plan.receipt.expect("gate must have run");
        vault
            .memory(actor(), oneiron::EdgeActorClass::Human)
            .consult_fanout_status(receipt.correlation_ref)
            .expect("durable plan status")
    }
    fn all_recorded(vault: &Vault) -> Vec<(OraclePlan, ConsultFanOutReceipt)> {
        FAN_OUT_PLANS.with(|plans| {
            plans
                .borrow()
                .iter()
                .filter_map(|plan| {
                    plan.receipt.as_ref().map(|receipt| {
                        let status = vault
                            .memory(actor(), oneiron::EdgeActorClass::Human)
                            .consult_fanout_status(receipt.correlation_ref)
                            .expect("stored run");
                        (plan.clone(), status)
                    })
                })
                .collect()
        })
    }
    fn scope(plan: &OraclePlan) -> String {
        format!("consult:{}:preset:{}", actor().to_hex(), plan.preset)
    }

    /// Stages a fixture; all estimation and admission use the production facade.
    pub(crate) fn submit_fan_out_plan(
        vault: &Vault,
        preset: &str,
        per_peer: &[(&str, u64)],
    ) -> u64 {
        put_person(vault, actor());
        let peers: Vec<_> = per_peer
            .iter()
            .map(|(peer, count)| {
                let peer_id = peer_id(peer);
                put_person(vault, peer_id);
                (peer_id, *count)
            })
            .collect();
        let assignees = peers
            .iter()
            .flat_map(|(peer, count)| {
                std::iter::repeat_n(
                    *peer,
                    usize::try_from(*count).expect("bounded oracle count"),
                )
            })
            .collect();
        let input = ConsultFanOutSpec {
            question_ref: question(vault),
            context_refs: Vec::new(),
            assignees,
            deadline_at: u64::MAX / 2,
            label: Some("oracle consult".into()),
            now: None,
        };
        FAN_OUT_PLANS.with(|plans| {
            let mut plans = plans.borrow_mut();
            let handle = plans.len() as u64;
            plans.push(OraclePlan {
                input,
                preset: preset.to_owned(),
                receipt: None,
                surfaced: false,
                owned_tasks_before: owned_task_count(vault),
                all_tasks_before: all_task_count(vault),
            });
            handle
        })
    }
    pub(crate) fn run_fan_out_gate(vault: &Vault, handle: u64) {
        let staged = plan(handle);
        let owned_before = owned_task_count(vault);
        let all_before = all_task_count(vault);
        let receipt = vault
            .memory(actor(), oneiron::EdgeActorClass::Human)
            .fan_out_counted_consults(&staged.input, &staged.preset)
            .expect("admit fan-out");
        FAN_OUT_PLANS.with(|plans| {
            let mut plans = plans.borrow_mut();
            plans[handle as usize].owned_tasks_before = owned_before;
            plans[handle as usize].all_tasks_before = all_before;
            plans[handle as usize].surfaced = receipt.paused.is_some();
            plans[handle as usize].receipt = Some(receipt);
        });
    }
    pub(crate) fn tick_fan_out_executor(vault: &Vault, handle: u64) {
        // Peer consults become TASKs, not connector-send ATTEMPTs. Claim the
        // real node-local executor door anyway, then check the authoritative
        // TASK owner index: no paused/denied plan can materialize work later.
        let staged = plan(handle);
        let status = recorded(vault, handle);
        if status.paused.is_some() {
            let claim = oneiron::AttemptQueue::new(vault)
                .claim(oneiron::attempt_queue::ClaimAttempt {
                    lease_owner: "es06-executor-tick".to_owned(),
                    now: u64::MAX / 2,
                })
                .expect("claim runnable work");
            assert_eq!(claim, oneiron::attempt_queue::ClaimOutcome::Empty);
            assert!(status.task_refs.is_empty());
            assert_eq!(owned_task_count(vault), staged.owned_tasks_before);
            assert_eq!(all_task_count(vault), staged.all_tasks_before);
        }
    }
    pub(crate) fn count_dispatched_consults(vault: &Vault, handle: u64) -> u64 {
        let staged = plan(handle);
        if staged.receipt.is_none() {
            // This is not a fixture flag standing in for dispatch: an
            // estimate-only call can still be caught if it mints an unreceipted
            // TASK, even if it misattributes that TASK to a different actor.
            return all_task_count(vault)
                .checked_sub(staged.all_tasks_before)
                .expect("TASK count cannot fall during estimate");
        }
        let status = recorded(vault, handle);
        let actual = owned_task_count(vault)
            .checked_sub(staged.owned_tasks_before)
            .expect("TASK count cannot fall during admission");
        for id in &status.task_refs {
            assert_eq!(
                vault.get_entity_type(id).expect("read peer TASK"),
                Some(oneiron::registry::ENTITY_TYPE_TASK)
            );
        }
        assert_eq!(
            actual,
            status.task_refs.len(),
            "stored receipt must name every created peer TASK"
        );
        actual as u64
    }
    pub(crate) fn count_needs_input_rows(vault: &Vault) -> usize {
        all_recorded(vault)
            .iter()
            .filter(|(plan, status)| {
                plan.surfaced && !status.paused.as_ref().is_some_and(|pause| pause.denied)
            })
            .count()
    }
    pub(crate) fn count_engine_killed_fan_outs(vault: &Vault) -> usize {
        all_recorded(vault)
            .iter()
            .filter(|(_, status)| status.paused.is_none() && status.task_refs.is_empty())
            .count()
    }
    fn rule(vault: &Vault, handle: u64, choice: ConsultFanOutChoice, cap: Option<u64>) {
        let status = recorded(vault, handle);
        vault
            .memory(actor(), oneiron::EdgeActorClass::Human)
            .resume_fan_out_consults_with_cap(
                status.correlation_ref,
                status.meter.plan_digest,
                choice,
                &owner(vault),
                cap,
            )
            .expect("authenticated fan-out ruling");
    }
    pub(crate) fn approve_fan_out(vault: &Vault, handle: u64, cap: Option<u64>) {
        rule(
            vault,
            handle,
            if cap.is_some() {
                ConsultFanOutChoice::ApproveAndRemember
            } else {
                ConsultFanOutChoice::ApproveOnce
            },
            cap,
        );
    }
    pub(crate) fn count_fan_out_policy_rows(vault: &Vault) -> usize {
        let mut scopes = std::collections::BTreeSet::new();
        all_recorded(vault)
            .iter()
            .filter(|(plan, _)| scopes.insert(scope(plan)))
            .filter(|(plan, _)| {
                standing_policy_for(vault, &scope(plan), EscalationTrigger::Budget)
                    .expect("read standing policy")
                    .is_some()
            })
            .count()
    }
    pub(crate) fn count_fan_out_policy_receipts(vault: &Vault) -> usize {
        let mut scopes = std::collections::BTreeSet::new();
        all_recorded(vault)
            .iter()
            .filter(|(plan, _)| scopes.insert(scope(plan)))
            .filter_map(|(plan, _)| {
                standing_policy_for(vault, &scope(plan), EscalationTrigger::Budget)
                    .expect("read standing policy")
            })
            .map(|row| {
                let receipts = vault
                    .receipts(ReceiptQuery::new(1000).with_kind(ReceiptKind::Gate))
                    .expect("read gate receipts");
                row.cited_receipts
                    .iter()
                    .filter(|cited| receipts.iter().any(|receipt| &receipt.receipt_id == *cited))
                    .count()
            })
            .sum()
    }
    pub(crate) fn deny_fan_out(vault: &Vault, handle: u64) {
        rule(vault, handle, ConsultFanOutChoice::Deny, None);
    }
    pub(crate) fn count_denied_fan_outs(vault: &Vault) -> usize {
        all_recorded(vault)
            .iter()
            .filter(|(_, status)| status.paused.as_ref().is_some_and(|pause| pause.denied))
            .count()
    }
    pub(crate) fn count_fan_out_denial_receipts(vault: &Vault) -> usize {
        vault
            .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))
            .expect("gate receipts")
            .iter()
            .filter(|row| row.outcome == "kept_paused")
            .count()
    }

    // ---- ONE-1720 (ES-07): AUTO-mode escalation learning ----
    //
    // The three seams here are gone rather than retargeted: `outbound_chokepoint`
    // is `pub(crate)`, so ONE-1719's plan, estimate, and decider are neither
    // nameable nor constructible from this integration-test crate and no public
    // composition reaches the classification seam. Their in-crate successors in
    // `crates/oneiron/src/fanout_auto/tests.rs` were removed by the 2026-10 test
    // prune as MIRROR tests.

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

// ===== ONE-1719 (ES-06) — fan-out estimate-then-approve gate =====

/// Doc 13 §5: approval unblocks the plan, and the "[always <= 500 for this
/// preset]" choice persists as ONE receipted policy row; a later 300-consult
/// plan under the same preset then runs silent (no second needs_input row).
#[test]
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

/// Doc 13 §5 ladder "[deny]": a human deny ruling on an over-threshold plan
/// dispatches NOTHING (including on later executor ticks), consumes the
/// pending needs_input row, records the denial as a receipt, and parks the
/// plan in an EXPLICIT denied state — never a silent engine kill.
#[test]
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

// ===== ONE-1720 (ES-07) — AUTO-mode escalation learning =====
//
// The three ES-07 arms are not here: the crate-private fan-out types they need
// are not nameable from this crate. Their in-crate successors in
// `crates/oneiron/src/fanout_auto/tests.rs` were removed by the 2026-10 test
// prune as MIRROR tests. `count_fan_out_policy_rows` stays ONE-1719-owned and
// untouched.

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

        let identity = crate::common::self_held_identity_in_state(
            "email",
            "me@primary.test",
            oneiron::channel_identity::SelfHeldShape::DedicatedAddress,
            oneiron::channel_identity::ChannelIdentityBinding::agent(actor),
            oneiron::channel_identity::ChannelIdentityState::Active,
            100,
        );
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
        pub(super) uncertain_first: bool,
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
            if self.uncertain_first && self.parts.len() == 1 {
                return oneiron::outbound::OutboundExecutionOutcome::failed(
                    "uncertain_wire_crossing",
                )
                .with_possible_delivery();
            }
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

/// A calendar revision is semantic replacement, unlike queue-emulated sends:
/// an ambiguous transport result must leave its frozen revision replayable.
#[test]
fn calendar_invite_ambiguous_crossing_replays_identical_revision() {
    use calendar_invite_fixture as fixture;
    use oneiron::outbound_intent_ledger::{IntentState, intent_ledger_records};

    let (_dir, vault, blob_ref) = fixture::admitted_vault();
    vault
        .memory(fixture::actor_ref(), oneiron::EdgeActorClass::Human)
        .calendar_invite(&fixture::invite(&blob_ref))
        .expect("schedule invite");
    let mut sink = fixture::InviteSink {
        uncertain_first: true,
        ..Default::default()
    };
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, 200)
            .expect("ambiguous send"),
        0
    );
    assert_eq!(sink.parts.len(), 1);
    let first = intent_ledger_records(&vault).expect("pending intent");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].state, IntentState::Pending);
    assert!(
        first[0].idempotency_supported,
        "same revision is replay safe"
    );
    let frozen_hash = first[0].payload_hash;

    // The transport curve re-arms at 200+60. No new UID, SEQUENCE or method
    // may be minted when that durable attempt resumes.
    assert_eq!(
        vault
            .run_connector_task_executor(&mut sink, 261)
            .expect("retry"),
        1
    );
    assert_eq!(sink.parts.len(), 2);
    assert_eq!(sink.parts[0], sink.parts[1], "identical iMIP bytes");
    let done = intent_ledger_records(&vault).expect("completed intent");
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].state, IntentState::Done);
    assert_eq!(done[0].payload_hash, frozen_hash);
    assert_eq!(fixture::live_sequence(&vault), Some(0));
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
// fourth: its one definition is `pub(crate)` and feature-gated
// (`any(sync, test)`), i.e. an origin-validated replay door for bytes a peer
// already authored, not a public write door.
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

    pub(super) const INGEST_SOURCE: &str = concat!(
        include_str!("../../src/ingest/mod.rs"),
        include_str!("../../src/ingest/resolution.rs"),
        include_str!("../../src/ingest/types.rs"),
        include_str!("../../src/ingest/admission.rs"),
        include_str!("../../src/ingest/registry.rs"),
        include_str!("../../src/ingest/transcripts.rs"),
    );
    pub(super) const BATCH_BUILDER_SOURCE: &str = concat!(
        include_str!("../../src/batch/builder/mod.rs"),
        include_str!("../../src/batch/builder/apply.rs"),
        include_str!("../../src/batch/builder/ops.rs"),
        include_str!("../../src/batch/builder/puts.rs"),
        include_str!("../../src/batch/builder/claims.rs"),
        include_str!("../../src/batch/builder/edges.rs"),
        include_str!("../../src/batch/builder/commit.rs"),
        include_str!("../../src/batch/builder/preflight.rs"),
    );

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
        )
        .expect("fixture");
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

    pub(super) fn priors_with_evidence(vault: &Vault, provider: &str, evidence: &str) -> usize {
        oneiron::provider_confidence::count_active_prior_claims_with_evidence(
            vault, provider, evidence,
        )
        .expect("evidence-carrying prior count")
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

// ── The write-time validator ───────────────────────────────────────────────

/// A `provider.enrichment` claim whose attribution cannot be read is refused at
/// WRITE time, on every default-feature door, with InvalidClaimBody.
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

    let cases: [(&str, rmpv::Value); 7] = [
        ("non-map value", rmpv::Value::from("clearbit")),
        (
            "missing provider key",
            rmpv::Value::Map(vec![(rmpv::Value::from("vendor"), rmpv::Value::from("x"))]),
        ),
        (
            "duplicate provider keys",
            rmpv::Value::Map(vec![
                (rmpv::Value::from("provider"), rmpv::Value::from("clearbit")),
                (rmpv::Value::from("provider"), rmpv::Value::from("scraper")),
            ]),
        ),
        (
            "non-string provider",
            rmpv::Value::Map(vec![(
                rmpv::Value::from("provider"),
                rmpv::Value::from(7_u64),
            )]),
        ),
        ("blank provider", one1891::enrichment_value("", &[])),
        (
            "untrimmed provider",
            one1891::enrichment_value(" clearbit ", &[]),
        ),
        (
            "oversized provider",
            one1891::enrichment_value(oversized.as_str(), &[]),
        ),
    ];

    let mut lead = 0x80_u8;
    for (label, value) in cases {
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
            assert!(
                matches!(error, oneiron::Error::InvalidClaimBody(_)),
                "{label} through {}",
                door.label(),
            );
            assert_eq!(
                one1891::counts(&vault),
                before,
                "{label} through {} left bytes behind",
                door.label(),
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
        assert!(
            matches!(error, oneiron::Error::InvalidClaimBody(_)),
            "through {}",
            door.label(),
        );
        assert_eq!(one1891::counts(&vault), before, "through {}", door.label());
    }
}

/// Invalid and evidence-free priors retain typed refusals, and generic claim
/// writes cannot plant reserved trust multipliers.
#[test]
fn one1891_prior_validator_is_untouched_by_the_enrichment_arm() {
    let (_dir, vault) = open_vault();

    one1891::write_prior(&vault, "provider_prior_ok", 0.65, "evidence:initial");
    assert_eq!(one1891::active_priors(&vault, "provider_prior_ok"), 1);
    assert_eq!(
        one1891::priors_with_evidence(&vault, "provider_prior_ok", "evidence:initial"),
        1
    );

    for (label, prior, evidence) in [
        ("above one", 1.5_f32, "evidence:x"),
        ("below zero", -0.1, "evidence:x"),
        ("not finite", f32::NAN, "evidence:x"),
        ("bare number", 0.5, ""),
    ] {
        let error = oneiron::provider_confidence::write_provider_prior(
            &vault,
            "provider_prior_ok",
            prior,
            evidence,
        )
        .expect_err("the prior door stays fail-closed");
        assert!(
            matches!(&error, oneiron::Error::InvalidClaimBody(_)),
            "{label}: expected an invalid-claim-body refusal, got {error}"
        );
    }
    assert_eq!(
        one1891::active_priors(&vault, "provider_prior_ok"),
        1,
        "a refused prior write leaves the live head alone"
    );
    assert_eq!(
        one1891::priors_with_evidence(&vault, "provider_prior_ok", "evidence:initial"),
        1
    );

    let actor = one1891::put_provider_actor(&vault, 0xe1, "provider_prior_ok");
    let mut body = oneiron::ClaimBody::new(
        "actor.confidence_prior",
        oneiron::ClaimSubject::Entity(actor),
        rmpv::Value::F32(1.0),
        1.0,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .expect("fixture");
    body.valid_from = Some(200);
    let error = vault
        .put_claim(&one1891::fixture_id(0xe2), &body, one1891::at(200), 200)
        .expect_err("actor.* is reserved");
    assert!(
        matches!(
            &error,
            oneiron::Error::Claim(oneiron::error::ClaimError::ReservedPredicate { .. })
        ),
        "expected a reserved-predicate refusal, got {error}"
    );
}

/// STRUCTURAL: `put_replicated` is not a fourth write door. Its definition is
/// `pub(crate)` and feature-gated, so the three doors exercised above are
/// the whole default-feature write surface for an enrichment claim — and a
/// replicated body still meets the same validator inside `apply_put`, so this
/// is a statement about REACH, not about a bypass.
#[test]
fn one1891_put_replicated_is_not_a_fourth_write_door() {
    for (label, source) in [("builder", one1891::BATCH_BUILDER_SOURCE)] {
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

// Ruling A/B/C: authority is minted only from vetted evidence and canonical heads.
mod one1891_ruling {
    use super::{Vault, one1891 as f, open_vault};
    use oneiron::identity_topology::{
        EntityLifecycleState, IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, MergeOp,
        SplitOp, SurvivorshipPlan,
    };
    use oneiron::{
        ClaimSource, ClaimSubject, EntityId, EntityResolutionCandidate, EntityResolutionRoute,
        Error,
    };

    fn merge(vault: &Vault, sources: Vec<EntityId>, survivor: EntityId) {
        vault
            .apply_identity_topology_op(
                &IdentityTopologyOp::Merge(MergeOp {
                    sources: sources.clone(),
                    survivor,
                    evidence: IdentityOpEvidence::default(),
                    survivorship_plan: SurvivorshipPlan::ReadThrough,
                }),
                &IdentityOpWrite::auto(ClaimSource::Inferred),
                400,
            )
            .expect("fixture merge");
        for shell in sources {
            assert_eq!(vault.resolve_entity(&shell).unwrap(), vec![survivor]);
            assert_eq!(
                vault.entity_lifecycle_state(&shell).unwrap(),
                EntityLifecycleState::Merged
            );
        }
    }

    fn split(vault: &Vault, entity: EntityId, heads: Vec<EntityId>) {
        vault
            .apply_identity_topology_op(
                &IdentityTopologyOp::Split(SplitOp {
                    entity,
                    heads,
                    reassignment: Default::default(),
                    evidence: IdentityOpEvidence::default(),
                }),
                &IdentityOpWrite::auto(ClaimSource::Inferred),
                500,
            )
            .expect("fixture split");
        assert_eq!(
            vault.entity_lifecycle_state(&entity).unwrap(),
            EntityLifecycleState::Split
        );
    }

    fn assert_noncanonical(vault: &Vault, candidate: EntityResolutionCandidate) {
        let before = f::counts(vault);
        assert!(matches!(
            oneiron::evaluate_entity_resolution_waterfall(vault, &[candidate], false),
            Err(Error::InvalidClaimBody(
                "waterfall candidate subject is not a canonical active entity"
            ))
        ));
        assert_eq!(f::counts(vault), before);
    }

    // The three stored-unvetted-evidence ruling tests live in
    // src/provider_confidence/prior_projection_tests.rs::one1891_ruling.
    // Their setup needs the existing crate-private put_replicated fixture door;
    // the ordinary put_claim gate must continue rejecting these Auto writes.

    #[test]
    fn one1891_twin_merge_projects_newest_prior_and_keeps_cache_reads_scope_one() {
        let (_dir, vault) = open_vault();
        let provider = "provider_merge_twins";
        let smaller = f::put_provider_actor(&vault, 0x11, provider);
        let older = f::write_prior(&vault, provider, 0.70, "evidence:older");
        let larger = f::put_provider_actor(&vault, 0x22, provider);
        f::set_indexes(&vault, provider, Some(larger.as_bytes()), None);
        let newer = f::write_prior(&vault, provider, 0.30, "evidence:newer");
        let old_body = vault.get_claim(&older).unwrap().unwrap();
        let new_body = vault.get_claim(&newer).unwrap().unwrap();
        assert!((new_body.valid_from, newer) > (old_body.valid_from, older));
        merge(&vault, vec![larger], smaller);
        assert_eq!(
            vault.get_claim(&older).unwrap().unwrap().subject,
            ClaimSubject::Entity(smaller),
        );
        assert_eq!(
            vault.get_claim(&newer).unwrap().unwrap().subject,
            ClaimSubject::Entity(larger),
        );
        let candidate = f::candidate(&vault, 0x31, 0x41, provider, 0.80);
        f::clear_indexes(&vault, provider);
        let before = f::counts(&vault);
        assert!(f::close(
            f::effective(&vault, &candidate.confidence_claim_ref),
            0.24,
        ));
        assert_eq!(f::counts(&vault), before);

        // A shell-prior shortcut must preserve the projected trust outcome.
        f::set_indexes(&vault, provider, None, Some(newer.as_bytes()));
        for _ in 0..2 {
            assert!(f::close(
                f::effective(&vault, &candidate.confidence_claim_ref),
                0.24,
            ));
            assert_eq!(f::counts(&vault), before);
        }
        let direct = f::write_prior(&vault, provider, 0.60, "evidence:survivor");
        let direct_body = vault.get_claim(&direct).unwrap().unwrap();
        assert_eq!(direct_body.subject, ClaimSubject::Entity(smaller));
        assert!((direct_body.valid_from, direct) > (new_body.valid_from, newer));
        f::set_indexes(&vault, provider, None, Some(newer.as_bytes()));
        let before = f::counts(&vault);
        for _ in 0..2 {
            assert!(f::close(
                f::effective(&vault, &candidate.confidence_claim_ref),
                0.48,
            ));
            assert_eq!(f::counts(&vault), before);
        }
        assert_eq!(
            vault.get_claim(&older).unwrap().unwrap().subject,
            ClaimSubject::Entity(smaller),
        );
        assert_eq!(
            vault.get_claim(&newer).unwrap().unwrap().subject,
            ClaimSubject::Entity(larger),
        );
    }

    #[test]
    fn one1891_cross_key_strand_blocks_reads_and_mint_without_index_repair() {
        fn assert_stranded<T: std::fmt::Debug>(result: oneiron::Result<T>) {
            assert!(matches!(
                result.expect_err("stranded prior must fail closed"),
                Error::InvalidClaimBody(_),
            ));
        }

        let (_dir, vault) = open_vault();
        let provider = "provider_stranded";
        let actor = f::put_provider_actor(&vault, 0x11, provider);
        let prior = f::write_prior(&vault, provider, 0.30, "evidence:stranded");
        let foreign = f::put_provider_actor(&vault, 0x22, "provider_other");
        merge(&vault, vec![actor], foreign);
        let candidate = f::candidate(&vault, 0x31, 0x41, provider, 0.90);
        for cached in [false, true] {
            f::set_indexes(
                &vault,
                provider,
                cached.then_some(actor.as_bytes()),
                cached.then_some(prior.as_bytes()),
            );
            let before = f::counts(&vault);
            assert_stranded(oneiron::provider_confidence::effective_confidence(
                &vault,
                &candidate.confidence_claim_ref,
            ));
            assert_eq!(f::counts(&vault), before);
            assert_stranded(oneiron::provider_confidence::write_provider_prior(
                &vault,
                provider,
                0.50,
                "evidence:no-fork",
            ));
            assert_eq!(f::counts(&vault), before);
            assert_eq!(
                vault.get_claim(&prior).unwrap().unwrap().subject,
                ClaimSubject::Entity(actor),
            );
            assert_stranded(oneiron::provider_confidence::effective_confidence(
                &vault,
                &candidate.confidence_claim_ref,
            ));
            assert_eq!(f::counts(&vault), before);
        }
    }

    #[test]
    fn one1891_split_provider_priors_are_stranded_even_with_one_matching_head() {
        fn assert_stranded<T: std::fmt::Debug>(result: oneiron::Result<T>) {
            assert!(matches!(
                result.expect_err("stranded prior must fail closed"),
                Error::InvalidClaimBody(_),
            ));
        }

        for head_count in 0..=2 {
            let (_dir, vault) = open_vault();
            let provider = "provider_split";
            let actor = f::put_provider_actor(&vault, 0x11, provider);
            let prior = f::write_prior(&vault, provider, 0.30, "evidence:split");
            let heads = (0..head_count)
                .map(|i| f::put_provider_actor(&vault, 0x21 + i, provider))
                .collect();
            split(&vault, actor, heads);
            let candidate = f::candidate(&vault, 0x31, 0x41, provider, 0.90);
            f::clear_indexes(&vault, provider);
            let before = f::counts(&vault);
            assert_stranded(oneiron::provider_confidence::effective_confidence(
                &vault,
                &candidate.confidence_claim_ref,
            ));
            assert_eq!(f::counts(&vault), before);
            assert_stranded(oneiron::provider_confidence::write_provider_prior(
                &vault,
                provider,
                0.50,
                "evidence:no-fork",
            ));
            assert_eq!(f::counts(&vault), before);
            assert_eq!(
                vault.get_claim(&prior).unwrap().unwrap().subject,
                ClaimSubject::Entity(actor),
            );
        }
    }

    #[test]
    fn one1891_waterfall_projects_both_subjects_and_never_selects_a_shell() {
        let (_dir, vault) = open_vault();
        let shell = f::candidate(&vault, 0x11, 0x41, "provider_canonical", 0.95);
        let other_shell = f::put_person(&vault, 0x12);
        let head = f::put_person(&vault, 0x31);
        let unrelated = f::put_person(&vault, 0x32);
        merge(&vault, vec![shell.subject, other_shell], head);
        let before = f::counts(&vault);
        for subject in [head, shell.subject, other_shell] {
            let decision = f::decide(
                &vault,
                &[EntityResolutionCandidate { subject, ..shell }],
                false,
            );
            assert_eq!(decision.claims_suppressed, 0);
            assert_eq!(decision.selected, Some(head));
            assert_eq!(decision.route, EntityResolutionRoute::HardLink);
            assert_eq!(decision.ranked[0].candidate.subject, head);
            assert_eq!(
                decision.ranked[0].candidate.confidence_claim_ref,
                shell.confidence_claim_ref
            );
        }
        assert!(matches!(
            oneiron::evaluate_entity_resolution_waterfall(
                &vault,
                &[EntityResolutionCandidate {
                    subject: unrelated,
                    ..shell
                }],
                false,
            ),
            Err(Error::InvalidClaimBody(
                "waterfall candidate subject does not match confidence claim subject"
            ))
        ));
        assert_eq!(
            vault
                .get_claim(&shell.confidence_claim_ref)
                .unwrap()
                .unwrap()
                .subject,
            ClaimSubject::Entity(shell.subject)
        );
        assert_eq!(f::counts(&vault), before);
    }

    #[test]
    fn one1891_waterfall_rejects_missing_ambiguous_and_nonactive_heads() {
        let (_dir, vault) = open_vault();
        let candidate = f::candidate(&vault, 0x11, 0x41, "provider_heads", 0.95);
        assert_noncanonical(
            &vault,
            EntityResolutionCandidate {
                subject: f::fixture_id(0x77),
                ..candidate
            },
        );
        let head = f::put_person(&vault, 0x21);
        merge(&vault, vec![candidate.subject], head);
        vault.drop_redirect_projection().unwrap();
        assert_noncanonical(&vault, candidate);
        assert_noncanonical(
            &vault,
            EntityResolutionCandidate {
                subject: head,
                ..candidate
            },
        );
        vault.rebuild_redirect_projection_from_edges().unwrap();
        split(&vault, head, vec![]);
        assert_noncanonical(&vault, candidate);

        let (_dir2, ambiguous) = open_vault();
        let candidate = f::candidate(&ambiguous, 0x11, 0x41, "provider_heads", 0.95);
        let first = f::put_person(&ambiguous, 0x21);
        let second = f::put_person(&ambiguous, 0x22);
        split(&ambiguous, candidate.subject, vec![first, second]);
        assert_noncanonical(&ambiguous, candidate);
        assert_noncanonical(
            &ambiguous,
            EntityResolutionCandidate {
                subject: first,
                ..candidate
            },
        );
    }

    #[test]
    fn one1891_canonical_ties_agree_on_two_devices_not_shell_order() {
        let mut decisions = Vec::new();
        for reverse in [false, true] {
            let (_dir, vault) = open_vault();
            let shell = f::candidate(&vault, 0x11, 0x41, "provider_tie", 0.80);
            let head = f::put_person(&vault, 0x33);
            let direct = f::candidate(&vault, 0x22, 0x42, "provider_tie", 0.80);
            merge(&vault, vec![shell.subject], head);
            let candidates = if reverse {
                [direct, shell]
            } else {
                [shell, direct]
            };
            let decision = f::decide(&vault, &candidates, false);
            assert_eq!(decision.selected, Some(direct.subject));
            assert_eq!(
                decision
                    .ranked
                    .iter()
                    .map(|row| row.candidate.subject)
                    .collect::<Vec<_>>(),
                vec![direct.subject, head]
            );
            decisions.push(decision);
        }
        assert_eq!(decisions[0], decisions[1]);
    }
}
