use std::collections::{HashSet, VecDeque};

use crate::config::VaultConfig;

use super::*;

const AUTHORIZATION: OutboundAuthorizationBinding = OutboundAuthorizationBinding::new([0xA5; 32]);

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn attempt(byte: u8) -> AttemptId {
    AttemptId::from_bytes(&[byte; 16]).expect("attempt id")
}

fn descriptor(
    read_only_hint: Option<bool>,
    idempotency_supported_hint: Option<bool>,
) -> OutboundToolDescriptor {
    OutboundToolDescriptor {
        read_only_hint,
        idempotency_supported_hint,
    }
}

fn request(
    attempt_id: AttemptId,
    call_seq: u64,
    payload: &[u8],
    now_ms: u64,
) -> OutboundCallRequest {
    OutboundCallRequest::new(
        attempt_id,
        call_seq,
        "test-server",
        "test-tool",
        payload.to_vec(),
        now_ms,
    )
    .with_authorization_binding(AUTHORIZATION)
}

fn persist_pending(
    vault: &Vault,
    attempt_id: AttemptId,
    call_seq: u64,
    payload: &[u8],
    now_ms: u64,
    idempotency_supported: bool,
) -> IntentLedgerRecord {
    let request = request(attempt_id, call_seq, payload, now_ms);
    let authorization_binding = request
        .authorization_binding
        .expect("test request authorization binding");
    let payload_hash = hash_frozen_payload(&request.payload);
    let intent_id = derive_intent_id(
        request.attempt_id,
        request.call_seq,
        &request.server,
        &request.tool,
        &payload_hash,
    )
    .expect("intent id");
    let call =
        FrozenOutboundCall::effectful(request, payload_hash, intent_id, idempotency_supported);
    let pending = IntentLedgerRecord {
        id: call.intent_id.expect("intent id"),
        attempt_id,
        call_seq,
        server: call.server.clone(),
        tool: call.tool.clone(),
        payload_hash: call.payload_hash,
        payload: call.payload.to_vec(),
        idempotency_key: call.idempotency_key.expect("idempotency key"),
        idempotency_supported,
        authorization_binding: Some(authorization_binding),
        binding_version: OUTBOUND_BINDING_VERSION,
        resolved_endpoint: None,
        capability_provenance: None,
        budget_accounting: BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: now_ms,
        },
        recorded_outcome: None,
        state: IntentState::Pending,
        created_ms: now_ms,
        updated_ms: now_ms,
    };
    let (record, replayed) = insert_pending_or_read(vault, &pending).expect("persist pending");
    assert!(!replayed);
    record
}

#[derive(Default)]
struct CountingSender {
    calls: usize,
    outcome: Option<OutboundSendOutcome>,
}

impl OutboundSender for CountingSender {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.calls += 1;
        self.outcome.unwrap_or(OutboundSendOutcome::Acked)
    }
}

#[test]
fn classifier_is_fail_closed_and_only_read_only_skips_the_ledger() {
    // If false/unknown read-only hints bypass the ledger, the exact effectful
    // row count is zero instead of one.
    let (_dir, vault) = open_vault();
    let mut sender = CountingSender::default();
    let result = execute_outbound_call(
        &vault,
        descriptor(Some(true), None),
        request(attempt(1), 0, b"read", 1),
        &mut sender,
    )
    .expect("read-only dispatch");
    assert_eq!(result.class, OutboundCallClass::ReadOnly);
    assert_eq!(intent_ledger_records(&vault).expect("records").len(), 0);

    for (case, read_only_hint) in [(2, Some(false)), (3, None)] {
        let (_dir, vault) = open_vault();
        let mut sender = CountingSender {
            outcome: Some(OutboundSendOutcome::Ambiguous),
            ..CountingSender::default()
        };
        let result = execute_outbound_call(
            &vault,
            descriptor(read_only_hint, Some(true)),
            request(attempt(case), 0, b"effect", 1),
            &mut sender,
        )
        .expect("effectful dispatch");
        assert_eq!(result.class, OutboundCallClass::Effectful);
        let records = intent_ledger_records(&vault).expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, IntentState::Pending);
    }
}

struct OrderingSender<'a> {
    vault: &'a Vault,
    calls: usize,
}

impl OutboundSender for OrderingSender<'_> {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.calls += 1;
        let records = intent_ledger_records(self.vault).expect("record visible at send");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, IntentState::Pending);
        assert_eq!(records[0].idempotency_key, call.idempotency_key().unwrap());
        OutboundSendOutcome::Acked
    }
}

#[test]
fn effectful_pending_is_durable_before_send_then_ack_becomes_done() {
    // With PENDING-before-send removed, the sender's exact row/state count fails.
    let (_dir, vault) = open_vault();
    let mut sender = OrderingSender {
        vault: &vault,
        calls: 0,
    };
    let result = execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(true)),
        request(attempt(4), 8, b"payload", 100),
        &mut sender,
    )
    .expect("dispatch");

    assert_eq!(sender.calls, 1);
    assert_eq!(result.state, Some(IntentState::Done));
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Done);
}

struct DeduplicatingServer {
    outcomes: VecDeque<OutboundSendOutcome>,
    seen_keys: HashSet<String>,
    observed_effects: usize,
    sends: usize,
}

impl DeduplicatingServer {
    fn new(outcomes: impl IntoIterator<Item = OutboundSendOutcome>) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
            seen_keys: HashSet::new(),
            observed_effects: 0,
            sends: 0,
        }
    }
}

impl OutboundSender for DeduplicatingServer {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.sends += 1;
        let key = call
            .idempotency_key()
            .expect("effectful call carries idempotency key")
            .to_owned();
        if self.seen_keys.insert(key) {
            self.observed_effects += 1;
        }
        self.outcomes
            .pop_front()
            .unwrap_or(OutboundSendOutcome::Acked)
    }
}

#[test]
fn crash_replay_and_recovery_observe_the_effect_exactly_once() {
    // Without the ledger, recovery under-fires after the crash; without the
    // persisted deterministic key, replay/recovery increments effects above one.
    let (_dir, vault) = open_vault();
    let attempt_id = attempt(5);
    let descriptor = descriptor(None, Some(true));
    let mut server = DeduplicatingServer::new([
        OutboundSendOutcome::Ambiguous,
        OutboundSendOutcome::Ambiguous,
        OutboundSendOutcome::Acked,
    ]);

    let first = execute_outbound_call(
        &vault,
        descriptor,
        request(attempt_id, 9, b"same payload", 100),
        &mut server,
    )
    .expect("first dispatch");
    assert_eq!(first.state, Some(IntentState::Pending));
    assert_eq!(server.observed_effects, 1);

    let replay = execute_outbound_call(
        &vault,
        descriptor,
        request(attempt_id, 9, b"same payload", 101),
        &mut server,
    )
    .expect("durable replay");
    assert!(replay.replayed);
    assert_eq!(replay.state, Some(IntentState::Pending));
    assert_eq!(server.observed_effects, 1);
    assert_eq!(intent_ledger_records(&vault).expect("records").len(), 1);

    let recovery = recover_outbound_intents(&vault, &mut server, 102).expect("recovery");
    assert_eq!(recovery.scanned, 1);
    assert_eq!(recovery.resent, 1);
    assert_eq!(recovery.completed, 1);
    assert_eq!(server.observed_effects, 1);
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Done);

    let done_replay = execute_outbound_call(
        &vault,
        descriptor,
        request(attempt_id, 9, b"same payload", 103),
        &mut server,
    )
    .expect("done replay");
    assert_eq!(done_replay.send_outcome, None);
    assert_eq!(server.sends, 3);
    assert_eq!(server.observed_effects, 1);
}

#[test]
fn non_idempotent_ambiguity_is_abandoned_and_never_resent() {
    // Recovery must re-derive exactly one PreviouslyAbandoned signal from the
    // durable row, proving a crash cannot lose the live ambiguity escalation.
    let (_dir, vault) = open_vault();
    let mut sender = CountingSender {
        calls: 0,
        outcome: Some(OutboundSendOutcome::Ambiguous),
    };
    let result = execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(false)),
        request(attempt(6), 0, b"non-idempotent", 100),
        &mut sender,
    )
    .expect("dispatch");
    assert_eq!(sender.calls, 1);
    assert_eq!(result.state, Some(IntentState::Abandoned));
    assert_eq!(
        result.escalation.map(|value| value.reason),
        Some(IntentEscalationReason::NonIdempotentAmbiguous)
    );

    let recovery = recover_outbound_intents(&vault, &mut sender, 101).expect("recovery");
    assert_eq!(sender.calls, 1);
    assert_eq!(recovery.skipped_abandoned, 1);
    assert_eq!(recovery.resent, 0);
    assert_eq!(recovery.escalations.len(), 1);
    assert_eq!(
        recovery.escalations[0],
        IntentEscalation {
            intent_id: result.intent_id,
            reason: IntentEscalationReason::PreviouslyAbandoned,
        }
    );
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Abandoned);
}

#[test]
fn recovery_abandons_non_idempotent_pending_without_sending() {
    // A directly persisted Pending row models a genuine crash-before-send.
    let (_dir, vault) = open_vault();
    let pending = persist_pending(&vault, attempt(7), 0, b"pending", 100, false);
    let mut sender = CountingSender::default();
    assert_eq!(intent_ledger_records(&vault).expect("records").len(), 1);

    let recovery = recover_outbound_intents(&vault, &mut sender, 101).expect("recovery");
    assert_eq!(sender.calls, 0);
    assert_eq!(recovery.resent, 0);
    assert_eq!(recovery.escalations.len(), 1);
    assert_eq!(
        recovery.escalations[0],
        IntentEscalation {
            intent_id: Some(pending.id),
            reason: IntentEscalationReason::NonIdempotentPending,
        }
    );
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Abandoned);
}

#[test]
fn live_replay_of_non_idempotent_pending_abandons_once() {
    // Without the live Pending-to-Abandoned transition, both exact escalation
    // reasons are NonIdempotentPending and the sole row remains Pending.
    let (_dir, vault) = open_vault();
    let attempt_id = attempt(23);
    let payload = b"live non-idempotent pending";
    let pending = persist_pending(&vault, attempt_id, 0, payload, 100, false);
    let mut sender = CountingSender::default();
    let descriptor = descriptor(Some(false), Some(false));

    let first = execute_outbound_call(
        &vault,
        descriptor,
        request(attempt_id, 0, payload, 101),
        &mut sender,
    )
    .expect("first live replay");

    assert_eq!(sender.calls, 0);
    assert!(first.replayed);
    assert_eq!(first.state, Some(IntentState::Abandoned));
    assert_eq!(first.send_outcome, None);
    assert_eq!(
        first.escalation,
        Some(IntentEscalation {
            intent_id: Some(pending.id),
            reason: IntentEscalationReason::NonIdempotentPending,
        })
    );
    let records = intent_ledger_records(&vault).expect("records after first replay");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Abandoned);

    let second = execute_outbound_call(
        &vault,
        descriptor,
        request(attempt_id, 0, payload, 102),
        &mut sender,
    )
    .expect("second live replay");

    assert_eq!(sender.calls, 0);
    assert!(second.replayed);
    assert_eq!(second.state, Some(IntentState::Abandoned));
    assert_eq!(second.send_outcome, None);
    assert_eq!(
        second.escalation,
        Some(IntentEscalation {
            intent_id: Some(pending.id),
            reason: IntentEscalationReason::PreviouslyAbandoned,
        })
    );
    let records = intent_ledger_records(&vault).expect("records after second replay");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Abandoned);
}

struct PendingCheckingSender<'a> {
    vault: &'a Vault,
    calls: usize,
    outcomes: VecDeque<OutboundSendOutcome>,
}

impl OutboundSender for PendingCheckingSender<'_> {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.calls += 1;
        let records = intent_ledger_records(self.vault).expect("record visible at send");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, IntentState::Pending);
        assert_eq!(Some(&records[0].id), call.intent_id());
        self.outcomes.pop_front().expect("test send outcome")
    }
}

#[test]
fn non_idempotent_pending_after_failure_abandons_without_retry() {
    let (_dir, vault) = open_vault();
    let failure = OutboundSendFailure {
        kind: OutboundFailureKind::Rejected,
        code: Some(400),
    };
    let mut sender = PendingCheckingSender {
        vault: &vault,
        calls: 0,
        outcomes: [
            OutboundSendOutcome::Failed(failure),
            OutboundSendOutcome::Acked,
        ]
        .into_iter()
        .collect(),
    };
    let descriptor = descriptor(Some(false), Some(false));
    let attempt_id = attempt(13);

    let failed = execute_outbound_call(
        &vault,
        descriptor,
        request(attempt_id, 0, b"retryable failure", 100),
        &mut sender,
    )
    .expect("definite failure");
    assert_eq!(sender.calls, 1);
    assert_eq!(failed.state, Some(IntentState::Pending));
    assert_eq!(
        failed.send_outcome,
        Some(OutboundSendOutcome::Failed(failure))
    );
    assert_eq!(failed.escalation, None);
    assert_eq!(intent_ledger_records(&vault).expect("records").len(), 1);

    let retry = execute_outbound_call(
        &vault,
        descriptor,
        request(attempt_id, 0, b"retryable failure", 101),
        &mut sender,
    )
    .expect("same-identity retry");
    assert_eq!(sender.calls, 1);
    assert!(retry.replayed);
    assert_eq!(retry.intent_id, failed.intent_id);
    assert_eq!(retry.state, Some(IntentState::Abandoned));
    assert_eq!(
        retry.escalation,
        Some(IntentEscalation {
            intent_id: failed.intent_id,
            reason: IntentEscalationReason::NonIdempotentPending,
        })
    );
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Abandoned);
}

#[test]
fn idempotent_recovery_failure_stays_pending_for_a_later_recovery() {
    // If a definite failure during idempotent recovery deletes the row, the
    // second recovery cannot resend and sender.calls remains one.
    let (_dir, vault) = open_vault();
    let pending = persist_pending(&vault, attempt(14), 0, b"idempotent pending", 100, true);
    let failure = OutboundSendFailure {
        kind: OutboundFailureKind::TransportNotStarted,
        code: None,
    };
    let mut sender = CountingSender {
        calls: 0,
        outcome: Some(OutboundSendOutcome::Failed(failure)),
    };

    let first = recover_outbound_intents(&vault, &mut sender, 101).expect("failed recovery");
    assert_eq!(sender.calls, 1);
    assert_eq!(first.resent, 1);
    assert_eq!(first.pending, 1);
    assert_eq!(first.failures.len(), 1);
    assert_eq!(
        first.failures[0],
        IntentRecoveryFailure {
            intent_id: pending.id,
            failure,
        }
    );
    assert_eq!(first.escalations.len(), 0);
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Pending);

    sender.outcome = Some(OutboundSendOutcome::Acked);
    let second = recover_outbound_intents(&vault, &mut sender, 102).expect("retry recovery");
    assert_eq!(sender.calls, 2);
    assert_eq!(second.resent, 1);
    assert_eq!(second.completed, 1);
    assert_eq!(second.failures.len(), 0);
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Done);
}

#[test]
fn failed_live_replay_retains_idempotent_pending_receipt() {
    // If a definite Failed replay deletes the maybe-delivered receipt, the
    // exact row count falls to zero instead of retaining one Pending row.
    let (_dir, vault) = open_vault();
    let failure = OutboundSendFailure {
        kind: OutboundFailureKind::TransportNotStarted,
        code: None,
    };
    let mut sender = PendingCheckingSender {
        vault: &vault,
        calls: 0,
        outcomes: [
            OutboundSendOutcome::Ambiguous,
            OutboundSendOutcome::Failed(failure),
        ]
        .into_iter()
        .collect(),
    };
    let descriptor = descriptor(Some(false), Some(true));
    let attempt_id = attempt(16);

    let first = execute_outbound_call(
        &vault,
        descriptor,
        request(attempt_id, 0, b"maybe delivered", 100),
        &mut sender,
    )
    .expect("ambiguous first send");
    assert_eq!(sender.calls, 1);
    assert!(!first.replayed);
    assert_eq!(first.state, Some(IntentState::Pending));

    let replay = execute_outbound_call(
        &vault,
        descriptor,
        request(attempt_id, 0, b"maybe delivered", 101),
        &mut sender,
    )
    .expect("failed replay");
    assert_eq!(sender.calls, 2);
    assert!(replay.replayed);
    assert_eq!(replay.intent_id, first.intent_id);
    assert_eq!(replay.state, Some(IntentState::Pending));
    assert_eq!(
        replay.send_outcome,
        Some(OutboundSendOutcome::Failed(failure))
    );
    assert_eq!(replay.escalation, None);
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, first.intent_id.expect("first intent id"));
    assert_eq!(records[0].state, IntentState::Pending);
}

#[test]
fn descriptor_idempotency_drift_reuses_durable_identity_and_key() {
    // If live idempotency metadata participates in identity, the missing hint
    // creates a second row and the exact observed-effect count rises above one.
    let (_dir, vault) = open_vault();
    let attempt_id = attempt(17);
    let mut server = DeduplicatingServer::new([
        OutboundSendOutcome::Ambiguous,
        OutboundSendOutcome::Ambiguous,
        OutboundSendOutcome::Acked,
    ]);

    let first = execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(true)),
        request(attempt_id, 0, b"stable identity", 100),
        &mut server,
    )
    .expect("initial idempotent dispatch");
    let missing_hint = execute_outbound_call(
        &vault,
        descriptor(Some(false), None),
        request(attempt_id, 0, b"stable identity", 101),
        &mut server,
    )
    .expect("missing-hint replay");
    let false_hint = execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(false)),
        request(attempt_id, 0, b"stable identity", 102),
        &mut server,
    )
    .expect("false-hint replay");

    assert_eq!(server.sends, 3);
    assert_eq!(server.observed_effects, 1);
    assert!(missing_hint.replayed);
    assert!(false_hint.replayed);
    assert_eq!(missing_hint.intent_id, first.intent_id);
    assert_eq!(false_hint.intent_id, first.intent_id);
    assert_eq!(missing_hint.class, OutboundCallClass::Effectful);
    assert_eq!(false_hint.class, OutboundCallClass::Effectful);
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, first.intent_id.expect("first intent id"));
    assert!(records[0].idempotency_supported);
    assert_eq!(records[0].state, IntentState::Done);
}

#[test]
fn read_only_descriptor_drift_honors_existing_effectful_row() {
    // If classification runs before the ledger probe, the replay reaches the
    // sender without a key instead of making exactly two keyed sends on one row.
    let (_dir, vault) = open_vault();
    let attempt_id = attempt(18);
    let mut server = DeduplicatingServer::new([
        OutboundSendOutcome::Ambiguous,
        OutboundSendOutcome::Ambiguous,
    ]);

    let first = execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(true)),
        request(attempt_id, 0, b"ledgered effect", 100),
        &mut server,
    )
    .expect("effectful dispatch");
    let replay = execute_outbound_call(
        &vault,
        descriptor(Some(true), None),
        request(attempt_id, 0, b"ledgered effect", 101),
        &mut server,
    )
    .expect("read-only-hint replay");

    assert_eq!(server.sends, 2);
    assert_eq!(server.observed_effects, 1);
    assert_eq!(replay.class, OutboundCallClass::Effectful);
    assert!(replay.replayed);
    assert_eq!(replay.intent_id, first.intent_id);
    assert_eq!(replay.state, Some(IntentState::Pending));
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, first.intent_id.expect("first intent id"));
    assert_eq!(records[0].state, IntentState::Pending);
}

struct ForceSyncObservingSender {
    calls: usize,
    force_sync_calls_at_send: Option<usize>,
}

impl OutboundSender for ForceSyncObservingSender {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.calls += 1;
        self.force_sync_calls_at_send = Some(FORCE_SYNC_CALLS.load(AtomicOrdering::SeqCst));
        OutboundSendOutcome::Ambiguous
    }
}

#[test]
fn early_hit_replay_force_syncs_before_resend() {
    // Without the early-hit durability fence, the count sampled at the sole
    // resend equals the pre-replay snapshot instead of being strictly greater.
    let (_dir, vault) = open_vault();
    let attempt_id = attempt(22);
    let payload = b"durability-fenced replay";
    persist_pending(&vault, attempt_id, 0, payload, 100, true);
    let before_replay = FORCE_SYNC_CALLS.load(AtomicOrdering::SeqCst);
    let mut sender = ForceSyncObservingSender {
        calls: 0,
        force_sync_calls_at_send: None,
    };

    let replay = execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(true)),
        request(attempt_id, 0, payload, 101),
        &mut sender,
    )
    .expect("early-hit replay");

    assert_eq!(sender.calls, 1);
    assert!(
        sender
            .force_sync_calls_at_send
            .expect("force-sync count sampled at send")
            > before_replay
    );
    assert!(replay.replayed);
    assert_eq!(replay.state, Some(IntentState::Pending));
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Pending);
}

#[test]
fn descriptor_drift_to_read_only_honors_done_receipt_without_fresh_binding() {
    // Before the replay-binding reorder, the no-binding replay returns exactly
    // one InvalidInput error instead of the persisted Done receipt.
    let (_dir, vault) = open_vault();
    let attempt_id = attempt(20);
    let payload = b"done receipt";
    let mut sender = CountingSender::default();

    let first = execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(true)),
        request(attempt_id, 0, payload, 100),
        &mut sender,
    )
    .expect("initial effectful dispatch");
    assert_eq!(first.state, Some(IntentState::Done));
    assert_eq!(sender.calls, 1);

    let replay_request = OutboundCallRequest::new(
        attempt_id,
        0,
        "test-server",
        "test-tool",
        payload.to_vec(),
        101,
    );
    let replay = execute_outbound_call(
        &vault,
        descriptor(Some(true), Some(true)),
        replay_request,
        &mut sender,
    )
    .expect("read-only-drifted Done replay");

    assert_eq!(replay.class, OutboundCallClass::Effectful);
    assert!(replay.replayed);
    assert_eq!(replay.state, Some(IntentState::Done));
    assert_eq!(replay.send_outcome, None);
    assert_eq!(sender.calls, 1);
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Done);
}

struct BindingCheckingDeduplicatingServer {
    outcomes: VecDeque<OutboundSendOutcome>,
    seen_keys: HashSet<String>,
    expected_binding: OutboundAuthorizationBinding,
    observed_effects: usize,
    sends: usize,
}

impl OutboundSender for BindingCheckingDeduplicatingServer {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.sends += 1;
        assert_eq!(call.authorization_binding(), Some(&self.expected_binding));
        let key = call
            .idempotency_key()
            .expect("effectful call carries idempotency key")
            .to_owned();
        if self.seen_keys.insert(key) {
            self.observed_effects += 1;
        }
        self.outcomes.pop_front().expect("test send outcome")
    }
}

#[test]
fn descriptor_drift_replay_of_pending_resends_with_stored_binding() {
    // Before the reorder, or if replay still requires a fresh binding, the
    // no-binding replay returns one InvalidInput error before its second send.
    let (_dir, vault) = open_vault();
    let attempt_id = attempt(21);
    let payload = b"pending receipt";
    let mut server = BindingCheckingDeduplicatingServer {
        outcomes: [OutboundSendOutcome::Ambiguous, OutboundSendOutcome::Acked]
            .into_iter()
            .collect(),
        seen_keys: HashSet::new(),
        expected_binding: AUTHORIZATION,
        observed_effects: 0,
        sends: 0,
    };

    let first = execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(true)),
        request(attempt_id, 0, payload, 100),
        &mut server,
    )
    .expect("initial ambiguous dispatch");
    assert_eq!(first.state, Some(IntentState::Pending));
    assert_eq!(server.sends, 1);
    assert_eq!(server.observed_effects, 1);

    let replay_request = OutboundCallRequest::new(
        attempt_id,
        0,
        "test-server",
        "test-tool",
        payload.to_vec(),
        101,
    );
    let replay = execute_outbound_call(
        &vault,
        descriptor(Some(true), None),
        replay_request,
        &mut server,
    )
    .expect("read-only-drifted Pending replay");

    assert_eq!(replay.class, OutboundCallClass::Effectful);
    assert!(replay.replayed);
    assert_eq!(replay.state, Some(IntentState::Done));
    assert_eq!(replay.send_outcome, Some(OutboundSendOutcome::Acked));
    assert_eq!(server.sends, 2);
    assert_eq!(server.observed_effects, 1);
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].authorization_binding, Some(AUTHORIZATION));
    assert_eq!(records[0].state, IntentState::Done);
}

#[test]
fn deterministic_identity_changes_with_every_identity_input() {
    // Each stable identity input must change the digest, while identical
    // canonical inputs must produce exactly the same replay key.
    let attempt_id = attempt(8);
    let payload_hash = hash_frozen_payload(b"payload");
    let base = derive_intent_id(attempt_id, 3, "server", "tool", &payload_hash).expect("id");
    assert_eq!(
        base,
        derive_intent_id(attempt_id, 3, "server", "tool", &payload_hash).expect("same id")
    );

    let changed_payload_hash = hash_frozen_payload(b"changed");
    for changed in [
        derive_intent_id(attempt(9), 3, "server", "tool", &payload_hash).expect("attempt"),
        derive_intent_id(attempt_id, 4, "server", "tool", &payload_hash).expect("sequence"),
        derive_intent_id(attempt_id, 3, "other", "tool", &payload_hash).expect("server"),
        derive_intent_id(attempt_id, 3, "server", "other", &payload_hash).expect("tool"),
        derive_intent_id(attempt_id, 3, "server", "tool", &changed_payload_hash).expect("payload"),
    ] {
        assert_ne!(base, changed);
    }
}

struct FrozenBytesSender {
    expected: Vec<u8>,
    calls: usize,
}

impl OutboundSender for FrozenBytesSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.calls += 1;
        assert_eq!(call.payload(), self.expected.as_slice());
        assert_eq!(call.payload_hash(), blake3::hash(&self.expected).as_bytes());
        OutboundSendOutcome::Acked
    }
}

#[test]
fn sender_receives_the_exact_frozen_bytes_that_were_hashed() {
    let (_dir, vault) = open_vault();
    let payload = br#"{"b":2,"a":1}"#.to_vec();
    let mut sender = FrozenBytesSender {
        expected: payload.clone(),
        calls: 0,
    };
    execute_outbound_call(
        &vault,
        descriptor(None, Some(true)),
        request(attempt(10), 0, &payload, 100),
        &mut sender,
    )
    .expect("dispatch");
    assert_eq!(sender.calls, 1);
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payload(), payload.as_slice());
    assert_eq!(records[0].payload_hash, hash_frozen_payload(&payload));
}

#[test]
fn unknown_version_row_escalates_without_drop_or_send() {
    // Recovery must preserve the sole unknown-version row byte-for-byte; an
    // existence-only check would miss an overwrite under the same key.
    let (_dir, vault) = open_vault();
    let id = [0xC7; 32];
    let key = intent_ledger_key(&id);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(
        &mut encoded,
        &Value::Map(vec![(
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(INTENT_LEDGER_SCHEMA_VERSION + 1),
        )]),
    )
    .expect("encode corrupt row");
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, &encoded)
        .expect("put corrupt row");
    wtxn.commit().expect("commit corrupt row");

    let mut sender = CountingSender::default();
    let recovery = recover_outbound_intents(&vault, &mut sender, 200).expect("recovery");
    assert_eq!(recovery.scanned, 1);
    assert_eq!(recovery.escalations.len(), 1);
    assert_eq!(
        recovery.escalations[0],
        IntentEscalation {
            intent_id: Some(id),
            reason: IntentEscalationReason::CorruptLedgerRow,
        }
    );
    assert_eq!(sender.calls, 0);
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let persisted = vault
        .store
        .vault_meta
        .get(&rtxn, &key)
        .expect("read corrupt row")
        .expect("corrupt row preserved");
    assert_eq!(&*persisted, encoded.as_slice());
    let mut row_count = 0usize;
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, INTENT_LEDGER_PRIVATE_PREFIX)
        .expect("iterate intent rows")
    {
        row.expect("intent row");
        row_count += 1;
    }
    assert_eq!(row_count, 1);
}

#[test]
fn greenfield_row_rejects_every_missing_chokepoint_field() {
    let (_dir, vault) = open_vault();
    let pending = persist_pending(&vault, attempt(28), 0, b"strict greenfield", 100, true);
    let key = intent_ledger_key(&pending.id);
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let original = vault
        .store
        .vault_meta
        .get(&rtxn, &key)
        .expect("read canonical row")
        .expect("canonical row")
        .to_vec();
    drop(rtxn);

    for required_key in [
        KEY_BINDING_VERSION,
        KEY_RESOLVED_ENDPOINT,
        KEY_CAPABILITY_PROVENANCE,
        KEY_BUDGET_ACCOUNTING,
        KEY_RECORDED_OUTCOME,
    ] {
        let Value::Map(mut entries) =
            rmpv::decode::read_value(&mut std::io::Cursor::new(&original))
                .expect("decode canonical row")
        else {
            panic!("canonical row must be a map");
        };
        let original_len = entries.len();
        entries.retain(|(candidate, _)| candidate.as_str() != Some(required_key));
        assert_eq!(entries.len() + 1, original_len);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
            .expect("encode missing-field row");
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        vault
            .store
            .vault_meta
            .put(&mut wtxn, &key, &encoded)
            .expect("replace row");
        wtxn.commit().expect("commit missing-field row");
        // The audit listing is per row: the damaged row is reported as corrupt
        // with its exact key and typed error, and is never returned as valid.
        let listing = intent_ledger_records(&vault).expect("listing survives the damaged row");
        assert!(listing.is_empty(), "a damaged row is never listed as valid");
        assert_eq!(listing.corrupt.len(), 1);
        assert_eq!(&*listing.corrupt[0].key, key.as_slice());
        assert!(matches!(
            listing.corrupt[0].error,
            IntentLedgerError::InvalidRecord(_)
        ));
    }
}

#[test]
fn corrupted_idempotency_support_is_rejected_without_resend() {
    // Without the content digest, flipping the one stored false byte to true
    // makes recovery resend and sender.calls becomes one instead of zero.
    let (_dir, vault) = open_vault();
    let pending = persist_pending(
        &vault,
        attempt(15),
        0,
        b"non-idempotent pending",
        100,
        false,
    );
    let key = intent_ledger_key(&pending.id);
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let original = vault
        .store
        .vault_meta
        .get(&rtxn, &key)
        .expect("read pending row")
        .expect("pending row exists")
        .to_vec();
    drop(rtxn);
    let mut encoded = original.clone();
    let field = KEY_IDEMPOTENCY_SUPPORTED.as_bytes();
    let offsets: Vec<usize> = encoded
        .windows(field.len())
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == field).then_some(offset))
        .collect();
    assert_eq!(offsets.len(), 1);
    let stored_boolean = offsets[0] + field.len();
    assert_eq!(encoded[stored_boolean], 0xc2);
    encoded[stored_boolean] = 0xc3;
    assert_eq!(
        original
            .iter()
            .zip(&encoded)
            .filter(|(before, after)| before != after)
            .count(),
        1
    );
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, &encoded)
        .expect("replace pending row");
    wtxn.commit().expect("commit corrupted row");
    force_sync(&vault).expect("sync corrupted row");

    let mut sender = CountingSender::default();
    let recovery = recover_outbound_intents(&vault, &mut sender, 101).expect("recovery");
    assert_eq!(sender.calls, 0);
    assert_eq!(recovery.resent, 0);
    assert_eq!(recovery.escalations.len(), 1);
    assert_eq!(
        recovery.escalations[0],
        IntentEscalation {
            intent_id: Some(pending.id),
            reason: IntentEscalationReason::CorruptLedgerRow,
        }
    );
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let persisted = vault
        .store
        .vault_meta
        .get(&rtxn, &key)
        .expect("read corrupted row")
        .expect("corrupted row retained");
    assert_eq!(&*persisted, encoded.as_slice());
    let mut row_count = 0usize;
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, INTENT_LEDGER_PRIVATE_PREFIX)
        .expect("iterate intent rows")
    {
        row.expect("intent row");
        row_count += 1;
    }
    assert_eq!(row_count, 1);
}

#[test]
fn terminal_state_cannot_be_resurrected() {
    let (_dir, vault) = open_vault();
    let mut sender = CountingSender {
        calls: 0,
        outcome: Some(OutboundSendOutcome::Ambiguous),
    };
    let result = execute_outbound_call(
        &vault,
        descriptor(None, Some(false)),
        request(attempt(11), 0, b"effect", 100),
        &mut sender,
    )
    .expect("dispatch");
    let id = result.intent_id.expect("intent id");
    assert!(matches!(
        transition_record(&vault, id, IntentState::Done, 101),
        Err(IntentLedgerError::InvalidTransition {
            from: IntentState::Abandoned,
            to: IntentState::Done,
        })
    ));
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Abandoned);

    sender.outcome = Some(OutboundSendOutcome::Acked);
    let done = execute_outbound_call(
        &vault,
        descriptor(None, Some(true)),
        request(attempt(11), 1, b"other effect", 102),
        &mut sender,
    )
    .expect("done dispatch");
    let done_id = done.intent_id.expect("done intent id");
    assert!(matches!(
        transition_record(&vault, done_id, IntentState::Pending, 103),
        Err(IntentLedgerError::InvalidTransition {
            from: IntentState::Done,
            to: IntentState::Pending,
        })
    ));
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records
            .iter()
            .filter(|record| record.state == IntentState::Done)
            .count(),
        1
    );
}

#[test]
fn effectful_call_without_authorization_binding_fails_before_send_or_write() {
    let (_dir, vault) = open_vault();
    let mut sender = CountingSender::default();
    let request =
        OutboundCallRequest::new(attempt(12), 0, "server", "tool", b"payload".to_vec(), 1);
    assert!(matches!(
        execute_outbound_call(&vault, descriptor(None, Some(true)), request, &mut sender,),
        Err(IntentLedgerError::InvalidInput(_))
    ));
    assert_eq!(sender.calls, 0);
    assert_eq!(intent_ledger_records(&vault).expect("records").len(), 0);
}

#[test]
fn debug_redacts_raw_payload_from_receipt_and_request() {
    // A derived Debug prints the raw payload Vec; the manual impls must show
    // only a byte count, so a `{:?}` of a receipt or request never leaks the
    // outbound body. The exact derived byte-array rendering must be absent.
    let (_dir, vault) = open_vault();
    let secret: &[u8] = b"SECRET-charge-4242-body";
    let payload_debug = format!("{:?}", secret.to_vec());
    let mut sender = CountingSender::default();
    execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(true)),
        request(attempt(19), 0, secret, 100),
        &mut sender,
    )
    .expect("dispatch");

    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    let record_debug = format!("{:?}", records[0]);
    assert!(record_debug.contains("bytes redacted"));
    assert!(!record_debug.contains(&payload_debug));

    let request_debug = format!("{:?}", request(attempt(19), 0, secret, 100));
    assert!(request_debug.contains("bytes redacted"));
    assert!(!request_debug.contains(&payload_debug));
}

// --- ONE-1885 typed capability provenance serialization ----------------------

fn capability_fixture() -> ScopedCapabilityProvenance {
    ScopedCapabilityProvenance::mint(
        "files",
        &EntityId::from_bytes([0x4D; 16]).expect("grant id"),
    )
    .expect("safe canonical scoped server")
}

fn capability_record(capability: ScopedCapabilityProvenance) -> IntentLedgerRecord {
    let mut request = request(attempt(31), 0, b"capability payload", 100);
    request.server = capability.server().to_owned();
    IntentLedgerRecord::pending(
        request
            .with_resolved_endpoint("https://files.example.test/mcp")
            .with_capability_provenance(capability),
        true,
        BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: 100,
        },
    )
    .expect("pending record")
}

#[test]
fn capability_row_without_resolved_endpoint_is_rejected_before_recovery_send() {
    let (_dir, vault) = open_vault();
    let mut record = capability_record(capability_fixture());
    // Encode a reconstructed v3 row with a self-consistent digest, but with
    // the endpoint that the scoped writer always freezes removed. This bypasses
    // insertion validation so recovery must treat the row as corrupt rather
    // than allowing it to reach a sender.
    record.resolved_endpoint = None;
    let key = intent_ledger_key(&record.id);
    let encoded = encode_record(&record).expect("encode malformed capability row");
    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, &encoded)
        .expect("insert reconstructed row");
    wtxn.commit().expect("commit reconstructed row");

    let mut sender = CountingSender::default();
    let recovery = recover_outbound_intents(&vault, &mut sender, 101).expect("recovery");
    assert_eq!(sender.calls, 0, "invalid capability row must never be sent");
    assert_eq!(recovery.scanned, 1);
    assert_eq!(recovery.resent, 0);
    assert_eq!(recovery.completed, 0);
    assert_eq!(recovery.pending, 0);
    assert_eq!(
        recovery.escalations,
        vec![IntentEscalation {
            intent_id: Some(record.id),
            reason: IntentEscalationReason::CorruptLedgerRow,
        }]
    );
}

#[test]
fn endpoint_bound_row_without_capability_provenance_is_rejected_before_recovery_send() {
    let (_dir, vault) = open_vault();
    let mut record = capability_record(capability_fixture());
    // A reconstructed scoped row may retain its endpoint and binding while the
    // typed discriminator is missing. Encode a self-consistent row directly so
    // recovery must reject it before it can downgrade the call to ordinary.
    record.capability_provenance = None;
    let key = intent_ledger_key(&record.id);
    let encoded = encode_record(&record).expect("encode malformed capability row");
    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, &encoded)
        .expect("insert reconstructed row");
    wtxn.commit().expect("commit reconstructed row");

    let mut sender = CountingSender::default();
    let recovery = recover_outbound_intents(&vault, &mut sender, 101).expect("recovery");
    assert_eq!(sender.calls, 0, "untyped scoped row must never be sent");
    assert_eq!(recovery.scanned, 1);
    assert_eq!(recovery.resent, 0);
    assert_eq!(recovery.completed, 0);
    assert_eq!(recovery.pending, 0);
    assert_eq!(
        recovery.escalations,
        vec![IntentEscalation {
            intent_id: Some(record.id),
            reason: IntentEscalationReason::CorruptLedgerRow,
        }]
    );
}

#[test]
fn capability_row_naming_another_server_is_rejected_before_recovery_send() {
    let (_dir, vault) = open_vault();
    let capability = capability_fixture();
    let mut record = capability_record(capability.clone());
    // A SELF-CONSISTENT forged row: the typed identity is one the engine could
    // really mint and the row digest is recomputed over it, but it names a
    // server this call never went to. Capability provenance is bound to the
    // call's own server, so the row must fail decode and never reach a sender.
    record.capability_provenance = Some(
        ScopedCapabilityProvenance::mint("other", &capability.grant_id())
            .expect("safe canonical scoped server"),
    );
    let key = intent_ledger_key(&record.id);
    let encoded = encode_record(&record).expect("encode forged capability row");
    assert!(matches!(
        decode_record(&key, &encoded),
        Err(IntentLedgerError::InvalidRecord(_))
    ));
    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, &encoded)
        .expect("insert forged row");
    wtxn.commit().expect("commit forged row");

    let mut sender = CountingSender::default();
    let recovery = recover_outbound_intents(&vault, &mut sender, 101).expect("recovery");
    assert_eq!(
        sender.calls, 0,
        "a capability naming another server must never be sent"
    );
    assert_eq!(recovery.scanned, 1);
    assert_eq!(recovery.resent, 0);
    assert_eq!(recovery.completed, 0);
    assert_eq!(recovery.pending, 0);
    assert_eq!(
        recovery.escalations,
        vec![IntentEscalation {
            intent_id: Some(record.id),
            reason: IntentEscalationReason::CorruptLedgerRow,
        }]
    );
}

fn row_with_capability_value(encoded: &[u8], value: Value) -> Vec<u8> {
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut std::io::Cursor::new(encoded)).expect("decode canonical row")
    else {
        panic!("canonical row must be a map");
    };
    for (candidate, slot) in &mut entries {
        if candidate.as_str() == Some(KEY_CAPABILITY_PROVENANCE) {
            *slot = value.clone();
        }
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode tampered row");
    out
}

#[test]
fn capability_provenance_round_trips_and_fails_closed_when_forged() {
    let capability = capability_fixture();
    let record = capability_record(capability.clone());
    let key = intent_ledger_key(&record.id);
    let encoded = encode_record(&record).expect("encode capability row");
    let decoded = decode_record(&key, &encoded).expect("decode capability row");
    assert_eq!(decoded, record);
    assert_eq!(decoded.capability_provenance(), Some(&capability));

    // The typed server is part of the durable call identity. A valid capability
    // minted for another server cannot be transplanted onto this row.
    let mut mismatched_server = record;
    mismatched_server.capability_provenance = Some(
        ScopedCapabilityProvenance::mint("other", &capability.grant_id())
            .expect("safe canonical scoped server"),
    );
    let mismatched_encoded = encode_record(&mismatched_server).expect("encode mismatched row");
    assert!(matches!(
        decode_record(&key, &mismatched_encoded),
        Err(IntentLedgerError::InvalidRecord(_))
    ));

    // An ordinary row stays representable with no capability provenance at all.
    let (_dir, vault) = open_vault();
    let ordinary = persist_pending(&vault, attempt(32), 0, b"ordinary", 100, true);
    assert!(ordinary.capability_provenance().is_none());
    let ordinary_encoded = encode_record(&ordinary).expect("encode ordinary row");
    assert_eq!(
        decode_record(&intent_ledger_key(&ordinary.id), &ordinary_encoded).expect("decode"),
        ordinary
    );

    // The digest binds the typed field: stripping it to Nil is a different row.
    assert!(matches!(
        decode_record(&key, &row_with_capability_value(&encoded, Value::Nil)),
        Err(IntentLedgerError::InvalidRecord(_))
    ));

    // Malformed and unknown provenance forms fail closed, and so does any
    // internally inconsistent identity — a connector that is not EXACTLY what
    // (server, grant) mints can never be read back as a capability.
    let grant_id = capability.grant_id();
    let grant_value = || Value::Binary(grant_id.as_bytes().to_vec());
    for forged in [
        Value::from("mcp:files:grant:0"),
        Value::Map(vec![
            (Value::from(CAPABILITY_PROVENANCE_KEYS[0]), grant_value()),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("files"),
            ),
        ]),
        Value::Map(vec![
            (Value::from(CAPABILITY_PROVENANCE_KEYS[0]), grant_value()),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("files"),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                Value::from(capability.connector()),
            ),
            (Value::from("extra"), Value::Nil),
        ]),
        Value::Map(vec![
            (Value::from(CAPABILITY_PROVENANCE_KEYS[0]), grant_value()),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("Files"),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                Value::from(capability.connector()),
            ),
        ]),
        Value::Map(vec![
            (Value::from(CAPABILITY_PROVENANCE_KEYS[0]), grant_value()),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("files"),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                Value::from("mcp:other:grant:00112233445566778899aabbccddeeff"),
            ),
        ]),
        Value::Map(vec![
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[0]),
                Value::Binary(vec![0x4D; 8]),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("files"),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                Value::from(capability.connector()),
            ),
        ]),
    ] {
        assert!(
            matches!(
                decode_record(&key, &row_with_capability_value(&encoded, forged.clone())),
                Err(IntentLedgerError::InvalidRecord(_))
            ),
            "forged capability provenance {forged:?} must fail closed"
        );
    }
}

// --- ONE-1769 digest preimage, storage ABI, and tolerant listing -------------

/// Writes one raw `vault_meta` row, bypassing every encoder, so a former-format
/// or damaged row can be observed exactly as a crashed device would leave it.
fn put_raw_row(vault: &Vault, key: &[u8], row: &[u8]) {
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, key, row)
        .expect("put raw row");
    wtxn.commit().expect("commit raw row");
}

fn raw_row(vault: &Vault, key: &[u8]) -> Vec<u8> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let raw = vault
        .store
        .vault_meta
        .get(&rtxn, key)
        .expect("read raw row")
        .expect("raw row exists")
        .to_vec();
    drop(rtxn);
    raw
}

fn row_entries(encoded: &[u8]) -> Vec<(Value, Value)> {
    let Value::Map(entries) =
        rmpv::decode::read_value(&mut std::io::Cursor::new(encoded)).expect("decode row")
    else {
        panic!("an intent row must be a map");
    };
    entries
}

fn encode_entries(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).expect("encode row");
    encoded
}

fn row_with_content_digest(encoded: &[u8], digest: [u8; 32]) -> Vec<u8> {
    let mut entries = row_entries(encoded);
    for (candidate, slot) in &mut entries {
        if candidate.as_str() == Some(KEY_CONTENT_DIGEST) {
            *slot = Value::Binary(digest.to_vec());
        }
    }
    encode_entries(entries)
}

/// The typed reason one row was reported corrupt, so a listing assertion names
/// the failure it means instead of accepting any error at all.
fn corrupt_reason(row: &IntentLedgerCorruptRow) -> &'static str {
    match row.error {
        IntentLedgerError::InvalidRecord(reason) => reason,
        ref other => panic!("a corrupt row must be an invalid record, not {other:?}"),
    }
}

#[test]
fn content_digest_is_hash_of_msgpack_minus_digest_key() {
    // The preimage IS the stored body minus one key. Rebuilding it here from
    // the persisted bytes — without calling the production digest — is what
    // catches a future second body representation.
    let (_dir, vault) = open_vault();
    let payload: &[u8] = b"digest preimage payload";
    let record = persist_pending(&vault, attempt(41), 0, payload, 100, true);
    let raw = raw_row(&vault, &intent_ledger_key(&record.id));

    let mut entries = row_entries(&raw);
    let stored_keys: Vec<&str> = entries
        .iter()
        .map(|(key, _)| key.as_str().expect("row keys are strings"))
        .collect();
    assert_eq!(stored_keys, INTENT_LEDGER_VALUE_KEYS);

    let (digest_key, digest_value) = entries.pop().expect("the row carries a final entry");
    assert_eq!(digest_key.as_str(), Some(KEY_CONTENT_DIGEST));
    let Value::Binary(stored_digest) = digest_value else {
        panic!("the stored content digest must be binary");
    };
    assert_eq!(stored_digest.len(), 32);
    assert_eq!(entries.len(), 19);

    let preimage = encode_entries(entries);
    // A 19-entry map is `map16`: the map header itself is inside the preimage.
    assert_eq!(preimage[..3], [0xde, 0x00, 0x13]);
    let width = payload.len();
    assert!(
        preimage.windows(width).any(|window| window == payload),
        "the raw payload rides the preimage"
    );
    assert_eq!(blake3::hash(&preimage).as_bytes()[..], stored_digest[..]);
    assert_eq!(
        encode_record_digest_preimage(&record).expect("preimage"),
        preimage
    );
    assert_eq!(
        record_content_digest(&record).expect("digest")[..],
        stored_digest[..]
    );
}

/// Hand-typed storage ABI of one persisted intent row. These literals are
/// deliberately NOT read from `INTENT_LEDGER_VALUE_KEYS` or recomputed from the
/// encoder: producer and expectation must be able to disagree, or a co-drifting
/// change would rewrite both sides at once. Pre-launch, a deliberate ABI change
/// re-pins them with a stated rationale.
const GOLDEN_ROW_KEYS: [&str; 20] = [
    "schema_version",
    "id",
    "attempt_id",
    "call_seq",
    "server",
    "tool",
    "payload_hash",
    "payload",
    "idempotency_key",
    "idempotency_supported",
    "authorization_binding",
    "binding_version",
    "resolved_endpoint",
    "capability_provenance",
    "budget_accounting",
    "recorded_outcome",
    "state",
    "created_ms",
    "updated_ms",
    "content_digest",
];
const GOLDEN_ATTEMPT_BYTE: u8 = 0x2B;
const GOLDEN_CALL_SEQ: u64 = 7;
const GOLDEN_PAYLOAD: &[u8] = b"golden fixture payload";
const GOLDEN_NOW_MS: u64 = 1_700_000_000_000;
/// The identity this fixture's attempt, sequence, server, tool, and payload
/// hash derive, in lowercase hex.
const GOLDEN_INTENT_ID_HEX: &str =
    "311135d83a39aeef442248566c71583daf41968a7e78ca7688da8119259086d3";
/// BLAKE3 of the 19-entry MessagePack body of that row at schema version 3.
const GOLDEN_CONTENT_DIGEST_HEX: &str =
    "770b0b4308af5fa80600143e4620adb0d5e5360c345905b404f38343bb0084c0";

#[test]
fn storage_abi_golden_fixture() {
    let (_dir, vault) = open_vault();
    let record = persist_pending(
        &vault,
        attempt(GOLDEN_ATTEMPT_BYTE),
        GOLDEN_CALL_SEQ,
        GOLDEN_PAYLOAD,
        GOLDEN_NOW_MS,
        true,
    );
    // Identity is pinned beside the row: the keyspace and the id it addresses
    // rows by cannot drift apart unnoticed.
    assert_eq!(
        derive_intent_id(
            attempt(GOLDEN_ATTEMPT_BYTE),
            GOLDEN_CALL_SEQ,
            "test-server",
            "test-tool",
            &hash_frozen_payload(GOLDEN_PAYLOAD),
        )
        .expect("golden identity"),
        record.id
    );
    assert_eq!(bytes_to_hex_lower(&record.id), GOLDEN_INTENT_ID_HEX);

    let entries = row_entries(&raw_row(&vault, &intent_ledger_key(&record.id)));
    let stored_keys: Vec<&str> = entries
        .iter()
        .map(|(key, _)| key.as_str().expect("row keys are strings"))
        .collect();
    assert_eq!(stored_keys, GOLDEN_ROW_KEYS);
    let Some((_, Value::Binary(stored_digest))) = entries.last() else {
        panic!("the final entry is the binary content digest");
    };
    assert_eq!(bytes_to_hex_lower(stored_digest), GOLDEN_CONTENT_DIGEST_HEX);
}

#[test]
fn record_content_digest_has_no_json_detour() {
    // The requirement is about REACHABILITY, not one function body: the digest
    // path must not reach canonical JSON through any callee, in any function
    // order. `derive_intent_id` is the sole exception — it hashes the shipped
    // identity preimage — so its body is sliced out and everything that remains
    // must be JSON-free.
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/outbound_intent_ledger.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {} must succeed: {err}", path.display()));
    let start = src
        .find("\npub fn derive_intent_id(")
        .expect("the identity derivation must be findable by its signature")
        + 1;
    let end = start
        + src[start..]
            .find("\n}\n")
            .expect("the identity derivation must terminate")
        + "\n}\n".len();
    let identity = &src[start..end];
    assert!(
        identity.contains("canonical_hash(&IntentIdentity {"),
        "the sliced body must be the identity derivation itself"
    );
    let remainder = format!("{}{}", &src[..start], &src[end..]);
    assert!(
        remainder.contains("fn record_content_digest("),
        "the remainder must still hold the digest path being audited"
    );
    for token in ["canonical_hash", "canonicalize_json", "serde_json"] {
        assert!(
            identity.contains(token),
            "{token} must remain inside derive_intent_id"
        );
        assert!(
            !remainder.contains(token),
            "{token} is reachable outside derive_intent_id"
        );
    }
}

#[test]
fn content_digest_is_stable_for_one_logical_record() {
    let (_dir, vault) = open_vault();
    let payload: &[u8] = b"stable digest payload";
    let persisted = persist_pending(&vault, attempt(42), 3, payload, 500, true);
    // Built through a different constructor, never read back from storage.
    let rebuilt = IntentLedgerRecord::pending(
        request(attempt(42), 3, payload, 500),
        true,
        BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: 500,
        },
    )
    .expect("independently built record");
    assert_eq!(persisted, rebuilt);
    assert_eq!(
        encode_record_digest_preimage(&persisted).expect("persisted preimage"),
        encode_record_digest_preimage(&rebuilt).expect("rebuilt preimage")
    );
    assert_eq!(
        record_content_digest(&persisted).expect("persisted digest"),
        record_content_digest(&rebuilt).expect("rebuilt digest")
    );

    // Entry order in a raw row is not the canonical order: a reordered but
    // otherwise equivalent map decodes to the same record and re-encodes to the
    // same canonical bytes and digest.
    let key = intent_ledger_key(&persisted.id);
    let canonical = encode_record(&persisted).expect("encode canonical row");
    let mut entries = row_entries(&canonical);
    entries.reverse();
    let reordered = encode_entries(entries);
    assert_ne!(reordered, canonical);
    let decoded = decode_record(&key, &reordered).expect("a reordered row still decodes");
    assert_eq!(decoded, persisted);
    assert_eq!(encode_record(&decoded).expect("re-encode"), canonical);
    assert_eq!(
        record_content_digest(&decoded).expect("reordered digest"),
        record_content_digest(&persisted).expect("canonical digest")
    );
}

const OTHER_BINDING: OutboundAuthorizationBinding = OutboundAuthorizationBinding::new([0x5A; 32]);

/// Applies one mutation and re-establishes the identity fields it moves, so
/// every mutated fixture is still a row this engine could have written. A field
/// is digest-bound only if a row the engine ACCEPTS still gets another digest.
fn mutated(
    base: &IntentLedgerRecord,
    change: impl FnOnce(&mut IntentLedgerRecord),
) -> IntentLedgerRecord {
    let mut record = base.clone();
    change(&mut record);
    record.payload_hash = hash_frozen_payload(record.payload());
    record.id = derive_intent_id(
        record.attempt_id,
        record.call_seq,
        &record.server,
        &record.tool,
        &record.payload_hash,
    )
    .expect("mutated identity");
    record.idempotency_key = bytes_to_hex_lower(&record.id);
    record
}

#[test]
fn every_body_field_is_digest_bound() {
    let (_dir, vault) = open_vault();
    let base = persist_pending(&vault, attempt(50), 11, b"digest binding", 1_000, true);
    let capability = capability_fixture();
    let scoped = capability_record(capability.clone());
    let other_grant = EntityId::from_bytes([0x5E; 16]).expect("other grant id");

    // Fields coupled by validation move together; the case names the body keys
    // it moves so the table can prove it covers every one of them.
    let cases: Vec<(&str, Vec<&str>, IntentLedgerRecord, IntentLedgerRecord)> = vec![
        (
            "attempt_id",
            vec![KEY_ID, KEY_ATTEMPT_ID, KEY_IDEMPOTENCY_KEY],
            base.clone(),
            mutated(&base, |record| record.attempt_id = attempt(51)),
        ),
        (
            "call_seq",
            vec![KEY_CALL_SEQ],
            base.clone(),
            mutated(&base, |record| record.call_seq = 12),
        ),
        (
            "server",
            vec![KEY_SERVER],
            base.clone(),
            mutated(&base, |record| record.server = "other".to_owned()),
        ),
        (
            "tool",
            vec![KEY_TOOL],
            base.clone(),
            mutated(&base, |record| record.tool = "other".to_owned()),
        ),
        (
            "payload",
            vec![KEY_PAYLOAD, KEY_PAYLOAD_HASH],
            base.clone(),
            mutated(&base, |record| record.payload = b"other body".to_vec()),
        ),
        (
            "idempotency_supported",
            vec![KEY_IDEMPOTENCY_SUPPORTED],
            base.clone(),
            mutated(&base, |record| record.idempotency_supported = false),
        ),
        (
            "authorization_binding",
            vec![KEY_AUTHORIZATION_BINDING],
            base.clone(),
            mutated(&base, |record| {
                record.authorization_binding = Some(OTHER_BINDING);
            }),
        ),
        (
            "budget key_ref, matched_rows, and sends_debit",
            vec![KEY_BUDGET_ACCOUNTING],
            base.clone(),
            mutated(&base, |record| {
                record.budget_accounting.key_ref =
                    Some(EntityId::from_bytes([0x77; 16]).expect("budget key ref"));
                record.budget_accounting.matched_rows = vec![1, 2];
                record.budget_accounting.sends_debit = 1;
            }),
        ),
        (
            "budget_class",
            vec![KEY_BUDGET_ACCOUNTING],
            base.clone(),
            mutated(&base, |record| {
                record.budget_accounting.budget_class = BudgetClass::Operation;
            }),
        ),
        (
            "budget accounted_at_ms",
            vec![KEY_BUDGET_ACCOUNTING],
            base.clone(),
            mutated(&base, |record| {
                record.budget_accounting.accounted_at_ms = 2_000;
            }),
        ),
        (
            "state and recorded_outcome",
            vec![KEY_STATE, KEY_RECORDED_OUTCOME],
            base.clone(),
            mutated(&base, |record| {
                record.state = IntentState::Done;
                record.recorded_outcome = Some(RecordedOutboundOutcome::Acked);
            }),
        ),
        (
            "created_ms",
            vec![KEY_CREATED_MS],
            base.clone(),
            mutated(&base, |record| record.created_ms = 900),
        ),
        (
            "updated_ms",
            vec![KEY_UPDATED_MS],
            base.clone(),
            mutated(&base, |record| record.updated_ms = 1_100),
        ),
        (
            "capability provenance stripped with its endpoint",
            vec![KEY_RESOLVED_ENDPOINT, KEY_CAPABILITY_PROVENANCE],
            scoped.clone(),
            mutated(&scoped, |record| {
                record.resolved_endpoint = None;
                record.capability_provenance = None;
            }),
        ),
        (
            "capability provenance swapped for another grant",
            vec![KEY_CAPABILITY_PROVENANCE],
            scoped.clone(),
            mutated(&scoped, |record| {
                record.capability_provenance = Some(
                    ScopedCapabilityProvenance::mint(capability.server(), &other_grant)
                        .expect("safe canonical scoped server"),
                );
            }),
        ),
    ];

    let mut covered: HashSet<&str> = HashSet::new();
    for (label, keys, case_base, case_mutated) in cases {
        for key in keys {
            assert!(
                INTENT_LEDGER_VALUE_KEYS[..19].contains(&key),
                "{label} names a key outside the digest preimage"
            );
            covered.insert(key);
        }
        let base_digest = record_content_digest(&case_base).expect("base digest");
        let moved_digest = record_content_digest(&case_mutated).expect("mutated digest");
        assert_ne!(base_digest, moved_digest, "{label} must move the digest");
        assert_ne!(
            encode_record_digest_preimage(&case_base).expect("base preimage"),
            encode_record_digest_preimage(&case_mutated).expect("moved preimage"),
            "{label} must move the digest preimage"
        );
        let key = intent_ledger_key(&case_mutated.id);
        let encoded = encode_record(&case_mutated).expect("encode mutated row");
        assert_eq!(
            decode_record(&key, &encoded).expect("the mutated row is itself valid"),
            case_mutated,
            "{label} must stay a row this engine could write"
        );
        let spliced = row_with_content_digest(&encoded, base_digest);
        assert!(
            matches!(
                decode_record(&key, &spliced),
                Err(IntentLedgerError::InvalidRecord(_))
            ),
            "{label} must fail decode once the unmutated digest is spliced in"
        );
    }

    // Keys 0 and 11 are digest-bound STRUCTURALLY, not mutationally: no valid
    // row can carry another schema_version or binding_version, so the fixture
    // pins their byte-exact preimage entries instead of mutating them.
    assert_eq!(INTENT_LEDGER_SCHEMA_VERSION, 3);
    assert_eq!(OUTBOUND_BINDING_VERSION, 2);
    let preimage = encode_record_digest_preimage(&base).expect("base preimage");
    for (key, value) in [("schema_version", 3_u64), ("binding_version", 2_u64)] {
        let mut entry = Vec::new();
        rmpv::encode::write_value(&mut entry, &Value::from(key)).expect("encode pinned key");
        rmpv::encode::write_value(&mut entry, &Value::from(value)).expect("encode pinned value");
        assert!(
            preimage
                .windows(entry.len())
                .any(|window| window == entry.as_slice()),
            "the preimage must carry a byte-exact ({key}, {value}) entry"
        );
    }

    let expected: HashSet<&str> = INTENT_LEDGER_VALUE_KEYS[..19]
        .iter()
        .copied()
        .filter(|key| *key != KEY_SCHEMA_VERSION && *key != KEY_BINDING_VERSION)
        .collect();
    assert_eq!(covered, expected, "every body key needs a mutation case");
    assert_eq!(covered.len(), 17, "19 body keys minus 2 structural ones");
}

/// The FORMER canonical-JSON content digest, reconstructed locally. Production
/// must never carry a second body representation; a test may, and this copy is
/// the only way to seed a row in the exact format this change retires.
fn legacy_json_content_digest(record: &IntentLedgerRecord) -> [u8; 32] {
    use std::collections::BTreeMap;

    use serde::Serialize;
    use serde_json::{Map as JsonMap, Value as JsonValue};

    #[derive(Serialize)]
    struct LegacyRecordContent<'a> {
        schema_version: u64,
        id: &'a [u8; 32],
        attempt_id: &'a [u8; 16],
        call_seq: u64,
        server: &'a str,
        tool: &'a str,
        payload_hash: &'a [u8; 32],
        idempotency_key: &'a str,
        idempotency_supported: bool,
        authorization_binding: Option<&'a [u8; 32]>,
        binding_version: u64,
        resolved_endpoint: Option<&'a str>,
        budget_key_ref: Option<&'a [u8; 16]>,
        budget_class: &'a str,
        budget_matched_rows: &'a [u16],
        budget_sends_debit: u64,
        budget_accounted_at_ms: u64,
        recorded_outcome: Option<&'a str>,
        recorded_outcome_reason: Option<&'a str>,
        state: &'a str,
        created_ms: u64,
        updated_ms: u64,
    }

    fn canonicalize(value: JsonValue) -> JsonValue {
        match value {
            JsonValue::Array(values) => {
                JsonValue::Array(values.into_iter().map(canonicalize).collect())
            }
            JsonValue::Object(entries) => {
                let mut sorted = BTreeMap::new();
                for (key, value) in entries {
                    sorted.insert(key, canonicalize(value));
                }
                let mut canonical = JsonMap::new();
                for (key, value) in sorted {
                    canonical.insert(key, value);
                }
                JsonValue::Object(canonical)
            }
            scalar => scalar,
        }
    }

    let content = LegacyRecordContent {
        schema_version: 2,
        id: &record.id,
        attempt_id: record.attempt_id.as_bytes(),
        call_seq: record.call_seq,
        server: &record.server,
        tool: &record.tool,
        payload_hash: &record.payload_hash,
        idempotency_key: &record.idempotency_key,
        idempotency_supported: record.idempotency_supported,
        authorization_binding: record
            .authorization_binding
            .as_ref()
            .map(OutboundAuthorizationBinding::as_bytes),
        binding_version: record.binding_version,
        resolved_endpoint: record.resolved_endpoint.as_deref(),
        budget_key_ref: record
            .budget_accounting
            .key_ref
            .as_ref()
            .map(EntityId::as_bytes),
        budget_class: record.budget_accounting.budget_class.as_str(),
        budget_matched_rows: &record.budget_accounting.matched_rows,
        budget_sends_debit: record.budget_accounting.sends_debit,
        budget_accounted_at_ms: record.budget_accounting.accounted_at_ms,
        recorded_outcome: record.recorded_outcome.map(|outcome| match outcome {
            RecordedOutboundOutcome::DefiniteNonDelivery => "definite_non_delivery",
            RecordedOutboundOutcome::Acked => "acked",
            RecordedOutboundOutcome::Abandoned(_) => "abandoned",
        }),
        recorded_outcome_reason: record.recorded_outcome.and_then(|outcome| match outcome {
            RecordedOutboundOutcome::DefiniteNonDelivery | RecordedOutboundOutcome::Acked => None,
            RecordedOutboundOutcome::Abandoned(reason) => Some(reason.as_str()),
        }),
        state: record.state.as_str(),
        created_ms: record.created_ms,
        updated_ms: record.updated_ms,
    };
    let value = serde_json::to_value(&content).expect("legacy canonical value");
    let bytes = serde_json::to_vec(&canonicalize(value)).expect("legacy canonical bytes");
    *blake3::hash(&bytes).as_bytes()
}

#[test]
fn old_json_digest_is_flagged_not_accepted() {
    // Pre-launch posture: no grandfather path, no dual verifier, no migration.
    // A former-format row is EVIDENCE of damage, never an accepted record.
    let (_dir, vault) = open_vault();
    let record = persist_pending(&vault, attempt(60), 0, b"former format", 300, true);
    let key = intent_ledger_key(&record.id);
    let canonical = raw_row(&vault, &key);
    let legacy_digest = legacy_json_content_digest(&record);
    assert_ne!(
        legacy_digest,
        record_content_digest(&record).expect("current digest"),
        "the retired JSON digest is not the MessagePack digest"
    );

    let json_digest_row = row_with_content_digest(&canonical, legacy_digest);
    put_raw_row(&vault, &key, &json_digest_row);
    assert!(matches!(
        read_intent_record(&vault, &record.id),
        Err(IntentLedgerError::InvalidRecord(_))
    ));
    let listing = intent_ledger_records(&vault).expect("listing sees the row");
    assert!(listing.is_empty(), "no fallback accepts a JSON digest");
    assert_eq!(listing.corrupt.len(), 1);
    assert_eq!(&*listing.corrupt[0].key, key.as_slice());
    assert_eq!(
        corrupt_reason(&listing.corrupt[0]),
        "outbound intent content digest mismatch"
    );
    assert_eq!(
        raw_row(&vault, &key),
        json_digest_row,
        "the listing observes the row, it never rewrites it"
    );

    // The same row as a full v2 row: old schema version, no typed capability
    // provenance, old digest. Corrupt evidence, not a readable record.
    let mut entries = row_entries(&canonical);
    entries.retain(|(candidate, _)| candidate.as_str() != Some(KEY_CAPABILITY_PROVENANCE));
    for (candidate, slot) in &mut entries {
        if candidate.as_str() == Some(KEY_SCHEMA_VERSION) {
            *slot = Value::from(2_u64);
        }
        if candidate.as_str() == Some(KEY_CONTENT_DIGEST) {
            *slot = Value::Binary(legacy_digest.to_vec());
        }
    }
    let v2_row = encode_entries(entries);
    put_raw_row(&vault, &key, &v2_row);
    assert!(matches!(
        read_intent_record(&vault, &record.id),
        Err(IntentLedgerError::InvalidRecord(_))
    ));
    let listing = intent_ledger_records(&vault).expect("listing sees the v2 row");
    assert!(listing.is_empty());
    assert_eq!(listing.corrupt.len(), 1);
    assert_eq!(
        corrupt_reason(&listing.corrupt[0]),
        "unsupported outbound intent schema_version"
    );
}

#[test]
fn listing_is_per_row_tolerant() {
    let (_dir, vault) = open_vault();
    let mut valid = Vec::new();
    for index in 0..3u8 {
        let row = persist_pending(&vault, attempt(100 + index), 0, b"tolerant", 100, true);
        valid.push(row);
    }
    // The lowest possible id sorts this damaged row FIRST under the private
    // prefix: a fail-closed listing would return nothing at all.
    let corrupt_key = intent_ledger_key(&[0x00; 32]);
    let corrupt_row: &[u8] = &[0xde, 0x00];
    put_raw_row(&vault, &corrupt_key, corrupt_row);

    let listing = intent_ledger_records(&vault).expect("listing tolerates the row");
    assert_eq!(listing.len(), valid.len());
    assert_eq!(listing.corrupt.len(), 1);
    assert_eq!(&*listing.corrupt[0].key, corrupt_key.as_slice());
    assert_eq!(
        corrupt_reason(&listing.corrupt[0]),
        "outbound intent MessagePack decode failed"
    );
    for record in &listing.records {
        assert!(
            intent_ledger_key(&record.id) > corrupt_key,
            "the damaged row precedes every valid row in the walk"
        );
    }
    let mut listed: Vec<[u8; 32]> = listing.iter().map(|record| record.id).collect();
    listed.sort_unstable();
    let mut expected: Vec<[u8; 32]> = valid.iter().map(|record| record.id).collect();
    expected.sort_unstable();
    assert_eq!(listed, expected);
    assert_eq!(
        raw_row(&vault, &corrupt_key),
        corrupt_row,
        "the corrupt row stays byte-identical in storage"
    );
}

#[test]
fn listing_tolerates_multiple_independent_failures() {
    let (_dir, vault) = open_vault();
    let first = persist_pending(&vault, attempt(110), 0, b"multi one", 100, true);
    let second = persist_pending(&vault, attempt(111), 0, b"multi two", 100, true);
    let canonical = raw_row(&vault, &intent_ledger_key(&first.id));

    let unknown_version = {
        let mut entries = row_entries(&canonical);
        for (candidate, slot) in &mut entries {
            if candidate.as_str() == Some(KEY_SCHEMA_VERSION) {
                *slot = Value::from(INTENT_LEDGER_SCHEMA_VERSION + 1);
            }
        }
        encode_entries(entries)
    };
    let missing_field = {
        let mut entries = row_entries(&canonical);
        entries.retain(|(candidate, _)| candidate.as_str() != Some(KEY_STATE));
        encode_entries(entries)
    };
    let duplicate_key = {
        let mut entries = row_entries(&canonical);
        let repeated = entries
            .iter()
            .find(|(candidate, _)| candidate.as_str() == Some(KEY_STATE))
            .cloned()
            .expect("the canonical row carries a state entry");
        entries.push(repeated);
        encode_entries(entries)
    };
    let digest_mismatch = row_with_content_digest(&canonical, [0xEE; 32]);
    let malformed = vec![0xde, 0x00];

    // Five rows, five independent causes, all keyed below the valid rows.
    let damaged = [
        (0x00u8, malformed),
        (0x01, unknown_version),
        (0x02, missing_field),
        (0x03, duplicate_key),
        (0x04, digest_mismatch),
    ];
    let reasons = [
        "outbound intent MessagePack decode failed",
        "unsupported outbound intent schema_version",
        "missing outbound intent state",
        "duplicate outbound intent key",
        "outbound intent content digest mismatch",
    ];
    let mut expected = Vec::new();
    for ((id_byte, row), reason) in damaged.into_iter().zip(reasons) {
        let key = intent_ledger_key(&[id_byte; 32]);
        put_raw_row(&vault, &key, &row);
        expected.push((key, reason));
    }

    let listing = intent_ledger_records(&vault).expect("listing survives five rows");
    assert_eq!(listing.corrupt.len(), 5);
    for (corrupt, (key, reason)) in listing.corrupt.iter().zip(expected) {
        assert_eq!(&*corrupt.key, key.as_slice());
        assert_eq!(
            corrupt_reason(corrupt),
            reason,
            "each damaged row must fail for its own reason"
        );
    }
    let mut listed: Vec<[u8; 32]> = listing.iter().map(|record| record.id).collect();
    listed.sort_unstable();
    let mut expected_ids = vec![first.id, second.id];
    expected_ids.sort_unstable();
    assert_eq!(listed, expected_ids, "later valid rows stay visible");
}

#[test]
fn listing_storage_errors_stay_top_level_by_construction() {
    // Tolerance is for row damage, never for an unavailable substrate. The
    // guard is structural because the byte-identical iteration line also lives
    // in the recovery walks, so a whole-file `contains` would prove nothing —
    // and no LMDB fault-injection harness exists or is wanted.
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/outbound_intent_ledger.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {} must succeed: {err}", path.display()));
    let iteration = "let (key, value) = row?;";
    assert!(
        src.matches(iteration).count() >= 2,
        "the recovery walks share this line, which is why the scan slices"
    );
    let start = src
        .find("\npub fn intent_ledger_records(")
        .expect("the listing must be findable by its signature")
        + 1;
    let end = start
        + src[start..]
            .find("\n}\n")
            .expect("the listing must terminate")
        + "\n}\n".len();
    let body = &src[start..end];
    assert!(
        body.contains("read_txn().map_err(Error::from)?"),
        "opening the read transaction stays a top-level error"
    );
    assert!(
        body.contains("prefix_iter(&rtxn, INTENT_LEDGER_PRIVATE_PREFIX)?"),
        "creating the prefix iterator stays a top-level error"
    );
    let iteration_at = body
        .find(iteration)
        .expect("advancing a failed iterator stays a top-level error");
    let tolerance_at = body
        .find("match decode_record(&key, &value)")
        .expect("per-row tolerance must be a decode match");
    assert!(
        iteration_at < tolerance_at,
        "the storage error propagates BEFORE any per-row tolerance"
    );
}

#[test]
fn deref_len_counts_valid_rows_only() {
    let (_dir, vault) = open_vault();
    let mut valid = Vec::new();
    for index in 0..3u8 {
        let row = persist_pending(&vault, attempt(120 + index), 0, b"deref", 100, true);
        valid.push(row);
    }
    put_raw_row(&vault, &intent_ledger_key(&[0x00; 32]), &[0xde, 0x00]);
    let mut expected: Vec<[u8; 32]> = valid.iter().map(|record| record.id).collect();
    expected.sort_unstable();

    let listing = intent_ledger_records(&vault).expect("listing");
    assert_eq!(listing.len(), valid.len());
    assert_eq!(listing.corrupt.len(), 1);
    assert!(!listing.is_empty());
    assert_eq!(
        listing.first().map(|record| record.state),
        Some(IntentState::Pending)
    );
    // Consuming iteration yields the valid rows and drops the corrupt ones.
    let mut owned: Vec<[u8; 32]> = listing.into_iter().map(|record| record.id).collect();
    owned.sort_unstable();
    assert_eq!(owned, expected);
}

#[test]
fn recovery_walk_is_unchanged() {
    let (_dir, vault) = open_vault();
    let first = persist_pending(&vault, attempt(70), 0, b"recovery one", 100, true);
    let second = persist_pending(&vault, attempt(71), 0, b"recovery two", 100, true);
    let corrupt_key = intent_ledger_key(&[0x00; 32]);
    let corrupt_row: &[u8] = &[0xde, 0x00];
    put_raw_row(&vault, &corrupt_key, corrupt_row);

    let mut sender = CountingSender::default();
    let recovery = recover_outbound_intents(&vault, &mut sender, 200).expect("recovery");
    assert_eq!(recovery.scanned, 3, "recovery still scans every row");
    assert_eq!(recovery.resent, 2);
    assert_eq!(recovery.completed, 2);
    assert_eq!(sender.calls, 2, "the corrupt row is never sent");
    assert_eq!(
        recovery.escalations,
        vec![IntentEscalation {
            intent_id: Some([0x00; 32]),
            reason: IntentEscalationReason::CorruptLedgerRow,
        }],
        "one CorruptLedgerRow escalation per corrupt row, unchanged"
    );

    let listing = intent_ledger_records(&vault).expect("listing after recovery");
    assert_eq!(listing.corrupt.len(), 1);
    for record in &listing.records {
        assert_eq!(record.state, IntentState::Done);
    }
    let mut listed: Vec<[u8; 32]> = listing.iter().map(|record| record.id).collect();
    listed.sort_unstable();
    let mut expected = vec![first.id, second.id];
    expected.sort_unstable();
    assert_eq!(listed, expected);
    assert_eq!(raw_row(&vault, &corrupt_key), corrupt_row);
}

#[test]
fn strict_targeted_reads_remain_strict() {
    let (_dir, vault) = open_vault();
    let payload: &[u8] = b"strict target payload";
    let target = persist_pending(&vault, attempt(80), 0, payload, 100, true);
    let neighbour = persist_pending(&vault, attempt(81), 0, b"neighbour", 100, true);
    let key = intent_ledger_key(&target.id);
    let damaged = row_with_content_digest(&raw_row(&vault, &key), [0xEE; 32]);
    put_raw_row(&vault, &key, &damaged);

    assert!(matches!(
        read_intent_record(&vault, &target.id),
        Err(IntentLedgerError::InvalidRecord(_))
    ));
    assert!(matches!(
        transition_record(&vault, target.id, IntentState::Done, 101),
        Err(IntentLedgerError::InvalidRecord(_))
    ));
    // Replay re-reads the targeted row and refuses: listing tolerance is
    // observation, never execution authority.
    let mut sender = CountingSender::default();
    assert!(matches!(
        execute_outbound_call(
            &vault,
            descriptor(None, Some(true)),
            request(attempt(80), 0, payload, 102),
            &mut sender,
        ),
        Err(IntentLedgerError::InvalidRecord(_))
    ));
    assert_eq!(sender.calls, 0);

    let listing = intent_ledger_records(&vault).expect("listing");
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].id, neighbour.id);
    assert_eq!(listing.corrupt.len(), 1);
    assert_eq!(&*listing.corrupt[0].key, key.as_slice());
}
