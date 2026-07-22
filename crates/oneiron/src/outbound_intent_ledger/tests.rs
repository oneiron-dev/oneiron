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
        assert!(matches!(
            intent_ledger_records(&vault),
            Err(IntentLedgerError::InvalidRecord(_))
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
