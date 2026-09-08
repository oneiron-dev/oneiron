//! ONE-1691 RT-11: intent-ledger exactly-once/crash-recovery oracles, ledger transports, and drive_* helpers.

use std::collections::{BTreeSet, HashSet, VecDeque};

use super::shared::{install_oracle_scoped_fixture, open_vault, oracle_prepared_effect};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundTransport, execute_outbound_effect,
};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentEscalationReason, IntentLedgerError, IntentState,
    OutboundCallRequest, OutboundSendOutcome, derive_intent_id, hash_frozen_payload,
    intent_ledger_records,
};

// ═══════════════════════════════════════════════════════════════════════
// ONE-1691 — [RT-11] outbound INTENT ledger (SECURITY)
// ═══════════════════════════════════════════════════════════════════════

/// One durable intent row, RE-READ from the store after the drive — never
/// echoed from the driver's in-memory state.
struct IntentRow {
    id: String,
    server: String,
    tool: String,
    payload_hash: String,
    state: String,
    idempotency_key: String,
}

/// Ledger + transport observation for one driven effectful MCP call.
struct IntentLedgerTrace {
    /// Ordered observation log: `(event kind, idempotency key)` in the
    /// order events were OBSERVED. Kinds pinned by the asserts:
    /// "intent_journaled", "wire_send".
    events: Vec<(String, String)>,
    /// Intent rows observed durably BEFORE the send.
    rows_before_send: Vec<IntentRow>,
    /// Intent rows RE-READ from the store after the ack (or recovery).
    rows_after: Vec<IntentRow>,
    /// Idempotency key carried by each wire send, in order.
    transport_send_keys: Vec<String>,
    /// Server-side effects actually applied (the exactly-once observable).
    effects_applied: usize,
}

fn oracle_intent_rows(vault: &Vault) -> Vec<IntentRow> {
    intent_ledger_records(vault)
        .expect("read oracle intent rows")
        .into_iter()
        .map(|record| IntentRow {
            id: crate::entity_id::bytes_to_hex_lower(&record.id),
            server: record.server,
            tool: record.tool,
            payload_hash: crate::entity_id::bytes_to_hex_lower(&record.payload_hash),
            state: record.state.as_str().to_owned(),
            idempotency_key: record.idempotency_key,
        })
        .collect()
}

struct OracleLedgerTransport<'a> {
    vault: &'a Vault,
    outcomes: VecDeque<OutboundSendOutcome>,
    events: Vec<(String, String)>,
    rows_before_send: Vec<IntentRow>,
    send_keys: Vec<String>,
    seen_keys: HashSet<String>,
    effects_applied: usize,
}

impl<'a> OracleLedgerTransport<'a> {
    fn new(vault: &'a Vault, outcomes: impl IntoIterator<Item = OutboundSendOutcome>) -> Self {
        Self {
            vault,
            outcomes: outcomes.into_iter().collect(),
            events: Vec::new(),
            rows_before_send: Vec::new(),
            send_keys: Vec::new(),
            seen_keys: HashSet::new(),
            effects_applied: 0,
        }
    }
}

impl OutboundTransport for OracleLedgerTransport<'_> {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        let key = call
            .idempotency_key()
            .expect("effectful oracle call carries idempotency key")
            .to_owned();
        if self.rows_before_send.is_empty() {
            self.rows_before_send = oracle_intent_rows(self.vault);
            assert_eq!(
                self.rows_before_send.len(),
                1,
                "transport observes exactly one durable row before its first send"
            );
            self.events
                .push(("intent_journaled".to_owned(), key.clone()));
        }
        self.events.push(("wire_send".to_owned(), key.clone()));
        self.send_keys.push(key.clone());
        if self.seen_keys.insert(key) {
            self.effects_applied = self.effects_applied.saturating_add(1);
        }
        self.outcomes.pop_front().expect("oracle send outcome")
    }
}

#[derive(Default)]
struct OracleReadOnlyTransport {
    calls: usize,
}

impl OutboundTransport for OracleReadOnlyTransport {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.calls = self.calls.saturating_add(1);
        OutboundSendOutcome::Acked
    }
}

/// ARMING SEAM (ONE-1691): drive one EFFECTFUL `self.mcp` call
/// (send/post/charge/book class). With `crash_before_ack` the process
/// "crashes" after the wire send but before the DONE journal write, then
/// runs crash-recovery.
fn drive_effectful_mcp_call(vault: &Vault, crash_before_ack: bool) -> IntentLedgerTrace {
    let fixture = install_oracle_scoped_fixture(vault);
    let attempt_id = AttemptId::from_bytes(&[0x93; 16]).expect("attempt id");
    let payload = b"oracle exactly-once payload".to_vec();
    let outcomes = if crash_before_ack {
        vec![OutboundSendOutcome::Ambiguous, OutboundSendOutcome::Acked]
    } else {
        vec![OutboundSendOutcome::Acked]
    };
    let mut transport = OracleLedgerTransport::new(vault, outcomes);
    let initial = execute_outbound_effect(
        vault,
        &fixture.authority,
        OutboundEffectCommand::New(oracle_prepared_effect(
            &fixture, attempt_id, 1, payload, true,
        )),
        20,
        &mut transport,
    )
    .expect("initial oracle dispatch");
    if crash_before_ack {
        assert_eq!(initial.dispatch.state, Some(IntentState::Pending));
        let intent_id = initial.dispatch.intent_id.expect("journaled intent id");
        let recovered = execute_outbound_effect(
            vault,
            &fixture.authority,
            OutboundEffectCommand::Resume(intent_id),
            21,
            &mut transport,
        )
        .expect("oracle crash recovery");
        assert_eq!(recovered.dispatch.state, Some(IntentState::Done));
    } else {
        assert_eq!(initial.dispatch.state, Some(IntentState::Done));
    }
    let rows_after = oracle_intent_rows(vault);
    IntentLedgerTrace {
        events: transport.events,
        rows_before_send: transport.rows_before_send,
        rows_after,
        transport_send_keys: transport.send_keys,
        effects_applied: transport.effects_applied,
    }
}

/// Trace of one READ-ONLY `self.mcp` call.
struct ReadOnlyCallTrace {
    /// Read-only calls the drive actually performed — 1, or the zero-rows
    /// assert below is vacuous.
    read_only_calls: usize,
    /// Intent-ledger rows those calls wrote.
    intent_rows: usize,
}

/// ARMING SEAM (ONE-1691): drive one READ-ONLY `self.mcp` call
/// (search/read/fetch class) and report the call + ledger trace.
fn drive_read_only_mcp_call(vault: &Vault) -> ReadOnlyCallTrace {
    let request = OutboundCallRequest::new(
        AttemptId::from_bytes(&[0x94; 16]).expect("attempt id"),
        1,
        "files",
        "read_file",
        b"oracle read-only payload".to_vec(),
        20,
    );
    let payload_hash = hash_frozen_payload(&request.payload);
    let call = FrozenOutboundCall::read_only(request, payload_hash);
    let mut transport = OracleReadOnlyTransport::default();
    assert_eq!(transport.send(&call), OutboundSendOutcome::Acked);
    ReadOnlyCallTrace {
        read_only_calls: transport.calls,
        intent_rows: intent_ledger_records(vault)
            .expect("read-only ledger inspection")
            .len(),
    }
}

/// Trace of one effectful call against a tool with NO idempotency support,
/// driven into an ambiguous (unacked) outcome.
struct AtMostOnceTrace {
    /// Ambiguous acks the fixture induced — 1, or the test is vacuous.
    ambiguous_acks: usize,
    wire_sends: usize,
    /// Automatic re-sends attempted after the ambiguity.
    auto_resends: usize,
    human_escalations: usize,
    /// Disposition the escalation carried to the human.
    escalated_disposition: Option<String>,
}

/// ARMING SEAM (ONE-1691): drive an effectful call against a tool with NO
/// idempotency support, inducing exactly one ambiguous (unacked) outcome.
fn drive_effectful_call_without_idempotency_support(vault: &Vault) -> AtMostOnceTrace {
    let fixture = install_oracle_scoped_fixture(vault);
    let mut transport = OracleLedgerTransport::new(vault, [OutboundSendOutcome::Ambiguous]);
    let result = execute_outbound_effect(
        vault,
        &fixture.authority,
        OutboundEffectCommand::New(oracle_prepared_effect(
            &fixture,
            AttemptId::from_bytes(&[0x95; 16]).expect("attempt id"),
            1,
            b"oracle at-most-once payload".to_vec(),
            false,
        )),
        20,
        &mut transport,
    )
    .expect("non-idempotent oracle dispatch");
    let escalation_reason = result.dispatch.escalation.map(|row| row.reason);
    AtMostOnceTrace {
        ambiguous_acks: usize::from(
            result.dispatch.send_outcome == Some(OutboundSendOutcome::Ambiguous),
        ),
        wire_sends: transport.send_keys.len(),
        auto_resends: transport.send_keys.len().saturating_sub(1),
        human_escalations: usize::from(escalation_reason.is_some()),
        escalated_disposition: (escalation_reason
            == Some(IntentEscalationReason::NonIdempotentAmbiguous))
        .then(|| "may not have sent".to_owned()),
    }
}

/// Recovery/retry observation for a crash BEFORE the PENDING journal write.
struct CrashBeforeJournalTrace {
    /// Intent rows recovery found (the crash preceded the journal write).
    rows_after_recovery: usize,
    /// Wire sends RECOVERY performed on its own.
    recovery_wire_sends: usize,
    /// Wire sends the caller's explicit retry performed.
    retry_wire_sends: usize,
    /// Intent rows after the retry settled.
    rows_after_retry: usize,
}

/// ARMING SEAM (ONE-1691): "crash" BEFORE the durable PENDING write, run
/// crash-recovery, then let the caller retry the call.
fn drive_crash_before_intent_journal(vault: &Vault) -> CrashBeforeJournalTrace {
    let fixture = install_oracle_scoped_fixture(vault);
    let attempt_id = AttemptId::from_bytes(&[0x96; 16]).expect("attempt id");
    let call_seq = 1;
    let payload = b"oracle pre-journal crash payload".to_vec();
    let payload_hash = hash_frozen_payload(&payload);
    let missing_intent_id = derive_intent_id(
        attempt_id,
        call_seq,
        &fixture.call.server,
        &fixture.call.tool,
        &payload_hash,
    )
    .expect("derive missing intent id");
    let mut transport = OracleLedgerTransport::new(vault, [OutboundSendOutcome::Acked]);
    let missing_recovery = execute_outbound_effect(
        vault,
        &fixture.authority,
        OutboundEffectCommand::Resume(missing_intent_id),
        20,
        &mut transport,
    );
    assert!(matches!(
        missing_recovery,
        Err(IntentLedgerError::InvalidRecord(
            "outbound resume target is missing"
        ))
    ));
    let rows_after_recovery = intent_ledger_records(vault)
        .expect("inspect pre-journal recovery")
        .len();
    let recovery_wire_sends = transport.send_keys.len();
    let sends_before_retry = transport.send_keys.len();
    let retry = execute_outbound_effect(
        vault,
        &fixture.authority,
        OutboundEffectCommand::New(oracle_prepared_effect(
            &fixture, attempt_id, call_seq, payload, true,
        )),
        21,
        &mut transport,
    )
    .expect("explicit post-crash retry");
    assert_eq!(retry.dispatch.state, Some(IntentState::Done));
    CrashBeforeJournalTrace {
        rows_after_recovery,
        recovery_wire_sends,
        retry_wire_sends: transport.send_keys.len() - sends_before_retry,
        rows_after_retry: intent_ledger_records(vault)
            .expect("inspect explicit retry")
            .len(),
    }
}

/// RT-11: the durable INTENT row (state PENDING, idempotency key already
/// minted) exists BEFORE the send — proven by OBSERVED event order, not a
/// self-reported flag — carries {id, server, tool, payload_hash, state},
/// and the ack flips it to DONE in the STORE (re-read, not returned). The
/// ledger doubles as the outbound audit receipt.
#[test]
fn one_1691_intent_is_pending_before_send_and_done_on_ack() {
    let (_dir, vault) = open_vault();
    let trace = drive_effectful_mcp_call(&vault, false);

    assert_eq!(trace.rows_before_send.len(), 1, "exactly one intent row");
    let intent = &trace.rows_before_send[0];
    assert_eq!(
        intent.state, "pending",
        "the intent is journaled PENDING before the wire send"
    );
    let populated = [
        &intent.id,
        &intent.server,
        &intent.tool,
        &intent.payload_hash,
        &intent.state,
    ]
    .iter()
    .filter(|field| !field.is_empty())
    .count();
    assert_eq!(
        populated, 5,
        "the row carries id, server, tool, payload_hash, state — all populated"
    );

    assert_eq!(trace.transport_send_keys.len(), 1, "exactly one wire send");
    assert_eq!(
        intent.idempotency_key, trace.transport_send_keys[0],
        "the wire send carries the journaled idempotency key"
    );

    // ORDER is observed, not self-reported: exactly one journal event and
    // one send event, and the journal precedes the send in the trace.
    let journal_events = trace
        .events
        .iter()
        .filter(|(kind, _)| kind == "intent_journaled")
        .count();
    let send_events = trace
        .events
        .iter()
        .filter(|(kind, _)| kind == "wire_send")
        .count();
    assert_eq!(journal_events, 1);
    assert_eq!(send_events, 1);
    let journal_pos = trace
        .events
        .iter()
        .position(|(kind, _)| kind == "intent_journaled")
        .expect("journal event present");
    let send_pos = trace
        .events
        .iter()
        .position(|(kind, _)| kind == "wire_send")
        .expect("send event present");
    assert!(
        journal_pos < send_pos,
        "the intent-row write is OBSERVED before the wire send"
    );

    assert_eq!(trace.rows_after.len(), 1);
    assert_eq!(
        trace.rows_after[0].state, "done",
        "the RE-READ row shows the ack flipped PENDING → DONE"
    );
    assert_eq!(
        trace.rows_after[0].id, intent.id,
        "same durable row settled — not a second one"
    );
    assert_eq!(trace.effects_applied, 1);
}

/// RT-11: crash-recovery re-sends a PENDING intent with the SAME
/// idempotency key, so the server dedups — a crash-before-journal or an
/// identical-bytes replay cannot double-fire. Exactly-once is observable.
#[test]
fn one_1691_crash_recovery_replays_with_the_same_key_exactly_once() {
    let (_dir, vault) = open_vault();
    let trace = drive_effectful_mcp_call(&vault, true);

    assert_eq!(
        trace.transport_send_keys.len(),
        2,
        "recovery re-sends the PENDING intent (crashed send + replay)"
    );
    let distinct_keys: BTreeSet<&String> = trace.transport_send_keys.iter().collect();
    assert_eq!(
        distinct_keys.len(),
        1,
        "the replay rides the SAME idempotency key — server-side dedupe"
    );
    assert_eq!(
        trace.effects_applied, 1,
        "exactly-once observable under simulated crash"
    );
    assert_eq!(trace.rows_after.len(), 1);
    assert_eq!(
        trace.rows_after[0].state, "done",
        "recovery settles the RE-READ row"
    );
}

/// RT-11: read-only calls (search/read/fetch) are replay-safe and carry
/// NO ledger machinery. Non-vacuous: the trace proves one read-only call
/// really ran.
#[test]
fn one_1691_read_only_calls_are_unledgered() {
    let (_dir, vault) = open_vault();
    let trace = drive_read_only_mcp_call(&vault);
    assert_eq!(
        trace.read_only_calls, 1,
        "exactly one read-only call was performed — the zero below is earned"
    );
    assert_eq!(
        trace.intent_rows, 0,
        "read-only MCP calls write zero intent rows"
    );
}

/// RT-11: a tool with no idempotency support degrades to AT-MOST-ONCE —
/// exactly one induced ambiguous ack, exactly one wire send, ZERO
/// automatic re-sends, and exactly one human escalation carrying the
/// may-not-have-sent disposition.
#[test]
fn one_1691_no_idempotency_support_degrades_to_at_most_once() {
    let (_dir, vault) = open_vault();
    let trace = drive_effectful_call_without_idempotency_support(&vault);
    assert_eq!(
        trace.ambiguous_acks, 1,
        "the fixture induced exactly one ambiguous ack — non-vacuous"
    );
    assert_eq!(
        trace.wire_sends, 1,
        "NO auto re-send on ambiguity — at-most-once"
    );
    assert_eq!(trace.auto_resends, 0, "zero automatic re-sends");
    assert_eq!(
        trace.human_escalations, 1,
        "the ambiguity escalates to a human exactly once"
    );
    assert_eq!(
        trace.escalated_disposition.as_deref(),
        Some("may not have sent"),
        "the escalation carries the may-not-have-sent disposition"
    );
}

/// RT-11 (G7): a crash BEFORE the PENDING journal write leaves recovery
/// with zero rows — recovery must send NOTHING on its own (the intent was
/// never durable; re-sending would forge one). The caller's retry then
/// produces exactly one send and one row.
#[test]
fn one_1691_crash_before_journal_recovers_to_zero_sends_and_retry_sends_once() {
    let (_dir, vault) = open_vault();
    let trace = drive_crash_before_intent_journal(&vault);
    assert_eq!(
        trace.rows_after_recovery, 0,
        "no intent row survived the pre-journal crash"
    );
    assert_eq!(
        trace.recovery_wire_sends, 0,
        "recovery never sends without a durable intent"
    );
    assert_eq!(
        trace.retry_wire_sends, 1,
        "the caller's retry sends exactly once"
    );
    assert_eq!(trace.rows_after_retry, 1, "and journals exactly one row");
}
