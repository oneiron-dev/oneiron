//! ONE-1691 RT-11: intent-ledger exactly-once/crash-recovery oracles, ledger transports, and drive_* helpers.

use std::collections::{HashSet, VecDeque};

use super::shared::{install_oracle_scoped_fixture, open_vault, oracle_prepared_effect};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundTransport, execute_outbound_effect,
};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentLedgerError, IntentLedgerRecord, IntentState, OutboundSendOutcome,
    derive_intent_id, hash_frozen_payload, intent_ledger_records,
};

// ═══════════════════════════════════════════════════════════════════════
// ONE-1691 — [RT-11] outbound INTENT ledger (SECURITY)
// ═══════════════════════════════════════════════════════════════════════

/// The durable intent rows, RE-READ from the store after the drive — never
/// echoed from the driver's in-memory state.
fn oracle_intent_rows(vault: &Vault) -> Vec<IntentLedgerRecord> {
    intent_ledger_records(vault)
        .expect("read oracle intent rows")
        .into_iter()
        .collect()
}

struct OracleLedgerTransport<'a> {
    vault: &'a Vault,
    outcomes: VecDeque<OutboundSendOutcome>,
    events: Vec<(String, String)>,
    rows_before_send: Vec<IntentLedgerRecord>,
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
    let prepared = oracle_prepared_effect(vault, &fixture, attempt_id, call_seq, payload, true);
    let payload_hash = hash_frozen_payload(&prepared.payload);
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
        OutboundEffectCommand::New(prepared),
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
