use std::collections::{HashSet, VecDeque};

use oneiron::{
    AttemptId, FrozenOutboundCall, IntentState, OutboundAuthorizationBinding, OutboundCallRequest,
    OutboundSendOutcome, OutboundSender, OutboundToolDescriptor, Vault, VaultConfig,
    execute_outbound_call, intent_ledger_records, recover_outbound_intents,
};

struct DeduplicatingServer {
    outcomes: VecDeque<OutboundSendOutcome>,
    seen_keys: HashSet<String>,
    observed_effects: usize,
    sends: usize,
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

fn request(attempt_id: AttemptId, now_ms: u64) -> OutboundCallRequest {
    OutboundCallRequest::new(
        attempt_id,
        17,
        "integration-server",
        "integration-tool",
        br#"{"value":"frozen"}"#.to_vec(),
        now_ms,
    )
    .with_authorization_binding(OutboundAuthorizationBinding::new([0x6B; 32]))
}

#[test]
fn crash_replay_and_recovery_fire_exactly_once_in_a_real_vault() {
    // With PENDING-before-send disabled, recovery has no row and under-fires;
    // with stable-key dedup disabled, replay/recovery observe multiple effects.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    let attempt_id = AttemptId::from_bytes(&[0x42; 16]).expect("attempt id");
    let descriptor = OutboundToolDescriptor {
        read_only_hint: None,
        idempotency_supported_hint: Some(true),
    };
    let mut server = DeduplicatingServer {
        outcomes: [
            OutboundSendOutcome::Ambiguous,
            OutboundSendOutcome::Ambiguous,
            OutboundSendOutcome::Acked,
        ]
        .into_iter()
        .collect(),
        seen_keys: HashSet::new(),
        observed_effects: 0,
        sends: 0,
    };

    execute_outbound_call(&vault, descriptor, request(attempt_id, 100), &mut server)
        .expect("first dispatch");
    assert_eq!(server.observed_effects, 1);
    assert_eq!(intent_ledger_records(&vault).expect("records").len(), 1);

    execute_outbound_call(&vault, descriptor, request(attempt_id, 101), &mut server)
        .expect("same-call replay");
    assert_eq!(server.observed_effects, 1);
    assert_eq!(intent_ledger_records(&vault).expect("records").len(), 1);

    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen after crash");
    let recovery = recover_outbound_intents(&vault, &mut server, 102).expect("recovery");
    assert_eq!(recovery.scanned, 1);
    assert_eq!(recovery.resent, 1);
    assert_eq!(recovery.completed, 1);
    assert_eq!(server.sends, 3);
    assert_eq!(server.observed_effects, 1);
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Done);

    let second_recovery =
        recover_outbound_intents(&vault, &mut server, 103).expect("second recovery");
    assert_eq!(second_recovery.scanned, 1);
    assert_eq!(second_recovery.skipped_done, 1);
    assert_eq!(second_recovery.resent, 0);
    assert_eq!(server.sends, 3);
    assert_eq!(server.observed_effects, 1);
}
