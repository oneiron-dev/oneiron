//! Door for `tests/stalwart_read_back.rs` (FIX 22347): one replay pass of an
//! outcome-free Pending native mail send that its transport looks up at its
//! provider (FIX 4747), counting the questions the pass asks that provider.

use std::cell::Cell;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundTransport, UncertainSendStep, execute_outbound_effect,
};
use crate::outbound_consent::OutboundBindingAuthority;
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, DeliveryReadBack, FrozenOutboundCall, IntentLedgerRecord,
    OutboundCallRequest, OutboundSendOutcome, force_sync, insert_pending_in_txn,
};

/// The provider questions one replay pass asked, and the sends it made.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PassQuestions {
    /// Read-backs of the send (FIX 8814 follow-up).
    pub read_backs: usize,
    /// Sent lookups of the send (FIX 4747).
    pub lookups: usize,
    /// Sends.
    pub sends: usize,
}

/// A connector-send TASK's transport, as the chokepoint sees it: it looks
/// uncertain sends up, its provider can tell nothing of this one, and it
/// counts every question.
#[derive(Default)]
struct CountingLookupTransport {
    read_backs: Cell<usize>,
    lookups: usize,
    sends: usize,
}

impl OutboundTransport for CountingLookupTransport {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.sends += 1;
        OutboundSendOutcome::Acked
    }

    fn looks_up_uncertain_sends(&self) -> bool {
        true
    }

    fn uncertain_send_step(&mut self, _call: &FrozenOutboundCall) -> UncertainSendStep {
        self.lookups += 1;
        UncertainSendStep::Hold
    }

    fn read_back_delivery(&self, _call: &FrozenOutboundCall) -> DeliveryReadBack {
        self.read_backs.set(self.read_backs.get() + 1);
        DeliveryReadBack::Unknown
    }
}

/// Writes one outcome-free Pending `email`/`send` row that claims no
/// provider idempotency, as a crash after its Pending insert leaves it, and
/// resumes it once through the chokepoint with a transport that looks it up.
///
/// # Panics
/// When the row cannot be written, or the resume fails.
#[must_use]
pub fn replay_uncertain_send(vault: &Vault) -> PassQuestions {
    let request = OutboundCallRequest::new(
        AttemptId::from_bytes(&[0x5B; 16]).expect("attempt id"),
        1,
        "email",
        "send",
        b"uncertain native mail send".to_vec(),
        10,
    );
    let marker = BudgetChargeMarker {
        key_ref: None,
        budget_class: BudgetClass::Operation,
        matched_rows: Vec::new(),
        sends_debit: 0,
        accounted_at_ms: 10,
    };
    let record = IntentLedgerRecord::pending(request, false, marker).expect("pending row");
    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    insert_pending_in_txn(vault, &mut wtxn, &record).expect("insert the pending row");
    wtxn.commit().expect("commit the pending row");
    force_sync(vault).expect("sync the pending row");

    let authority = OutboundBindingAuthority::from_secret([0xAC; 32]);
    let mut transport = CountingLookupTransport::default();
    execute_outbound_effect(
        vault,
        &authority,
        OutboundEffectCommand::Resume(record.id),
        11,
        &mut transport,
    )
    .expect("resume the pending row");
    PassQuestions {
        read_backs: transport.read_backs.get(),
        lookups: transport.lookups,
        sends: transport.sends,
    }
}
