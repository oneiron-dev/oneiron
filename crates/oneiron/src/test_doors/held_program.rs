//! A held turn-program attempt for release tests: plant a Diverged hold as
//! the admission and the program runtime leave it, without the run or
//! checkpoint a resume would read; or one whose stamp binds no admission.
//! And a call of a planted try resumed through the outbound chokepoint at a
//! known ledger second, so a test reads the outbound step it settles.

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::turn_program_test_hooks::{
    HeldProgramAdmission, plant_held_program_attempt,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundTransport, execute_outbound_effect,
};
use crate::outbound_consent::OutboundBindingAuthority;
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, DeliveryReadBack, FrozenOutboundCall, IntentLedgerRecord,
    OutboundCallRequest, OutboundSendOutcome, force_sync, insert_pending_in_txn,
};
use crate::{EdgeActorClass, EntityId, Vault};

/// Plants a Diverged-held turn-program attempt stamped as `actor`'s program
/// try (class `actor_class`), with the admission that queued it as its
/// program's root try, sealed for `actor`. Answers the attempt's hex, the
/// hold's exact reason and its park time, as a release request names them.
///
/// # Errors
///
/// A store failure.
pub fn plant_held_turn_program_for_test(
    vault: &Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> Result<(String, String, u64)> {
    plant_held_program_attempt(vault, actor, actor_class, HeldProgramAdmission::Bound)
}

/// Plants the same held attempt with a stamp that names `actor` but an
/// admission no row holds: no program read finds a program there. Answers
/// as [`plant_held_turn_program_for_test`].
///
/// # Errors
///
/// A store failure.
pub fn plant_unbound_held_turn_program_for_test(
    vault: &Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> Result<(String, String, u64)> {
    plant_held_program_attempt(vault, actor, actor_class, HeldProgramAdmission::Absent)
}

/// What one chokepoint pass over a planted program try's call did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramCallPass {
    /// The call's frozen intent id (64 hex), as the program's outbound step
    /// names it.
    pub intent: String,
    /// The sends the pass made.
    pub sends: usize,
}

/// A transport whose provider acknowledges every send.
#[derive(Default)]
struct AcknowledgingTransport {
    sends: usize,
}

impl OutboundTransport for AcknowledgingTransport {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.sends += 1;
        OutboundSendOutcome::Acked
    }
}

/// A transport whose provider's own record reads back that the call went.
#[derive(Default)]
struct DeliveredReadBackTransport {
    sends: usize,
}

impl OutboundTransport for DeliveredReadBackTransport {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.sends += 1;
        OutboundSendOutcome::Acked
    }

    fn read_back_delivery(&self, _call: &FrozenOutboundCall) -> DeliveryReadBack {
        DeliveryReadBack::Delivered
    }
}

/// Resumes call `call_seq` of the planted program try `attempt` (its hex, as
/// [`plant_held_turn_program_for_test`] answers it) through the outbound
/// chokepoint at ledger time `now`, Unix seconds: an outcome-free Pending
/// row whose provider deduplicates a resend under its key, resent to a
/// provider that acknowledges it. The acknowledged send settles the
/// program's outbound step.
///
/// # Panics
///
/// When `attempt` is not a 32-hex attempt id, the row cannot be written, or
/// the resume fails.
#[must_use]
pub fn send_program_call_acked_at(
    vault: &Vault,
    attempt: &str,
    call_seq: u64,
    now: u64,
) -> ProgramCallPass {
    let record = insert_program_call(vault, attempt, call_seq, true, now);
    let mut transport = AcknowledgingTransport::default();
    resume_program_call(vault, &record, now, &mut transport);
    ProgramCallPass {
        intent: bytes_to_hex_lower(&record.id),
        sends: transport.sends,
    }
}

/// Resumes call `call_seq` of the planted program try `attempt` through the
/// outbound chokepoint at ledger time `now`, Unix seconds: an outcome-free
/// Pending row that claims no provider idempotency, as a crash after its
/// send leaves it, whose provider's own record reads back that it went. It
/// completes by that read-back, never sent again, and settles the program's
/// outbound step.
///
/// # Panics
///
/// As [`send_program_call_acked_at`].
#[must_use]
pub fn complete_program_call_by_read_back_at(
    vault: &Vault,
    attempt: &str,
    call_seq: u64,
    now: u64,
) -> ProgramCallPass {
    let record = insert_program_call(vault, attempt, call_seq, false, now);
    let mut transport = DeliveredReadBackTransport::default();
    resume_program_call(vault, &record, now, &mut transport);
    ProgramCallPass {
        intent: bytes_to_hex_lower(&record.id),
        sends: transport.sends,
    }
}

/// Writes call `call_seq` of `attempt` as an outcome-free Pending row
/// admitted at `now`, charged to no connector key.
fn insert_program_call(
    vault: &Vault,
    attempt: &str,
    call_seq: u64,
    idempotency_supported: bool,
    now: u64,
) -> IntentLedgerRecord {
    let attempt = EntityId::from_hex(attempt).expect("a 32-hex attempt id");
    let attempt = AttemptId::from_bytes(attempt.as_bytes()).expect("an attempt id");
    let request = OutboundCallRequest::new(
        attempt,
        call_seq,
        "fixture",
        "send",
        b"turn program send".to_vec(),
        now,
    );
    let marker = BudgetChargeMarker {
        key_ref: None,
        budget_class: BudgetClass::Operation,
        matched_rows: Vec::new(),
        sends_debit: 0,
        accounted_at_ms: now,
    };
    let record =
        IntentLedgerRecord::pending(request, idempotency_supported, marker).expect("pending row");
    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    insert_pending_in_txn(vault, &mut wtxn, &record).expect("insert the pending row");
    wtxn.commit().expect("commit the pending row");
    force_sync(vault).expect("sync the pending row");
    record
}

/// Resumes `record` once through the outbound chokepoint at `now`.
fn resume_program_call<T: OutboundTransport>(
    vault: &Vault,
    record: &IntentLedgerRecord,
    now: u64,
    transport: &mut T,
) {
    let authority = OutboundBindingAuthority::from_secret([0xAC; 32]);
    execute_outbound_effect(
        vault,
        &authority,
        OutboundEffectCommand::Resume(record.id),
        now,
        transport,
    )
    .expect("resume the pending row");
}
