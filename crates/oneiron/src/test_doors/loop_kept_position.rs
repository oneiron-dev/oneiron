//! Door for `tests/loop_kept_position_grant.rs` (FIX-LIST
//! LOOP-KEPT-POSITION-FLOOR-AND-GRANT): a loop decision whose one read
//! context is a kept record position, recorded with no claim and no loop
//! write.

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::gate_reason::GateReceiptOutcome;
use crate::store::{
    GateDecisionContext, GateDecisionReadContext, GateDecisionRecord, GateReceipt, PolicyBasis,
    ReceiptActor,
};
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

/// The reason code of [`record_kept_position_receipt`]'s row.
pub const KEPT_POSITION_REASON: &str = "gate.dreamer.maintenance_refused";

/// The agent `agent`'s own refused applied-maintenance decision about a
/// candidate claim that never landed: a fresh candidate id whose kept read
/// position is the one the stored claim `claim`'s body stamps
/// (`GateDecisionReadContext::claim`), with no `about` row, so that
/// position alone decides who reads the decision. Recorded through
/// `Store::record_gate_receipt_in_txn`. The row it appended, and the
/// candidate's id.
///
/// # Errors
/// `claim` is not stored, its body does not decode or keeps no read
/// position, or the write fails.
pub fn record_kept_position_receipt(
    vault: &Vault,
    agent: EntityId,
    claim: EntityId,
) -> Result<(GateDecisionRecord, EntityId)> {
    let body = vault.get(&claim)?.ok_or(Error::EntityNotFound)?;
    let body = crate::claim::decode_claim_body(&body, true)?;
    let candidate = vault.new_entity_id()?;
    let kept = GateDecisionReadContext::claim(&candidate, &body).ok_or(Error::InvalidClaimBody(
        "the claim keeps no read position for a candidate",
    ))?;
    let mut receipt = GateReceipt::new(
        GateReceiptOutcome::Rejected,
        crate::dreamer_runner::maintenance::MAINTENANCE_APPLY_KIND,
        KEPT_POSITION_REASON,
        ReceiptActor::Row(WriteActor::new(agent, EdgeActorClass::Agent)),
        candidate.as_bytes().to_vec(),
        PolicyBasis::NOT_READ,
    );
    receipt.about = Some(candidate);
    receipt.context = GateDecisionContext {
        read: vec![GateDecisionReadContext {
            about: Vec::new(),
            ..kept
        }],
        links: Vec::new(),
        analysis: None,
        restates: None,
    };
    let row = vault.with_write_txn(|txn| vault.store.record_gate_receipt_in_txn(txn, receipt))?;
    Ok((row, candidate))
}
