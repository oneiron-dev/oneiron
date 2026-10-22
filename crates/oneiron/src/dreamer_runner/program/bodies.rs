//! A turn program's STEP bodies under body custody (KS-2B1, FIX 5719; FIX
//! 5683 part B1).
//!
//! A send's kept body is one body instance, bound the first time a
//! checkpoint carries its STEP row. The image holds the step's evidence (its
//! key, try, issuing binding, digest and time) with its body taken, and the
//! body sealed under the instance alone: a restore under a live instance
//! lands the exact row, and under a retired one keeps that evidence, which
//! settles nothing again and sends nothing again. Its owners are the actor
//! its try ran as, by the attempt stamp its admission wrote, its code run
//! and its step.

use super::ATTEMPT;
use super::run::{RUN, STEP, StepState};
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{SideKey, SideTableDbs};
use crate::store::{ResponseCarriage, ResponseScan};

/// What a checkpoint carries of the STEP row `value`: a settled step's
/// kept body, its evidence with the body taken as the stub its erased
/// disposition keeps whole. No response for a step that keeps no body; a
/// row that does not decode, or whose evidence does not encode, is carried
/// whole as an opaque response (FIX 6227).
pub(crate) fn program_step_carriage(value: &[u8]) -> ResponseScan {
    let Ok(mut step) = STEP.decode_value(value) else {
        return ResponseScan::opaque_row();
    };
    let StepState::Settled { result, .. } = &mut step.state else {
        return ResponseScan::NotResponse;
    };
    if result.take().is_none() {
        return ResponseScan::NotResponse;
    }
    let Ok(stub) = STEP.encode_value(&step) else {
        return ResponseScan::opaque_row();
    };
    ResponseScan::Decoded(ResponseCarriage {
        keep: 0,
        retired: stub.len(),
        stub,
    })
}

/// Who owns the STEP row `key`'s body: its code run, its step, and the
/// actor its try ran as.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn program_step_owners(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<Vec<EntityId>> {
    let mut owners = Vec::new();
    if let Some((code_run, step)) = key
        .strip_prefix(STEP.decl().prefix)
        .and_then(<(EntityId, EntityId) as SideKey>::decode_key)
    {
        owners.extend([code_run, step]);
    }
    if let Ok(step) = STEP.decode_value(value) {
        owners.extend(attempt_actor_in_txn(dbs, txn, &step.attempt)?);
    }
    Ok(owners)
}

/// The actor a turn program's code run `code_run` runs as, by the attempt
/// that entered it: `None` for a code run no program entered.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn program_run_actor_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    code_run: &EntityId,
) -> Result<Option<EntityId>> {
    match RUN.get_lenient(dbs, txn, code_run)? {
        Some(run) => attempt_actor_in_txn(dbs, txn, &run.attempt),
        None => Ok(None),
    }
}

/// The waking actor the attempt stamp of `attempt` names.
fn attempt_actor_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    attempt: &[u8; 16],
) -> Result<Option<EntityId>> {
    let Ok(attempt) = AttemptId::from_bytes(attempt) else {
        return Ok(None);
    };
    Ok(ATTEMPT
        .get_lenient(dbs, txn, &attempt)?
        .map(|stamp| stamp.actor))
}
