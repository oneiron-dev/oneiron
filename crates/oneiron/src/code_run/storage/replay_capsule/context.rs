//! A captured step's replay context (FIX 6351), attached to its capsule in
//! its checkpoint's one transaction: its body admitted through the side-row
//! wall under the capsule's key, so each secret in it is its custody handle,
//! published as a body the run owns, and named on the capsule beside its
//! start. Its instances are minted before the checkpoint's writer opens.
//!
//! The context joins in a savepoint of its own and never fails the commit:
//! a capsule that is gone, erased, not the context's step or already names a
//! context, a body the wall refuses or one that spills past its minted
//! instances leaves the capsule without one. The step's effects stand, and
//! each of its responses reads as not captured. A context never names a
//! checkpoint that did not commit: it is written in that checkpoint's own
//! transaction. An erase of the capsule's actor releases the context with
//! the capsule's other bodies (`erase`).

use heed::RwTxn;

use super::super::super::replay_capsule::{StepContextRef, StepReplayCapsule};
use super::super::super::replay_context::{StepContextCommit, StepReplayContext};
use super::super::records::body_drifted;
use super::admit::{Spill, Unwritten};
use super::erase::actor_gone_in_txn;
use super::{CAPSULES, capsule_key, held_body_in_txn, kept_in_txn};
use crate::batch::secret_scan::{SidePart, admit_side_parts};
use crate::{EntityId, Error, Result, Vault};

/// Where the wall's custody records name what they lifted from a capsule's
/// replay context, beside the capsule's key.
const CONTEXT_PLACE: &str = "side:CODE_RUN_REPLAY_CAPSULE:context";

/// A step's replay context ready to join its checkpoint's commit, with the
/// instances its body may spill into.
pub(crate) struct StagedContext<'c> {
    commit: &'c StepContextCommit,
    key: (EntityId, u64, u64),
    spill: Spill,
}

/// `commit` staged for its checkpoint's writer, its instances minted now:
/// `None` when it names no capsule, and when they cannot be minted, which
/// is logged.
pub(crate) fn stage_step_context<'c>(
    vault: &Vault,
    commit: &'c StepContextCommit,
) -> Option<StagedContext<'c>> {
    let (attempt, lease_generation) = commit.capsule?;
    let key = (attempt, u64::from(lease_generation), commit.context.step);
    match Spill::minted(vault, &[commit.bytes.len()]) {
        Ok(spill) => Some(StagedContext { commit, key, spill }),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a step replay context was not staged");
            None
        }
    }
}

/// Joins `staged` to its checkpoint's commit in `wtxn`, in a savepoint of
/// its own. A context that does not join leaves its capsule without one,
/// which is logged; the commit goes on.
pub(crate) fn join_step_context_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    staged: &StagedContext<'_>,
) {
    match join_in_savepoint(vault, wtxn, staged) {
        Ok(true) => {}
        Ok(false) => tracing::debug!("a step replay context joined no capsule"),
        Err(Unwritten::Unreserved(needed)) => tracing::warn!(
            needed,
            "a step replay context spilled past its minted instances; it is not kept"
        ),
        Err(Unwritten::Failed(error)) => {
            tracing::warn!(kind = ?error.kind(), "a step replay context was not kept");
        }
    }
}

/// [`attach_in_txn`] in a savepoint of `wtxn`, kept only once it attached.
fn join_in_savepoint(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    staged: &StagedContext<'_>,
) -> std::result::Result<bool, Unwritten> {
    let mut savepoint = vault
        .store
        .env
        .nested_write_txn(wtxn)
        .map_err(Error::from)?;
    if !attach_in_txn(vault, &mut savepoint, staged)? {
        return Ok(false);
    }
    savepoint.commit().map_err(Error::from)?;
    Ok(true)
}

/// The context's body admitted and published, and its capsule naming it,
/// in `wtxn`: `false`, with nothing written, when the capsule is gone, its
/// content or actor is, it already names a context, or it is not the
/// context's step (its run, its step and the bridge position its start
/// holds).
fn attach_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    staged: &StagedContext<'_>,
) -> std::result::Result<bool, Unwritten> {
    let StagedContext { commit, key, spill } = staged;
    let Some(mut capsule) = CAPSULES.get(&vault.store, wtxn, key)? else {
        return Ok(false);
    };
    let Some(actor) = capsule.content.actor() else {
        return Ok(false);
    };
    if actor_gone_in_txn(vault, wtxn, &actor)
        || capsule.context.is_some()
        || !captured_step(&capsule, &commit.context)
    {
        return Ok(false);
    }
    let key_bytes = CAPSULES.key_bytes(key);
    let mut parts = [SidePart::Body(commit.bytes.clone())];
    let at = (CONTEXT_PLACE, key_bytes.as_slice());
    let bytes = if admit_side_parts(vault, wtxn, at, &mut parts, reads_context)? {
        admitted_context(&parts)?
    } else {
        commit.bytes.clone()
    };
    spill.holds(&[bytes.len()])?;
    let path = context_path(&capsule);
    let body = spill.publish_in_txn(vault, wtxn, capsule.run, &path, &bytes)?;
    capsule.context = Some(StepContextRef {
        body,
        path,
        digest: *blake3::hash(&bytes).as_bytes(),
        erased: false,
    });
    CAPSULES.put(vault, wtxn, key, &capsule)?;
    Ok(true)
}

/// Whether `context` is the step `capsule` captured: its run and step, and
/// the bridge position the capsule's start holds.
fn captured_step(capsule: &StepReplayCapsule, context: &StepReplayContext) -> bool {
    capsule.run == context.run
        && capsule.step == context.step
        && capsule
            .start
            .as_ref()
            .is_some_and(|start| !start.erased && start.bridge_start == context.bridge_start)
}

/// Where the run keeps a capsule's replay context, beside its request and
/// start.
fn context_path(capsule: &StepReplayCapsule) -> String {
    format!(
        "replay/capsule/{}/{:06}.context.json",
        capsule.lease_generation, capsule.step
    )
}

/// Whether an admitted copy still reads as a replay context.
fn reads_context(parts: &[SidePart]) -> bool {
    matches!(parts, [SidePart::Body(body)] if StepReplayContext::decode(body).is_some())
}

/// A context as the wall admitted it, encoded again from its typed copy.
fn admitted_context(parts: &[SidePart]) -> Result<Vec<u8>> {
    let [SidePart::Body(admitted)] = parts else {
        return Err(Error::InvariantViolation(
            "an admitted step replay context is no longer a body",
        ));
    };
    StepReplayContext::decode(admitted)
        .ok_or(Error::InvariantViolation(
            "an admitted step replay context does not decode",
        ))?
        .encode()
}

/// The capsule's replay context body (FIX 6351), read in the caller's
/// transaction, as stored: masked. `None` when the capsule names none,
/// holds its content no longer (its actor was erased), or the body is
/// released, gone, withheld, marked erased by a restore or no longer its
/// digest.
pub(crate) fn capsule_context_body(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    capsule: &StepReplayCapsule,
) -> Result<Option<Vec<u8>>> {
    let Some(capsule) = kept_in_txn(vault, rtxn, &capsule_key(capsule))? else {
        return Ok(None);
    };
    let Some(context) = &capsule.context else {
        return Ok(None);
    };
    if context.erased {
        return Ok(None);
    }
    let held = match held_body_in_txn(vault, rtxn, capsule.run, &context.path, context.body) {
        // Bytes that drifted from their row are no context, as bytes no
        // longer its digest are; a read that fails stays an error.
        Err(error) if body_drifted(&error) => return Ok(None),
        held => held?,
    };
    Ok(held.filter(|bytes| *blake3::hash(bytes).as_bytes() == context.digest))
}
