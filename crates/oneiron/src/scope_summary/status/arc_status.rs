//! An Arc declaration's owed state on its public status (FIX 8060, 8291):
//! the typed cause its row records, and for an Arc composing in parts its
//! work generation with the parts done and still owed, counted as the
//! landing's completion proof counts a part done. Ids, codes and counts
//! only: never a source's words.

use super::super::arc_gate::{ArcPendingCause, pending_cause_in_txn};
use super::super::arc_work::child_terminal;
use super::super::arc_work_store::{child_in_txn, manifest_in_txn};
use super::ArcPendingStatus;
use crate::Vault;
use crate::error::Result;
use rmpv::Value;

/// The owed cause of the Arc `input` declares; `None` for any other
/// declaration, for an Arc owing nothing, and when its row does not read
/// (logged, so the rest of the status still answers).
pub(super) fn arc_pending_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &Value,
) -> Option<ArcPendingStatus> {
    if !super::super::arc::is_arc_declaration(input) {
        return None;
    }
    match pending_in_txn(vault, txn, input) {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "an arc's owed cause did not read for its status"
            );
            None
        }
    }
}

fn pending_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &Value,
) -> Result<Option<ArcPendingStatus>> {
    let input = super::super::derivation::encode(input)?;
    let Some(cause) = pending_cause_in_txn(vault, txn, &input)? else {
        return Ok(None);
    };
    Ok(Some(match cause {
        ArcPendingCause::LowerPending { session } => ArcPendingStatus::ArcLowerPending { session },
        ArcPendingCause::SourceUnavailable { handle } => {
            ArcPendingStatus::ArcSourceUnavailable { handle }
        }
        ArcPendingCause::CompositionPending { work_id } => {
            let (parts_done, parts_owed) = parts_in_txn(vault, txn, &work_id)?;
            ArcPendingStatus::ArcCompositionPending {
                work_id,
                parts_done,
                parts_owed,
            }
        }
        ArcPendingCause::WindowTooSmall {
            window,
            frame_tokens,
        } => ArcPendingStatus::ArcWindowTooSmall {
            window,
            frame_tokens,
        },
    }))
}

/// How many of generation `work`'s parts are done and how many are still
/// owed; none of either when its manifest is gone.
fn parts_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, work: &str) -> Result<(u64, u64)> {
    let Some(manifest) = manifest_in_txn(vault, txn, work)? else {
        return Ok((0, 0));
    };
    let mut done = 0_u64;
    for child in &manifest.children {
        if child_in_txn(vault, txn, work, child.id)?
            .is_some_and(|row| child_terminal(&row, &manifest))
        {
            done += 1;
        }
    }
    let parts = manifest.children.len() as u64;
    Ok((done, parts.saturating_sub(done)))
}
