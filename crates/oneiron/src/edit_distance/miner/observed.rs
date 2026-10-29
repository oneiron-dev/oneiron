//! The observed-preference door's evidence bar for a mined cluster (FIX 3083).
//!
//! ARCH-0003 mints a want derived from behaviour as an `observed`
//! `preference.*` claim only on "three observations across two or more
//! sessions". A mined preference is stamped Observed only when its cited
//! receipts join to that much real evidence; below the bar it keeps its
//! Generated stamp, unchanged.
//!
//! One observation is one source TURN whose proposal the decider corrected:
//! a cited receipt's captured Δ, the retained proposal its proposed end
//! names, and the live TURN that proposal derives from. Two receipts over
//! one proposal, or two proposals over one turn, are one observation. Its
//! session is the live SESSION that TURN was witnessed into, read off the
//! recorded membership. [`MinerRun::session`](super::model::MinerRun) is the
//! sitting that scheduled the pass, never a source, and is not read here. A
//! link that does not resolve, and a membership never recorded (an UNKNOWN
//! answer), counts for nothing.

use std::collections::BTreeSet;

use super::model::SubstitutionCluster;
use crate::Vault;
use crate::compaction::turn_session_membership_in_txn;
use crate::edit_distance::delta::captured_amendment_delta_in_txn;
use crate::edit_distance::text_ref::retained_proposal_in_txn;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Distinct observations an Observed preference needs: ARCH-0003's minting
/// rule, "three observations across two or more sessions".
pub(super) const OBSERVED_PREFERENCE_MIN_OBSERVATIONS: usize = 3;

/// Distinct sessions those observations must span: the same rule's "two or
/// more sessions".
pub(super) const OBSERVED_PREFERENCE_MIN_SESSIONS: usize = 2;

/// Whether `cluster`'s receipts join to at least
/// [`OBSERVED_PREFERENCE_MIN_OBSERVATIONS`] distinct observations across at
/// least [`OBSERVED_PREFERENCE_MIN_SESSIONS`] distinct sessions, read on the
/// emitting writer's snapshot.
///
/// # Errors
///
/// Storage errors, and an undecodable Δ or proposal row.
pub(super) fn observed_support_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cluster: &SubstitutionCluster,
) -> Result<bool> {
    let mut observations = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    for receipt in &cluster.receipt_refs {
        if let Some((turn, session)) = receipt_observation(vault, txn, receipt)? {
            observations.insert(turn);
            sessions.insert(session);
        }
    }
    Ok(observations.len() >= OBSERVED_PREFERENCE_MIN_OBSERVATIONS
        && sessions.len() >= OBSERVED_PREFERENCE_MIN_SESSIONS)
}

/// The source TURN and its SESSION behind one cited receipt, when every link
/// resolves.
fn receipt_observation(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &str,
) -> Result<Option<(EntityId, EntityId)>> {
    let Some(delta) = captured_amendment_delta_in_txn(vault, txn, receipt)? else {
        return Ok(None);
    };
    let Some(artifact) = delta.proposed_ref.proposal_artifact() else {
        return Ok(None);
    };
    let Some(turn) = retained_proposal_in_txn(vault, txn, artifact)?
        .and_then(|proposal| proposal.record.source_turn_ref)
    else {
        return Ok(None);
    };
    if !is_live(vault, txn, &turn, ENTITY_TYPE_TURN)? {
        return Ok(None);
    }
    let Some(session) = turn_session_membership_in_txn(&vault.store, txn, &turn)? else {
        return Ok(None);
    };
    Ok(is_live(vault, txn, &session, ENTITY_TYPE_SESSION)?.then_some((turn, session)))
}

fn is_live(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId, entity_type: u8) -> Result<bool> {
    Ok(matches!(
        live_entity_row_in_txn(&vault.store, txn, id)?,
        LiveEntityRow::Live { entity_type: found, .. } if found == entity_type
    ))
}
