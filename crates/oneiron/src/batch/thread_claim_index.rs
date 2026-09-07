//! Thread claims reuse the existing ClaimOf index at every storage door.
use super::*;
use crate::affect::Vad;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

pub(super) fn index_thread_claim_subject(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Result<()> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvariantViolation("validated thread claim subject"));
    };
    let removed = reconcile_claim_of_edges(store, wtxn, id, Some(subject))?;
    for old in removed {
        crate::ppr::invalidate_ppr_for_edge(store, wtxn, id, &old)?;
    }
    // Structural ClaimOf edges are derived from the subject, including when a
    // replicated owner has not arrived yet. The reader checks owner type.
    apply_edge_with_created_at(
        store,
        wtxn,
        *id,
        EdgeKind::ClaimOf,
        subject,
        crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
        learned_at,
        Vad::NEUTRAL,
        None,
    )?;
    crate::ppr::invalidate_ppr_for_edge(store, wtxn, id, &subject)
}
