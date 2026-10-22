//! A projection-bound push's ingress proof, reopened by recovery (FIX 7608
//! slice 2b-ii-A): the intent names the proof's id, and recovery reads it
//! back only when it stands for the very operation and canonical authority
//! the intent was accepted under. No live caller is inferred and no ingress
//! authority is made up.

use heed::RoTxn;

use super::authority_digest;
use crate::Vault;
use crate::claim::ClaimSubject;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::secret_projection::claims::{
    RepoProjectionClaim, RepoProjectionIngress, RepoProjectionRecord,
};
use crate::origin::smart_http::door::DoorAdmissionStamp;

/// What recovery reopens of an accepted projection-bound push: its copy
/// graph and its ingress record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionIngressRecovery {
    pub(crate) graph: EntityId,
    pub(crate) ingress: RepoProjectionIngress,
}

/// The ingress proof `proof` names for the recovered `stamp`, when it
/// stands for that very operation and authority; `None` otherwise, and the
/// intent then completes as it was accepted.
///
/// # Errors
/// A store failure, or a record that does not decode.
pub(crate) fn recover_projection_ingress(
    vault: &Vault,
    txn: &RoTxn<'_>,
    proof: &EntityId,
    stamp: &DoorAdmissionStamp,
) -> Result<Option<RepoProjectionIngressRecovery>> {
    let Some(body) = vault.get_claim_in_txn(txn, proof)? else {
        return Ok(None);
    };
    let ClaimSubject::Entity(graph) = body.subject else {
        return Ok(None);
    };
    let Some(ingress) =
        RepoProjectionClaim::load_ingress_in_txn(vault, txn, &graph, &stamp.operation_id)?
    else {
        return Ok(None);
    };
    let claim = RepoProjectionClaim::of(graph, RepoProjectionRecord::Ingress(ingress.clone()));
    if claim.id()? != *proof || ingress.authority != authority_digest(stamp)? {
        return Ok(None);
    }
    Ok(Some(RepoProjectionIngressRecovery { graph, ingress }))
}
