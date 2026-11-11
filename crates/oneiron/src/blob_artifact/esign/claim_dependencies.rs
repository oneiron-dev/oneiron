//! The records an `esign.*` claim reads beside (FIX 6945 A): its signing
//! document and every original artifact that document's trail names. The
//! credential lane and the scoped record doors judge an e-sign claim beside
//! these records, as `vault.esign.get` judges its caller beside them
//! (`lane_scope`); a claim whose dependencies do not resolve is refused,
//! never admitted without them.

use super::ledger::delivery_chain_in;
use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};
use crate::{EntityId, Result, Vault};

/// The records an `esign.*` claim is admitted beside: its signing document
/// and every original artifact the document's trail names, in one order, or
/// that this rule does not judge the claim, or that the claim is refused.
pub(crate) enum EsignClaimDependencies {
    /// Not an `esign.*` claim: this rule does not judge it.
    NotEsign,
    /// The signing document first, then each original artifact, in item order.
    Records(Vec<EntityId>),
    /// An `esign.*` claim whose document or originals do not resolve: refuse it.
    Unresolved,
}

/// The records the claim `body` reads beside in `txn`: its signing document
/// first, then each original artifact the document's trail names, in item
/// order. Only an `esign.*` claim with an entity subject is judged; its
/// trail is the fold `esign_get` reads, held events included. A ref that is
/// no id, a subject that is no entity, and a trail that does not read or
/// folds to no document are [`EsignClaimDependencies::Unresolved`], never
/// admitted without the records.
/// # Errors
/// The store's own failure. Only trail refusals become `Unresolved`.
pub(crate) fn esign_claim_dependencies_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<EsignClaimDependencies> {
    if !body.predicate.starts_with("esign.") {
        return Ok(EsignClaimDependencies::NotEsign);
    }
    let ClaimSubject::Entity(document) = body.subject else {
        return Ok(EsignClaimDependencies::Unresolved);
    };
    let Some((state, _)) = delivery_chain_in(vault, txn, document)? else {
        return Ok(EsignClaimDependencies::Unresolved);
    };
    let mut records = vec![document];
    for item in &state.document.items {
        let Ok(artifact) = EntityId::from_hex(&item.artifact_ref) else {
            return Ok(EsignClaimDependencies::Unresolved);
        };
        records.push(artifact);
    }
    Ok(EsignClaimDependencies::Records(records))
}
