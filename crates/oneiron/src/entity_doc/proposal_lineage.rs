//! Core half of `entity_doc::proposal_lineage`: its store-layer items live in `oneiron_store::entity_doc::proposal_lineage` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::entity_doc::proposal_lineage::*;

use super::forks::{DocAuthorization, ProposalBundle};
use super::invalid;
use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{ArtifactError, Error, Result};

/// The lineage an opening under `authorization` freezes, read in `txn`'s
/// authority snapshot: an owner proof's credential chains, else none.
pub(super) fn opening_lineage(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authorization: &DocAuthorization<'_>,
) -> Result<Vec<[u8; 32]>> {
    match authorization {
        DocAuthorization::Owner(owner) => owner.credential_lineage_in_txn(vault, txn),
        DocAuthorization::StandingGrant | DocAuthorization::ProposeOnly => Ok(Vec::new()),
    }
}

/// Adds `lineage` to what `bundle` froze: an opening that joins a bundle
/// later freezes its own lineage beside the first, so neither settles it.
pub(super) fn freeze(bundle: &mut ProposalBundle, lineage: &[[u8; 32]]) {
    for slip in lineage {
        let slip = bytes_to_hex_lower(slip);
        if !bundle.opener_lineage.contains(&slip) {
            bundle.opener_lineage.push(slip);
        }
    }
}

/// The lineage `bundle` froze, as slip ids.
pub(super) fn frozen(bundle: &ProposalBundle) -> Result<Vec<[u8; 32]>> {
    bundle
        .opener_lineage
        .iter()
        .map(|slip| slip_id(slip).ok_or_else(|| invalid("proposal opener lineage")))
        .collect()
}

/// Refuses an explicit verdict on `bundle` whose owner proof answers from
/// the lineage that opened it, or from a fork of it, in `txn`'s authority
/// snapshot. A verdict under a standing grant, a bundle that froze no
/// lineage, and a proof no credential carried are never refused here.
pub(super) fn refuse_opener_verdict(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authorization: &DocAuthorization<'_>,
    bundle: &ProposalBundle,
) -> Result<()> {
    let DocAuthorization::Owner(owner) = authorization else {
        return Ok(());
    };
    if owner.answers_from_slip_lineage_in_txn(vault, txn, &frozen(bundle)?)? {
        return Err(Error::Artifact(ArtifactError::SettleNotAuthorized(
            "the lineage that opened a proposal cannot settle it",
        )));
    }
    Ok(())
}
