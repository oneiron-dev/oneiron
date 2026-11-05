//! Core half of `origin::document_candidates::projected_source`: its store-layer items live in `oneiron_store::origin::document_candidates::projected_source` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the queue and landing seams call it in 2b-ii-B"
)]

pub(crate) use oneiron_store::origin::document_candidates::projected_source::*;

use super::projected::RepoProjectedCandidatePins;
use crate::error::Result;
use crate::git_wire::GitOid;
use crate::origin::secret_projection::claims::{
    RepoProjectionClaim, RepoProjectionRecord, RepoProjectionTranslation,
};
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};

/// The translation record `pins` stand on for `candidate` of the receive
/// `operation`; `None` while the pins name no ORIGINAL base or a tip that
/// does not parse.
fn translation(
    pins: &RepoProjectedCandidatePins,
    candidate: EntityId,
    operation: EntityId,
) -> Option<RepoProjectionClaim> {
    let canonical_base = GitOid::parse_hex(pins.canonical_base.clone()?).ok()?;
    let submitted_new = GitOid::parse_hex(pins.submitted_new.clone()).ok()?;
    let canonical_target = match &pins.canonical_target_tree {
        Some(tree) => Some(GitOid::parse_hex(tree.clone()).ok()?),
        None => None,
    };
    Some(RepoProjectionClaim::of(
        pins.graph,
        RepoProjectionRecord::Translation(RepoProjectionTranslation {
            candidate,
            operation,
            submitted_new,
            canonical_base,
            canonical_target,
            pins: pins.digest(),
        }),
    ))
}

/// Writes the translation record of `candidate` once, with the candidate.
/// `false` when it already stands or the pins name no ORIGINAL base.
///
/// # Errors
/// A store failure, or another record under its id.
pub(crate) fn record_projected_translation_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    pins: &RepoProjectedCandidatePins,
    candidate: EntityId,
    operation: EntityId,
    at: u64,
) -> Result<bool> {
    match translation(pins, candidate, operation) {
        Some(record) => record.put_in_txn(vault, wtxn, at),
        None => Ok(false),
    }
}

/// Whether `candidate`'s projected source stands in `txn`: the ingress
/// proof its pins name, for `operation` under its graph, and its
/// translation record, each exactly as written.
///
/// # Errors
/// A store failure, or a record that does not decode.
pub(crate) fn require_projected_candidate_source_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    pins: &RepoProjectedCandidatePins,
    candidate: EntityId,
    operation: EntityId,
) -> Result<bool> {
    let Some(ingress) =
        RepoProjectionClaim::load_ingress_in_txn(vault, txn, &pins.graph, &operation)?
    else {
        return Ok(false);
    };
    let proof = RepoProjectionClaim::of(pins.graph, RepoProjectionRecord::Ingress(ingress));
    if proof.id()? != pins.ingress {
        return Ok(false);
    }
    match translation(pins, candidate, operation) {
        Some(record) => record.stands_in_txn(vault, txn),
        None => Ok(false),
    }
}
