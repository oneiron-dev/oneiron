//! Consolidated SameAs (FIX 8363, L02 02:15).
//!
//! The Dreamer's nightly continuations judge two consolidated proposal CLAIMs
//! one and write a PROPOSED `core.coreference.status` claim on their SameAs
//! EdgeRef. While the owner's own standing grant lets it, the edge is applied
//! in that same transaction, here: the link and its status still land
//! together, the writer's actor and endpoint checks are the ones
//! [`put_coreference_link`](super::put_coreference_link) runs, and the
//! grant's use leaves its Gate receipt. The endpoints are CLAIMs, not
//! PERSONs, so the PERSON pair rule is this writer's CLAIM pair rule, and no
//! link of this kind is ever confirmed here.

use crate::affect::Vad;
use crate::batch::BatchOp;
use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

use super::{COREFERENCE_LINK_WEIGHT, require_coreference_actor};

/// The domain of a consolidated link's grant-use effect digest.
const CONSOLIDATED_SAME_AS_DOMAIN: &[u8] = b"oneiron:consolidated-same-as:v1";

/// One SameAs the Dreamer applies between two consolidated proposals.
pub(crate) struct ConsolidatedSameAs<'a> {
    /// The Dreamer's System actor, which wrote the status claim.
    pub(crate) actor: WriteActor,
    pub(crate) source: EntityId,
    pub(crate) target: EntityId,
    /// The link's PROPOSED status claim, written in the same transaction.
    pub(crate) status_claim: EntityId,
    /// The owner's standing grant it applies under, read in that transaction.
    pub(crate) grant_ref: &'a str,
}

/// The checks [`put_coreference_link`](super::put_coreference_link) runs
/// before its transaction, for a consolidated link: its actor through
/// [`require_coreference_actor`] and both endpoints present. Run before the
/// write that applies the link opens.
///
/// # Errors
///
/// The actor gate's errors, and [`Error::EntityNotFound`] for an absent
/// endpoint.
pub(crate) fn check_consolidated_same_as(
    vault: &Vault,
    actor: &WriteActor,
    source: EntityId,
    target: EntityId,
) -> Result<()> {
    require_coreference_actor(vault, actor)?;
    if !vault.entity_exists(&source)? || !vault.entity_exists(&target)? {
        return Err(Error::EntityNotFound);
    }
    Ok(())
}

/// Applies `link` in `txn`, the write that lands its status claim: both
/// endpoints live, unarchived CLAIMs; the status claim live, PROPOSED and on
/// exactly this link's EdgeRef; then the SameAs edge (weight
/// [`COREFERENCE_LINK_WEIGHT`]) and the status claim's `claim_of` edge to
/// the link's source, which the owning door supplies, and the grant's use
/// recorded as its Gate receipt naming `grant_ref`. An edge already there
/// is kept as it is.
///
/// # Errors
///
/// [`Error::EntityNotFound`] or [`Error::InvalidClaimBody`] for an endpoint
/// or status claim that does not hold, the consent door's errors for a grant
/// no longer active, and any batch failure. The caller rolls back the write.
pub(crate) fn put_consolidated_same_as_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    link: &ConsolidatedSameAs<'_>,
) -> Result<()> {
    if link.source == link.target {
        return Err(Error::InvalidClaimBody(
            "a consolidated same_as joins two claims",
        ));
    }
    for id in [link.source, link.target] {
        let claim = matches!(
            crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?,
            crate::vault::LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                ..
            }
        );
        if !claim || vault.archive_tombstone_in_txn(txn, &id)?.is_some() {
            return Err(Error::EntityNotFound);
        }
    }
    let subject = ClaimSubject::Edge {
        source: link.source,
        kind: EdgeKind::SameAs,
        target: link.target,
    };
    let status = vault
        .get_claim_in_txn(txn, &link.status_claim)?
        .ok_or(Error::EntityNotFound)?;
    if status.predicate != crate::claim::PREDICATE_COREFERENCE_STATUS
        || status.lifecycle != ClaimLifecycleStatus::Active
        || status.subject != subject
        || status.value.as_str() != Some(crate::claim::COREFERENCE_STATUS_PROPOSED)
    {
        return Err(Error::InvalidClaimBody(
            "a consolidated same_as needs its proposed status claim",
        ));
    }
    let mut ops = Vec::new();
    if vault
        .store
        .port_edge_get(txn, &link.source, EdgeKind::SameAs, &link.target)?
        .is_none()
    {
        ops.push(BatchOp::Edge {
            src: link.source,
            kind: EdgeKind::SameAs,
            tgt: link.target,
            weight: COREFERENCE_LINK_WEIGHT,
            vad: Vad::NEUTRAL,
        });
    }
    if vault
        .store
        .port_edge_get(txn, &link.status_claim, EdgeKind::ClaimOf, &link.source)?
        .is_none()
    {
        ops.push(BatchOp::Edge {
            src: link.status_claim,
            kind: EdgeKind::ClaimOf,
            tgt: link.source,
            weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
            vad: Vad::NEUTRAL,
        });
    }
    if !ops.is_empty() {
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            ops,
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
    }
    let mut digest = blake3::Hasher::new();
    digest.update(CONSOLIDATED_SAME_AS_DOMAIN);
    digest.update(link.source.as_bytes());
    digest.update(link.target.as_bytes());
    digest.update(link.status_claim.as_bytes());
    vault.record_standing_grant_use_in_txn(
        txn,
        link.grant_ref,
        crate::consent::EffectDigest::from_bytes(*digest.finalize().as_bytes()),
    )?;
    Ok(())
}

/// The owner's removal of a consolidated SameAs (FIX 8363):
/// [`unlink_coreference_link`](super::unlink_coreference_link) takes PERSON
/// endpoints only, so a link between two consolidated CLAIMs is removed here
/// the same way. Both
/// orientations go and the link's live status claims are retracted, in one
/// transaction; the two proposal claims stay.
///
/// # Errors
///
/// Returns an owner-proof error, [`Error::InvalidClaimBody`] for an endpoint
/// that is not a CLAIM, [`Error::EdgeNotFound`] for a missing link, or a
/// claim-lifecycle or batch error. Any failure rolls back the whole unlink.
pub fn unlink_consolidated_same_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    source: EntityId,
    target: EntityId,
) -> Result<Vec<EntityId>> {
    vault.with_write_txn_grouped(|wtxn| {
        let actor = WriteActor::new(
            owner.revalidate_in_txn(vault, wtxn)?,
            crate::edge::EdgeActorClass::Human,
        );
        for id in [source, target] {
            if vault.get_entity_type_in_txn(wtxn, &id)? != Some(crate::registry::ENTITY_TYPE_CLAIM)
            {
                return Err(Error::InvalidClaimBody(
                    "a consolidated same_as joins two claims",
                ));
            }
        }
        let mut ops = Vec::new();
        let mut claims = std::collections::BTreeSet::new();
        for (from, to) in [(source, target), (target, source)] {
            if vault
                .store
                .port_edge_get(wtxn, &from, EdgeKind::SameAs, &to)?
                .is_some()
            {
                ops.push(BatchOp::DeleteEdge {
                    src: from,
                    kind: EdgeKind::SameAs,
                    tgt: to,
                });
            }
            let link = ClaimSubject::Edge {
                source: from,
                kind: EdgeKind::SameAs,
                target: to,
            };
            for claim in vault.claims_for_subject_in_txn(wtxn, &from)? {
                let Some(body) = vault.get_claim_in_txn(wtxn, &claim)? else {
                    continue;
                };
                if body.lifecycle == ClaimLifecycleStatus::Active
                    && body.predicate == crate::claim::PREDICATE_COREFERENCE_STATUS
                    && body.subject == link
                {
                    claims.insert(claim);
                }
            }
        }
        if ops.is_empty() {
            return Err(Error::EdgeNotFound);
        }
        let now = vault.now_recorded_at();
        for claim in &claims {
            vault.retract_claim_in_txn_as(wtxn, claim, now, Some(actor))?;
        }
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            ops,
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(claims.into_iter().collect())
    })
}
