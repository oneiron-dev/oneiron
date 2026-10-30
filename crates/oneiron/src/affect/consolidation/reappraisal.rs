//! A claim-VAD reappraisal's exposure (FIX 9553, 11251). The derived state
//! claim lands on its source claim's world, relationship, scope, facet and
//! project, and its mean reads only the evidence turns at least as wide as
//! that claim, so it never lands wider than a turn it read. A turn more
//! private than the claim stays out of the claim's mean; its own VAD stays
//! on the turn.
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::Scope;
use crate::federation::record_scope::disclosure_scope_for_stored_row;
use crate::ports::EntityStoreRead;

/// `derived` on every audience axis of `source`.
pub(super) fn copy_claim_axes(derived: &mut ClaimBody, source: &ClaimBody) {
    derived.world = source.world;
    derived.rel.clone_from(&source.rel);
    derived.scope = source.scope.clone();
    derived.scope_facet = source.scope_facet;
    derived.scope_project = source.scope_project;
}

/// Whether `derived` stands on every audience axis of `source`.
pub(super) fn same_claim_axes(derived: &ClaimBody, source: &ClaimBody) -> bool {
    derived.world == source.world
        && derived.rel == source.rel
        && derived.scope == source.scope
        && derived.scope_facet == source.scope_facet
        && derived.scope_project == source.scope_project
}

/// The turns of `turns` whose stored position is no wider a reader set
/// than `claim`'s on every disclosure axis: every reader the claim admits
/// reads each of them. Without a stored position for the claim, or for a
/// turn, no wider-than check can hold, so that turn stays out.
pub(super) fn turns_within_claim(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: &EntityId,
    turns: impl IntoIterator<Item = EntityId>,
) -> Result<Vec<EntityId>> {
    let Some(claim_position) = stored_position(vault, txn, claim)? else {
        return Ok(Vec::new());
    };
    let mut within = Vec::new();
    for turn in turns {
        if stored_position(vault, txn, &turn)?
            .is_some_and(|position| discloses_within(&position, &claim_position))
        {
            within.push(turn);
        }
    }
    Ok(within)
}

/// Row `id`'s stored disclosure position, when it has one.
fn stored_position(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Option<Scope>> {
    let Some(raw) = vault.store.port_entity_raw(txn, id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    disclosure_scope_for_stored_row(
        &vault.store,
        txn,
        *id,
        header.entity_type,
        &raw[ENTITY_METADATA_HEADER_LEN..],
    )
}

/// Whether `turn` narrows to `claim` on the axes a read admits by (worlds,
/// bands, audience, sensitivity): a reader the claim's position admits
/// reads the turn too. Facets are a provenance mask, not judged here.
fn discloses_within(turn: &Scope, claim: &Scope) -> bool {
    turn.worlds.is_narrowing_of(&claim.worlds)
        && turn.bands.is_narrowing_of(&claim.bands)
        && turn.audience.is_narrowing_of(&claim.audience)
        && turn.sensitivity.is_narrowing_of(claim.sensitivity)
}
