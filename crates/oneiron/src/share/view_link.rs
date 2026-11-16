//! One live brief share, bound to the recipient who redeems its view link.

use super::{Share, read_share_in_txn, verify_share_actor};
use crate::access_grant::AccessGrantStatus;
use crate::edge::EdgeActorClass;
use crate::error::{Error, RecordError, Result};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

pub(crate) fn live_share_for_holder_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    share_id: &EntityId,
    holder: &EntityId,
    now: u64,
) -> Result<Option<Share>> {
    let Some((share, _)) = read_share_in_txn(&vault.store, txn, share_id)? else {
        return Ok(None);
    };
    // The share's end is a wall-clock edge handed to its recipient (DEC-0006
    // duration amendment; `AccessGrant::expires_at`): a caller's slip-clock
    // `now` can bring it forward, never put it back past the recording clock.
    let at = now.max(crate::ports::job_recorded_at_in_txn(&vault.store, txn)?);
    if share.recipient_ref != *holder
        || share.grant().effective_status_at(at) != AccessGrantStatus::Active
        || !crate::vault::live_entity_row_in_txn(&vault.store, txn, share_id)?.is_live()
    {
        return Ok(None);
    }
    Ok(Some(share))
}

pub(crate) fn authorize_share_link_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    share_id: &EntityId,
    actor: &WriteActor,
    now: u64,
) -> Result<Share> {
    let refused = || {
        Error::Record(RecordError::AuthorityRefused(
            "share link requires issuer or owner",
        ))
    };
    let (share, admission) = read_share_in_txn(&vault.store, txn, share_id)?.ok_or_else(refused)?;
    verify_share_actor(&vault.store, txn, actor).map_err(|error| match error {
        Error::EntityNotFound => refused(),
        error => error,
    })?;
    if Some(*actor) != admission.issuer {
        let fold = vault.authority_fold_readonly_in_txn(txn)?;
        if actor.actor_class() != EdgeActorClass::Human
            || fold.vault_root_is_conflicted()
            || !crate::authority::actor_binding_is_active(&fold, &actor.entity_ref(), "human")
        {
            return Err(refused());
        }
    }
    live_share_for_holder_in_txn(vault, txn, share_id, &share.recipient_ref, now)?
        .ok_or_else(refused)
}

/// A bound view's non-claim prompt sources, judged under the current share's
/// maximum before their ordinary native read. The brief carrier is not a
/// prompt source read, so this never narrows its base-world NOTE lane.
pub(crate) fn share_prompt_sources(
    vault: &Vault,
    read: &crate::claim::ScopedRead<'_>,
    share_id: &EntityId,
    viewer: &EntityId,
    narrowing: Option<&super::ShareViewerScope>,
    sources: &[EntityId],
) -> Result<Option<std::collections::BTreeSet<EntityId>>> {
    use crate::ports::EntityStoreRead;
    use oneiron_authority::federation::ScopeAxis;

    let txn = vault.store.env.read_txn()?;
    if read.actor_key().share_view_ref() != Some(*share_id)
        || read.actor_key().actor_ref() != viewer.to_hex()
        || !read.proof_live_in(&txn)?
    {
        return Ok(None);
    }
    let now = vault.instant_in_txn(&txn)?.secs();
    let Some(share) = live_share_for_holder_in_txn(vault, &txn, share_id, viewer, now)? else {
        return Ok(None);
    };
    let mut maximum = super::ShareViewerScope {
        world_refs: share.world_refs,
        facet_refs: share.facet_refs,
        include_unscoped: share.include_unscoped,
    };
    if let Some(narrowing) = narrowing {
        maximum
            .world_refs
            .retain(|id| narrowing.world_refs.contains(id));
        maximum
            .facet_refs
            .retain(|id| narrowing.facet_refs.contains(id));
        maximum.include_unscoped &= narrowing.include_unscoped;
    }
    let store = read.store_read();
    let mut permitted = std::collections::BTreeSet::new();
    for source in sources {
        let Some(row) = store.port_entity_record(&txn, source)? else {
            continue;
        };
        let Some(scope) =
            crate::federation::record_scope::scope_for_blob(&store, &txn, *source, &row.encode())?
        else {
            continue;
        };
        let world = match &scope.worlds {
            ScopeAxis::Some(worlds) => worlds.iter().any(|world| {
                maximum.world_refs.contains(&world.0)
                    || (maximum.include_unscoped && world.0 == crate::claim::base_world_id())
            }),
            ScopeAxis::All => maximum.include_unscoped,
            ScopeAxis::Bottom => false,
        };
        let facet = match &scope.facets {
            ScopeAxis::Some(facets) if !facets.is_empty() => facets
                .iter()
                .any(|facet| maximum.facet_refs.contains(&facet.0)),
            ScopeAxis::All => maximum.include_unscoped,
            ScopeAxis::Bottom | ScopeAxis::Some(_) => false,
        };
        if world && facet {
            permitted.insert(*source);
        }
    }
    Ok(Some(permitted))
}
