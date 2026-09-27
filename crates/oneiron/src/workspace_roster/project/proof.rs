//! Signed project revision admission, common to local, batch and replicated puts.
use super::*;
use crate::authority::{CapabilitySlip, authority_fold_readonly_for_store_in_txn};
use crate::error::RecordError;
use crate::federation::{ScopeAxis, ScopeId};
use crate::store::Store;

fn refused(reason: &'static str) -> Error {
    RecordError::InvalidProjectBody(reason).into()
}

pub(crate) fn validate_transition(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    bytes: &[u8],
    posture: crate::HostingPrivacyPosture,
) -> Result<()> {
    let next: ProjectRecord = decode(bytes).map_err(|_| refused("invalid project body"))?;
    let prior = record::<ProjectRecord>(store, txn, id, kind)?;
    let root = store.vault_meta.get(txn, ROOT)?;
    // Only the initial vault bootstrap writes an unproved root. The root
    // binding and row are committed atomically by seed_root_project.
    if prior.is_none()
        && root.is_none()
        && store.vault_meta.get(txn, ROOT_SEEDING)?.as_deref() == Some(id.as_bytes())
        && next.parents.is_empty()
        && next.claims_scope_ref == id.to_hex()
    {
        return Ok(());
    }
    if next.parents.is_empty() && root.as_deref() != Some(id.as_bytes()) {
        return Err(refused("only the vault root has no project parent"));
    }
    let mut parents = Vec::new();
    for parent in &next.parents {
        let parent_id = EntityId::from_hex(parent).map_err(|_| refused("invalid parent id"))?;
        parents.push((
            parent_id,
            super::projection::dependency(store, txn, parent_id, kind)?,
        ));
    }
    let proof = next
        .write_proof
        .as_ref()
        .ok_or_else(|| refused("missing project write proof"))?;
    let slip = CapabilitySlip::from_token(&proof.slip_wire)
        .map_err(|_| refused("invalid project write slip"))?;
    let fold = authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    let mint = fold
        .slips
        .mints
        .get(&slip.claims.slip_id)
        .ok_or_else(|| refused("project write slip not minted"))?;
    let floor = store
        .sync_state
        .get(txn, crate::authority::authority_first_seen_clock_sync_key())?
        .and_then(|raw| crate::authority::decode_authority_first_seen_secs(&raw))
        .unwrap_or(0);
    let now =
        crate::authority::authority_observation_secs(store, floor, store.clock.now_recorded_at());
    let verified = slip
        .verify_with_host_key(
            &mint.signer,
            &fold,
            now,
            &next.write_challenge(id)?,
            &proof.holder_signature,
        )
        .map_err(|_| refused("invalid project write proof"))?;
    let claims = verified.claims();
    let actor = &claims.holder_ref;
    let scope = verified.scope();
    if !scope.verbs.contains(&"project.write".to_owned())
        || !scope.bands.contains(&kind)
        || !scope
            .worlds
            .contains(&ScopeId(next.slice.world.unwrap_or(id)))
            && !matches!(scope.worlds, ScopeAxis::All)
        || next
            .slice
            .facet
            .is_some_and(|facet| !scope.facets.contains(&ScopeId(facet)))
    {
        return Err(refused("project write outside slip scope"));
    }
    let board_action = prior.as_ref().is_some_and(|old| {
        old.parents != next.parents
            || old.leader != next.leader
            || old.depth_limit < next.depth_limit
            || old.depth_remaining < next.depth_remaining
            || old.slice.attenuate(next.slice.clone()).is_err()
            || old.board != next.board
            || old.claims_scope_ref != next.claims_scope_ref
    });
    if let Some(old) = &prior {
        if !scope.audience.contains(&ScopeId(id)) && old != &next {
            return Err(refused("project write outside slip audience"));
        }
        if !board_action && old.leader != *actor {
            return Err(refused("only leader may update project"));
        }
        if board_action
            && !old.board.contains(actor)
            && !(root.as_deref() == Some(id.as_bytes()) && actor == "host")
        {
            return Err(refused("project widening needs board holder proof"));
        }
    } else {
        let (parent_id, parent) = parents
            .first()
            .ok_or_else(|| refused("missing project parent"))?;
        if parent.leader != *actor
            || slip.caveats.is_empty()
            || !scope.audience.contains(&ScopeId(*parent_id))
        {
            return Err(refused("project spawn needs parent leader slip"));
        }
    }
    // The project's hierarchy is a meet: even a board action cannot widen
    // a descendant beyond any current parent; a wider parent is the board's
    // separate, explicit mutation.
    for (_, parent) in &parents {
        if next.depth_limit > parent.depth_limit
            || next.depth_remaining >= parent.depth_remaining
            || parent.slice.attenuate(next.slice.clone()).is_err()
        {
            return Err(refused("project slice exceeds parent"));
        }
    }
    Ok(())
}
