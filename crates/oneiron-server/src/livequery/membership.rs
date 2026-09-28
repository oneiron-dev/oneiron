//! Insertion/edge membership checks, separate from served entity dependencies.
use super::*;
use oneiron::sync::bridge::MaterializedDiffSummary;
use std::collections::BTreeSet;

pub(super) fn changed(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    view: &ScopedView,
    channel: Channel,
    diff: &MaterializedDiffSummary,
) -> Result<bool, AppError> {
    let memory = bound_memory(vault, auth)?;
    // Gate receipts have no entity document of their own. Their channel is
    // deliberately a governance-membership probe, not a window dependency.
    if channel != Channel::View {
        return Ok(true);
    }
    let ids: BTreeSet<_> = diff
        .containers
        .iter()
        .filter_map(|path| path.strip_prefix("e:"))
        .filter_map(|id| oneiron::EntityId::from_hex(id).ok())
        .collect();
    if ids.is_empty() {
        return Ok(true);
    } // metadata/authority change, no fabricated entity id
    let world = view
        .world_ref
        .as_deref()
        .map(|world| {
            memory
                .get_entity(world)
                .map_err(AppError::from)
                .and_then(|entity| {
                    // A membership probe serves no row, so no receipt leaves it.
                    entity
                        .value
                        .map(|entity| entity.id_hex)
                        .ok_or_else(|| AppError::bad_request("unknown world", Some("worldRef")))
                })
        })
        .transpose()?;
    let kind = view
        .filter
        .as_ref()
        .and_then(|v| v.get("kind"))
        .and_then(Value::as_str);
    let predicate = view
        .filter
        .as_ref()
        .and_then(|v| v.get("predicate"))
        .and_then(Value::as_str);
    for id in ids {
        // Metadata is used only to decide whether the authority-bound view
        // needs re-derivation. No raw entity body is sent to a subscriber.
        let Some(entity) = memory
            .get_entity(&id.to_hex())
            .map_err(AppError::from)?
            .value
        else {
            return Ok(true);
        };
        let entity_type = vault
            .get_entity_type(&id)
            .map_err(|_| AppError::internal_server_error("membership type read failed"))?;
        if entity_type == Some(oneiron::registry::ENTITY_TYPE_ACCESS_GRANT) {
            return Ok(true);
        }
        if kind.is_some_and(|kind| kind != entity.kind) {
            continue;
        }
        let claim = if entity_type == Some(oneiron::registry::ENTITY_TYPE_CLAIM) {
            vault
                .get_claim(&id)
                .map_err(|_| AppError::internal_server_error("membership read failed"))?
        } else {
            None
        };
        if let Some(claim) = claim {
            if claim.world.map(|id| id.to_hex()) == world
                && predicate.is_none_or(|predicate| predicate == claim.predicate)
            {
                return Ok(true);
            }
        } else if world.is_none() && predicate.is_none() {
            return Ok(true);
        }
    }
    Ok(false)
}
