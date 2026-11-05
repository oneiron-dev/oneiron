//! Read-only own-peer text vectors; these bytes never enter a canonical window root.

use std::collections::BTreeSet;

use super::*;
use oneiron::sync::residence::residence_window_for_blob;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MediaVectorsRequest {
    selector: String,
    space: String,
    id: EntityId,
}

pub(super) fn media_vectors(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: MediaVectorsRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let PeerMachine::Proven { machine, .. } = server.vault.peer_machine_stands(peer) else {
        return Err(AppError::not_found("item", None));
    };
    let selector = bound_selector(server, auth, &input.selector)?;
    let admission = admitted(server, auth, peer, &selector)?;
    if admission.destination() != Destination::Machine(machine)
        || !admission.allows_item(input.id).map_err(unavailable)?
    {
        return Err(AppError::not_found("item", None));
    }
    let grant = server
        .vault
        .get_raw(&selector.grant_id)
        .map_err(unavailable)?;
    let mut selected = Vec::new();
    for replica in server
        .vault
        .text_media_vector_replicas(&input.id, &input.space)
        .map_err(unavailable)?
    {
        if replica.space_id() != input.space {
            continue;
        }
        if full_sources_match(server, &selector, &admission, replica.sources())? {
            selected.push(replica);
        }
    }
    // Re-admit after point reads and recheck each complete source image.
    bound_selector(server, auth, &input.selector)?;
    let current = admitted(server, auth, peer, &selector)?;
    if current.destination() != Destination::Machine(machine)
        || !matches!(
            server.vault.peer_machine_stands(peer),
            PeerMachine::Proven { .. }
        )
    {
        return Err(AppError::not_found("item", None));
    }
    let mut released = Vec::new();
    let mut rows = BTreeSet::new();
    for replica in selected {
        if full_sources_match(server, &selector, &current, replica.sources())? {
            rows.extend(replica.sources().iter().map(|(id, _)| *id));
            released.push(replica);
        }
    }
    let rows: Vec<_> = rows.into_iter().collect();
    if !auth.credential_is_live(server.vault.as_ref())
        || server
            .vault
            .get_raw(&selector.grant_id)
            .map_err(unavailable)?
            != grant
        || !current.rows_may_leave(&rows).map_err(unavailable)?
    {
        return Err(AppError::not_found("item", None));
    }
    Ok((json!(released), Some(rows)))
}

fn full_sources_match(
    server: &SyncServer,
    selector: &SyncSelector,
    admission: &ResidenceAdmission<'_>,
    sources: &[(EntityId, [u8; 32])],
) -> Result<bool, AppError> {
    for (id, digest) in sources {
        if !admission.allows_item(*id).map_err(unavailable)? {
            return Ok(false);
        }
        let Some(raw) = server.vault.get_raw(id).map_err(unavailable)? else {
            return Ok(false);
        };
        let window = residence_window_for_blob(&raw).map_err(unavailable)?;
        if !read_window_list(&server.root_doc).contains(&window) {
            return Ok(false);
        }
        let held = server
            .reassert_manager
            .open_window(&window)
            .map_err(unavailable)?;
        let Some(blob) = selected_item_blob_with(
            &server.vault,
            &held.doc,
            &window,
            crate::handler::selector_scope::selector_grant_scope(),
            selector,
            admission.withhold(),
            *id,
        )
        .map_err(unavailable)?
        else {
            return Ok(false);
        };
        if blake3::hash(&blob).as_bytes() != digest {
            return Ok(false);
        }
    }
    Ok(true)
}

fn unavailable(_: oneiron::Error) -> AppError {
    AppError::internal_server_error("media vector read unavailable")
}
