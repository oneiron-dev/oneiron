//! Grant-scoped home-node reads for opened-item devices.
//! App-tier bind provides the actor; request bytes never choose a principal.

#[cfg(test)]
mod tests;

use base64::Engine;
use oneiron::EntityId;
use oneiron::claim::ScopedReadActorKey;
use oneiron::sync::residence::{
    INDEX_PAGE_MAX, IndexPage, promotion_snapshot, selected_item_blob, window_index_page,
};
use oneiron::sync::schema::read_window_list;
use oneiron::sync::{SyncSelector, WindowKey, decode_sync_selector};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{AppError, CoreAuth, CoreScope, RpcRequest, rpc_error, rpc_result};
use crate::server::SyncServer;

const MAX_SEARCH_RESULTS: usize = 100;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexRequest {
    window: String,
    selector: String,
    #[serde(default)]
    after: Option<String>,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TouchRequest {
    window: String,
    selector: String,
    entity_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PromotionRequest {
    window: String,
    selector: String,
    entity_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRequest {
    query: String,
    limit: usize,
}

pub(super) fn run(
    server: &SyncServer,
    auth: &CoreAuth,
    request: RpcRequest,
) -> Result<Vec<Vec<u8>>, crate::protocol::ProtocolError> {
    let result = (|| {
        auth.require(CoreScope::Read)?;
        if !auth.credential_is_live(server.vault.as_ref()) {
            return Err(AppError::unauthorized());
        }
        match request.method.as_str() {
            "residence.index" => index(server, auth, request.params),
            "residence.touch" => touch(server, auth, request.params),
            "residence.promote" => promote(server, auth, request.params),
            "residence.search" => search(server, auth, request.params),
            _ => Err(AppError::bad_request(
                "unknown residence RPC",
                Some("method"),
            )),
        }
    })();
    match result {
        Ok(value) => rpc_result(request.request_id, value).or_else(|_| {
            rpc_error(
                request.request_id,
                AppError::bad_request("RPC result byte limit exceeded", None),
            )
        }),
        Err(error) => rpc_error(request.request_id, error),
    }
}

fn selected_window(
    server: &SyncServer,
    auth: &CoreAuth,
    key: &str,
    encoded_selector: &str,
) -> Result<(WindowKey, SyncSelector, loro::LoroDoc), AppError> {
    let window = WindowKey::try_new(key).ok_or_else(AppError::invalid_params)?;
    if !read_window_list(&server.root_doc).contains(&window) {
        return Err(AppError::not_found("item", None));
    }
    let selector_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded_selector)
        .map_err(|_| AppError::invalid_params())?;
    if selector_bytes.len() > 4096 {
        return Err(AppError::invalid_params());
    }
    let selector = decode_sync_selector(&selector_bytes).map_err(|_| AppError::invalid_params())?;
    let principal = EntityId::from_hex(
        auth.require_registered_principal()
            .map_err(|_| AppError::unauthorized())?,
    )
    .map_err(|_| AppError::unauthorized())?;
    if selector.member_ref != principal {
        return Err(AppError::not_found("item", None));
    }
    oneiron::sync::authorize_sync_selector(
        &server.vault,
        crate::handler::selector_grant_scope(),
        &selector,
    )
    .map_err(|_| AppError::not_found("item", None))?;
    let doc = server
        .reassert_manager
        .open_window(&window)
        .map_err(|_| AppError::internal_server_error("window unavailable"))?;
    Ok((window, selector, doc.doc.clone()))
}

fn index(server: &SyncServer, auth: &CoreAuth, params: Value) -> Result<Value, AppError> {
    let input: IndexRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let cursor = input
        .after
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| AppError::invalid_params())?;
    if input.limit == 0 || input.limit > INDEX_PAGE_MAX {
        return Err(AppError::invalid_params());
    }
    let (window, selector, doc) = selected_window(server, auth, &input.window, &input.selector)?;
    let proof = auth.verified_slip().ok_or_else(AppError::unauthorized)?;
    let actor = ScopedReadActorKey::from_verified_slip(proof).ok_or_else(AppError::unauthorized)?;
    let scoped = server.vault.scoped_read(actor);
    let items = window_index_page(
        &server.vault,
        &doc,
        &window,
        crate::handler::selector_grant_scope(),
        &selector,
        IndexPage {
            after: cursor,
            limit: input.limit,
        },
        |id| scoped.is_entity_readable(&id),
    )
    .map_err(|_| AppError::internal_server_error("index unavailable"))?;
    let next = (items.len() == input.limit)
        .then(|| items.last().map(|entry| entry.entity_id.clone()))
        .flatten();
    Ok(json!({"window": window.as_str(), "items": items, "nextCursor": next}))
}

fn touch(server: &SyncServer, auth: &CoreAuth, params: Value) -> Result<Value, AppError> {
    let input: TouchRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let id = EntityId::from_hex(&input.entity_id).map_err(|_| AppError::invalid_params())?;
    let (window, selector, doc) = selected_window(server, auth, &input.window, &input.selector)?;
    // A stored grant constrains the selector; the actor's live scoped-read
    // floor must ALSO admit the exact target. Either denial looks missing.
    let proof = auth.verified_slip().ok_or_else(AppError::unauthorized)?;
    let actor = ScopedReadActorKey::from_verified_slip(proof).ok_or_else(AppError::unauthorized)?;
    if !server
        .vault
        .scoped_read(actor)
        .is_entity_readable(&id)
        .map_err(|_| AppError::internal_server_error("item admission unavailable"))?
    {
        return Err(AppError::not_found("item", None));
    }
    let blob = selected_item_blob(
        &server.vault,
        &doc,
        &window,
        crate::handler::selector_grant_scope(),
        &selector,
        id,
    )
    .map_err(|_| AppError::internal_server_error("item unavailable"))?
    .ok_or_else(|| AppError::not_found("item", None))?;
    let document = server
        .reassert_manager
        .export_document_in_window(
            id,
            &window,
            crate::handler::selector_grant_scope(),
            &selector,
            &loro::VersionVector::new().encode(),
        )
        .map_err(|_| AppError::internal_server_error("item document unavailable"))?;
    Ok(json!({
        "window": window.as_str(),
        "entityId": id.to_hex(),
        "blob": base64::engine::general_purpose::STANDARD.encode(blob),
        "document": base64::engine::general_purpose::STANDARD.encode(document),
    }))
}

fn promote(server: &SyncServer, auth: &CoreAuth, params: Value) -> Result<Value, AppError> {
    let input: PromotionRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let id = EntityId::from_hex(&input.entity_id).map_err(|_| AppError::invalid_params())?;
    let (window, selector, doc) = selected_window(server, auth, &input.window, &input.selector)?;
    let proof = auth.verified_slip().ok_or_else(AppError::unauthorized)?;
    let actor = ScopedReadActorKey::from_verified_slip(proof).ok_or_else(AppError::unauthorized)?;
    let scoped = server.vault.scoped_read(actor);
    if !scoped
        .is_entity_readable(&id)
        .map_err(|_| AppError::internal_server_error("promotion admission unavailable"))?
        || selected_item_blob(
            &server.vault,
            &doc,
            &window,
            crate::handler::selector_grant_scope(),
            &selector,
            id,
        )
        .map_err(|_| AppError::not_found("item", None))?
        .is_none()
    {
        return Err(AppError::not_found("item", None));
    }
    let snapshot = promotion_snapshot(
        &server.vault,
        &doc,
        &window,
        crate::handler::selector_grant_scope(),
        &selector,
        |item| scoped.is_entity_readable(&item),
    )
    .map_err(|_| AppError::internal_server_error("window promotion unavailable"))?
    .ok_or_else(|| AppError::not_found("window promotion", None))?;
    Ok(json!({
        "window": window.as_str(),
        "snapshot": base64::engine::general_purpose::STANDARD.encode(snapshot),
    }))
}

fn search(server: &SyncServer, auth: &CoreAuth, params: Value) -> Result<Value, AppError> {
    let input: SearchRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    if input.query.trim().is_empty()
        || input.query.len() > 4096
        || input.limit == 0
        || input.limit > MAX_SEARCH_RESULTS
    {
        return Err(AppError::invalid_params());
    }
    auth.require_registered_principal()
        .map_err(|_| AppError::unauthorized())?;
    let proof = auth.verified_slip().ok_or_else(AppError::unauthorized)?;
    let actor = ScopedReadActorKey::from_verified_slip(proof).ok_or_else(AppError::unauthorized)?;
    let result = server
        .vault
        .scoped_read(actor)
        .search_text(&input.query, input.limit, None)
        .map_err(|_| AppError::internal_server_error("scoped search unavailable"))?;
    let hits: Vec<_> = result
        .value
        .iter()
        .map(|hit| json!({"entityId": hit.id.to_hex(), "score": hit.score}))
        .collect();
    Ok(json!({"hits": hits, "source": "home", "complete": true}))
}
