//! Grant-scoped home-node reads for opened-item devices.
//! App-tier bind provides the actor; request bytes never choose a principal.

#[cfg(test)]
mod tests;

use base64::Engine;
use oneiron::EntityId;
use oneiron::claim::ScopedReadActorKey;
use oneiron::sync::residence::{
    INDEX_PAGE_MAX, IndexPage, WindowIndexEntry, home_search_candidates, index_selection_revision,
    promotion_snapshot, selected_item_blob, window_index_page, window_index_projection,
};
use oneiron::sync::residence_operation_budgets::ResidenceOperationBudgets;
use oneiron::sync::schema::read_window_list;
use oneiron::sync::{SyncSelector, WindowKey, decode_sync_selector};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{AppError, CoreAuth, CoreScope, RpcRequest, rpc_error, rpc_result};
use crate::server::SyncServer;

/// One revision-bound metadata projection per authenticated socket. Replacing
/// it on the next window keeps memory bounded and never caches a grant decision
/// across sockets or principals.
pub(crate) struct ResidenceIndexCache {
    window: WindowKey,
    selector: SyncSelector,
    revision: String,
    window_vv: Vec<u8>,
    grant_raw: Vec<u8>,
    authority: oneiron::authority::AuthorityFold,
    selection_revision: ([u8; 32], u64, u64),
    items: Vec<WindowIndexEntry>,
    pages: usize,
    budgets: ResidenceOperationBudgets,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexRequest {
    window: String,
    selector: String,
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    revision: Option<String>,
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
    selector: String,
}

pub(super) fn run(
    server: &SyncServer,
    auth: &CoreAuth,
    request: RpcRequest,
    index_cache: &mut Option<ResidenceIndexCache>,
) -> Result<Vec<Vec<u8>>, crate::protocol::ProtocolError> {
    let result = (|| {
        auth.require(CoreScope::Read)?;
        if !auth.credential_is_live(server.vault.as_ref()) {
            return Err(AppError::unauthorized());
        }
        let budgets = operation_budgets(server)?;
        match request.method.as_str() {
            "residence.index" => index(server, auth, request.params, index_cache, budgets),
            "residence.touch" => touch(server, auth, request.params),
            "residence.promote" => promote(server, auth, request.params),
            "residence.search" => search(server, auth, request.params, budgets),
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

fn operation_budgets(server: &SyncServer) -> Result<ResidenceOperationBudgets, AppError> {
    server
        .vault
        .residence_operation_budgets()
        .map_err(|_| AppError::internal_server_error("residence policy unavailable"))?
        .ok_or_else(|| AppError::internal_server_error("residence policy unavailable"))
}

fn bound_selector(
    server: &SyncServer,
    auth: &CoreAuth,
    encoded_selector: &str,
) -> Result<SyncSelector, AppError> {
    if encoded_selector.len() > 8192 {
        return Err(AppError::invalid_params());
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
    Ok(selector)
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
    let selector = bound_selector(server, auth, encoded_selector)?;
    let doc = server
        .reassert_manager
        .open_window(&window)
        .map_err(|_| AppError::internal_server_error("window unavailable"))?;
    Ok((window, selector, doc.doc.clone()))
}

fn index(
    server: &SyncServer,
    auth: &CoreAuth,
    params: Value,
    cache: &mut Option<ResidenceIndexCache>,
    budgets: ResidenceOperationBudgets,
) -> Result<Value, AppError> {
    let input: IndexRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let after = input
        .after
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| AppError::invalid_params())?;
    if input.limit == 0
        || input.limit > INDEX_PAGE_MAX
        || input.after.is_some() != input.revision.is_some()
    {
        return Err(AppError::invalid_params());
    }
    let page_limit = input.limit.min(budgets.index_page_limit);
    let (window, selector, doc) = selected_window(server, auth, &input.window, &input.selector)?;
    let proof = auth.verified_slip().ok_or_else(AppError::unauthorized)?;
    let actor = ScopedReadActorKey::from_verified_slip(proof).ok_or_else(AppError::unauthorized)?;
    let scoped = server.vault.scoped_read(actor);
    let current_vv = doc.oplog_vv().encode();
    let grant = server
        .vault
        .get_raw(&selector.grant_id)
        .map_err(|_| AppError::internal_server_error("index grant unavailable"))?
        .ok_or_else(|| AppError::not_found("grant", None))?;
    let authority = server
        .vault
        .authority_fold()
        .map_err(|_| AppError::internal_server_error("index authority unavailable"))?;
    let selection_revision = index_selection_revision(&server.vault)
        .map_err(|_| AppError::internal_server_error("index selection unavailable"))?;

    if after.is_none() {
        let entries = window_index_projection(
            &server.vault,
            &doc,
            &window,
            crate::handler::selector_grant_scope(),
            &selector,
            budgets.title_max_chars,
            |id| scoped.is_entity_readable(&id),
        )
        .map_err(|_| AppError::internal_server_error("index unavailable"))?;
        let bytes = entries
            .iter()
            .try_fold(0usize, |total, entry| {
                total.checked_add(
                    entry.entity_id.len() + entry.title.as_ref().map_or(0, String::len) + 8,
                )
            })
            .ok_or_else(|| AppError::bad_request("index metadata too large", None))?;
        if bytes > budgets.index_cache_bytes {
            return Err(AppError::bad_request("index metadata too large", None));
        }
        if doc.oplog_vv().encode() != current_vv
            || server
                .vault
                .get_raw(&selector.grant_id)
                .map_err(|_| AppError::internal_server_error("index grant unavailable"))?
                .as_deref()
                != Some(grant.as_slice())
            || server
                .vault
                .authority_fold()
                .map_err(|_| AppError::internal_server_error("index authority unavailable"))?
                != authority
            || index_selection_revision(&server.vault)
                .map_err(|_| AppError::internal_server_error("index selection unavailable"))?
                != selection_revision
        {
            *cache = None;
            return Err(index_changed());
        }
        let mut material = EntityId::now().as_bytes().to_vec();
        material.extend_from_slice(window.as_str().as_bytes());
        material.extend_from_slice(&current_vv);
        material.extend_from_slice(&grant);
        let revision = blake3::hash(&material).to_hex().to_string();
        *cache = Some(ResidenceIndexCache {
            window: window.clone(),
            selector: selector.clone(),
            revision,
            window_vv: current_vv.clone(),
            grant_raw: grant.clone(),
            authority: authority.clone(),
            selection_revision,
            items: entries,
            pages: 0,
            budgets,
        });
    }
    let retained = cache.as_mut().ok_or_else(index_changed)?;
    if retained.window != window
        || retained.selector != selector
        || input
            .revision
            .as_deref()
            .is_some_and(|revision| revision != retained.revision.as_str())
        || retained.window_vv != current_vv
        || retained.grant_raw != grant
        || retained.authority != authority
        || retained.selection_revision != selection_revision
        || retained.budgets != budgets
    {
        *cache = None;
        return Err(index_changed());
    }
    retained.pages = retained.pages.saturating_add(1);
    if retained.pages > budgets.max_index_pages {
        *cache = None;
        return Err(AppError::bad_request("index page budget exceeded", None));
    }
    let mut items = Vec::with_capacity(page_limit);
    let mut cursor = after;
    loop {
        let candidates = window_index_page(
            &retained.items,
            IndexPage {
                after: cursor,
                limit: page_limit,
            },
        )
        .map_err(|_| AppError::invalid_params())?;
        let count = candidates.len();
        for entry in candidates {
            if items.len() == page_limit {
                break;
            }
            let id = EntityId::from_hex(&entry.entity_id)
                .map_err(|_| AppError::internal_server_error("index entry malformed"))?;
            cursor = Some(id);
            if scoped
                .is_entity_readable(&id)
                .map_err(|_| AppError::internal_server_error("index admission unavailable"))?
            {
                items.push(entry);
            }
            if items.len() == page_limit {
                break;
            }
        }
        if items.len() == page_limit || count < page_limit {
            break;
        }
    }
    // Recheck after all point reads: a newly revoked grant or changed window
    // never publishes a mixed or stale page.
    if doc.oplog_vv().encode() != retained.window_vv
        || server
            .vault
            .get_raw(&selector.grant_id)
            .map_err(|_| AppError::internal_server_error("index grant unavailable"))?
            .as_deref()
            != Some(retained.grant_raw.as_slice())
        || server
            .vault
            .authority_fold()
            .map_err(|_| AppError::internal_server_error("index authority unavailable"))?
            != retained.authority
        || index_selection_revision(&server.vault)
            .map_err(|_| AppError::internal_server_error("index selection unavailable"))?
            != retained.selection_revision
    {
        *cache = None;
        return Err(index_changed());
    }
    let next = cursor
        .filter(|id| {
            retained
                .items
                .last()
                .is_some_and(|last| last.entity_id > id.to_hex())
        })
        .map(|id| id.to_hex());
    Ok(json!({
        "window": window.as_str(), "items": items, "nextCursor": next,
        "revision": retained.revision.as_str(),
    }))
}

fn index_changed() -> AppError {
    AppError::new(
        "INDEX_REVISION_CHANGED",
        "window index changed during paging",
        ["Restart the window index from the first page."],
    )
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

fn search(
    server: &SyncServer,
    auth: &CoreAuth,
    params: Value,
    budgets: ResidenceOperationBudgets,
) -> Result<Value, AppError> {
    let input: SearchRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    if input.query.trim().is_empty()
        || input.query.len() > budgets.search_query_max_bytes
        || input.limit == 0
        || input.limit > budgets.search_limit
    {
        return Err(AppError::invalid_params());
    }
    let selector = bound_selector(server, auth, &input.selector)?;
    let grant_before = server
        .vault
        .get_raw(&selector.grant_id)
        .map_err(|_| AppError::internal_server_error("grant unavailable"))?
        .ok_or_else(|| AppError::not_found("grant", None))?;
    let proof = auth.verified_slip().ok_or_else(AppError::unauthorized)?;
    let candidates = home_search_candidates(&server.vault, proof, &input.query, input.limit)
        .map_err(|_| AppError::internal_server_error("scoped search unavailable"))?;
    let current_windows: std::collections::HashSet<_> =
        read_window_list(&server.root_doc).into_iter().collect();
    let mut selected_by_window = std::collections::HashMap::new();
    let mut hits = Vec::with_capacity(input.limit);
    for (id, score, window) in candidates {
        if !current_windows.contains(&window) {
            continue;
        }
        if !selected_by_window.contains_key(&window) {
            let doc = server
                .reassert_manager
                .open_window(&window)
                .map_err(|_| AppError::internal_server_error("search window unavailable"))?;
            // Home search reads LMDB, whose latest local writes can be ahead of
            // an already-open Loro window. Mirror missing canonical rows before
            // applying the same grant selector used by first touch.
            oneiron::sync::window::reverse_rematerialize(&server.vault, &doc.doc, &window)
                .map_err(|_| AppError::internal_server_error("search window unavailable"))?;
            let selected = oneiron::sync::filtered_window_doc(
                &server.vault,
                &doc.doc,
                &window,
                crate::handler::selector_grant_scope(),
                &selector,
            )
            .map_err(|_| AppError::not_found("grant", None))?;
            selected_by_window.insert(window.clone(), selected);
        }
        let selected = selected_by_window
            .get(&window)
            .ok_or_else(|| AppError::internal_server_error("search window unavailable"))?;
        if matches!(
            selected.get_map("entities").get(&id.to_hex()),
            Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(_)))
        ) {
            hits.push(json!({"entityId": id.to_hex(), "score": score}));
            if hits.len() == input.limit {
                break;
            }
        }
    }
    // The app credential, grant and selector are rechecked after the search:
    // a revoked or replaced grant never returns a cached answer.
    bound_selector(server, auth, &input.selector)?;
    if server
        .vault
        .get_raw(&selector.grant_id)
        .map_err(|_| AppError::internal_server_error("grant unavailable"))?
        .as_deref()
        != Some(grant_before.as_slice())
    {
        return Err(AppError::not_found("grant", None));
    }
    Ok(json!({"hits": hits, "source": "home", "complete": true}))
}
