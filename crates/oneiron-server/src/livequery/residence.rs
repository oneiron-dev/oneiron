//! Grant-scoped home-node reads for opened-item devices.
//! App-tier bind provides the actor; request bytes never choose a principal.

#[cfg(test)]
pub(super) mod tests;

use base64::Engine;
use oneiron::EntityId;
use oneiron::authority::{Destination, PeerMachine};
use oneiron::sync::residence::{
    INDEX_PAGE_MAX, IndexPage, ResidenceAdmission, WindowIndexEntry, authority_tail_for,
    home_search_candidates, index_selection_revision, promotion_snapshot_with, sealed_shelf_after,
    sealed_shelf_packet, selected_item_blob_with, shelve_sealed_window, window_index_page,
    window_index_projection_with,
};
use oneiron::sync::residence_operation_budgets::ResidenceOperationBudgets;
use oneiron::sync::schema::read_window_list;
use oneiron::sync::{SyncSelector, WindowKey, decode_sync_selector};
use oneiron::world_keys::SealedContentId;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{AppError, CoreAuth, CoreScope, RpcRequest};
use crate::wire_telemetry::LimitRow;

/// A result and the rows it carries (DEC-0005).
type Answer = (Value, Option<Vec<EntityId>>);
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
    /// The machine the projection was selected for: a proof that stops
    /// standing, or a new one, never reuses it.
    destination: Destination,
    selection_revision: ([u8; 32], u64, u64),
    items: Vec<WindowIndexEntry>,
    pages: usize,
    budgets: ResidenceOperationBudgets,
    /// The projection's charge on the server's retained-memory line.
    _held: crate::byte_line::HeldBytes,
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

/// One window's version vector, asked before an opened machine demotes it
/// (OF-534).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowVvRequest {
    window: String,
    selector: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRequest {
    query: String,
    limit: usize,
    selector: String,
}

/// A sealed packet of one private-world window, for the home to keep
/// (OF-534 G7).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedPutRequest {
    window: String,
    packet: String,
    #[serde(default)]
    retire_through: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedListRequest {
    #[serde(default)]
    after: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedGetRequest {
    id: String,
}

/// The authority entries a machine holds, as concatenated 32-byte hashes in
/// base64, and how many missing entries it takes in one page (OF-469).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityTailRequest {
    held: String,
    limit: usize,
}

pub(super) fn run(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    request: RpcRequest,
    index_cache: &mut Option<ResidenceIndexCache>,
) -> Result<super::RpcReply, crate::protocol::ProtocolError> {
    let call = super::RpcCall::of(&request);
    let result = (|| {
        auth.require(CoreScope::Read)?;
        if !auth.credential_is_live(server.vault.as_ref()) {
            return Err(AppError::unauthorized());
        }
        let budgets = operation_budgets(server)?;
        match request.method.as_str() {
            "residence.index" => index(server, auth, peer, request.params, index_cache, budgets),
            "residence.touch" => touch(server, auth, peer, request.params),
            "residence.promote" => promote(server, auth, peer, request.params),
            "residence.window.vv" => window_vv(server, auth, peer, request.params),
            "residence.search" => search(server, auth, peer, request.params, budgets),
            "residence.sealed.put" => sealed_put(server, auth, peer, request.params),
            "residence.sealed.list" => sealed_list(server, peer, request.params),
            "residence.sealed.get" => sealed_get(server, peer, request.params),
            "residence.authority.tail" => authority_tail(server, peer, request.params),
            _ => Err(AppError::bad_request(
                "unknown residence RPC",
                Some("method"),
            )),
        }
    })();
    super::RpcReply::answer(server, auth, call, request.request_id, result)
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

/// One request's residence admission for the machine this socket proved
/// (OF-534 G6). A refused credential, grant or member looks missing.
fn admitted<'v>(
    server: &'v SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    selector: &SyncSelector,
) -> Result<ResidenceAdmission<'v>, AppError> {
    let proof = auth.verified_slip().ok_or_else(AppError::unauthorized)?;
    ResidenceAdmission::load(
        &server.vault,
        proof,
        peer,
        crate::handler::selector_grant_scope(),
        selector,
    )
    .map_err(|_| AppError::not_found("item", None))
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
    peer: PeerMachine,
    params: Value,
    cache: &mut Option<ResidenceIndexCache>,
    budgets: ResidenceOperationBudgets,
) -> Result<Answer, AppError> {
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
    let admission = admitted(server, auth, peer, &selector)?;
    let destination = admission.destination();
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
        let entries = window_index_projection_with(
            &server.vault,
            &doc,
            &window,
            crate::handler::selector_grant_scope(),
            &selector,
            admission.withhold(),
            budgets.title_max_chars,
            |id| admission.allows_item(id),
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
        // Rule 5: the projection is charged to the retained-memory line,
        // never refused for its size; past its row it asks. Only a full
        // line, the memory floor, refuses it.
        let questions = server.wire_telemetry.limit_questions();
        if bytes > budgets.index_cache_bytes {
            questions.ask(
                LimitRow::ResidenceIndexBytes,
                budgets.index_cache_bytes as u64,
                bytes as u64,
            );
        }
        // Retaken below: the projection this one replaces gives its bytes back.
        *cache = None;
        let held = server
            .retained
            .try_reserve_alone(bytes, questions)
            .ok_or_else(AppError::memory_floor)?;
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
            destination,
            selection_revision,
            items: entries,
            pages: 0,
            budgets,
            _held: held,
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
        || retained.destination != destination
        || retained.selection_revision != selection_revision
        || retained.budgets != budgets
    {
        *cache = None;
        return Err(index_changed());
    }
    retained.pages = retained.pages.saturating_add(1);
    if retained.pages == budgets.max_index_pages.saturating_add(1) {
        // Rule 5: a read past its page row asks once and goes on.
        server.wire_telemetry.limit_questions().ask(
            LimitRow::ResidenceIndexPages,
            budgets.max_index_pages as u64,
            retained.pages as u64,
        );
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
            if admission
                .allows_item(id)
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
    let rows = items
        .iter()
        .map(|item| EntityId::from_hex(&item.entity_id).ok())
        .collect();
    Ok((
        json!({
            "window": window.as_str(), "items": items, "nextCursor": next,
            "revision": retained.revision.as_str(),
        }),
        rows,
    ))
}

fn index_changed() -> AppError {
    AppError::new(
        "INDEX_REVISION_CHANGED",
        "window index changed during paging",
        ["Restart the window index from the first page."],
    )
}

fn touch(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: TouchRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let id = EntityId::from_hex(&input.entity_id).map_err(|_| AppError::invalid_params())?;
    let (window, selector, doc) = selected_window(server, auth, &input.window, &input.selector)?;
    // A stored grant constrains the selector; the actor's live scoped-read
    // floor and the destination machine's world read settings must ALSO
    // admit the exact target. Either denial looks missing.
    let admission = admitted(server, auth, peer, &selector)?;
    if !admission
        .allows_item(id)
        .map_err(|_| AppError::internal_server_error("item admission unavailable"))?
    {
        return Err(AppError::not_found("item", None));
    }
    let blob = selected_item_blob_with(
        &server.vault,
        &doc,
        &window,
        crate::handler::selector_grant_scope(),
        &selector,
        admission.withhold(),
        id,
    )
    .map_err(|_| AppError::internal_server_error("item unavailable"))?
    .ok_or_else(|| AppError::not_found("item", None))?;
    // The export opens the document: past the live-document row it waits its
    // turn off the runtime worker (rule 5).
    let document = crate::server::blocking(|| {
        server.reassert_manager.export_document_in_window_with(
            id,
            &window,
            crate::handler::selector_grant_scope(),
            &selector,
            admission.withhold(),
            &loro::VersionVector::new().encode(),
        )
    })
    .map_err(|error| {
        if error.kind() == oneiron::ErrorKind::LiveDocumentWaitedOut {
            AppError::waited_out()
        } else {
            AppError::internal_server_error("item document unavailable")
        }
    })?;
    Ok((
        json!({
            "window": window.as_str(),
            "entityId": id.to_hex(),
            "blob": base64::engine::general_purpose::STANDARD.encode(blob),
            "document": base64::engine::general_purpose::STANDARD.encode(document),
        }),
        Some(vec![id]),
    ))
}

fn promote(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: PromotionRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let id = EntityId::from_hex(&input.entity_id).map_err(|_| AppError::invalid_params())?;
    let (window, selector, doc) = selected_window(server, auth, &input.window, &input.selector)?;
    let admission = admitted(server, auth, peer, &selector)?;
    if !admission
        .allows_item(id)
        .map_err(|_| AppError::internal_server_error("promotion admission unavailable"))?
        || selected_item_blob_with(
            &server.vault,
            &doc,
            &window,
            crate::handler::selector_grant_scope(),
            &selector,
            admission.withhold(),
            id,
        )
        .map_err(|_| AppError::not_found("item", None))?
        .is_none()
    {
        return Err(AppError::not_found("item", None));
    }
    // Every row of the window a walk admitted this reader: the snapshot
    // carries no other.
    let mut rows = vec![id];
    let snapshot = promotion_snapshot_with(
        &server.vault,
        &doc,
        &window,
        crate::handler::selector_grant_scope(),
        &selector,
        admission.withhold(),
        |item| {
            rows.push(item);
            admission.allows_item(item)
        },
    )
    .map_err(|_| AppError::internal_server_error("window promotion unavailable"))?
    .ok_or_else(|| AppError::not_found("window promotion", None))?;
    Ok((
        json!({
            "window": window.as_str(),
            "snapshot": base64::engine::general_purpose::STANDARD.encode(snapshot),
        }),
        Some(rows),
    ))
}

/// The home's version vector for a window, on the residence index's gate: a
/// bound selector and a machine the grant admits. An opened machine demotes
/// its promoted copy only once this covers every op it holds (OF-534).
fn window_vv(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: WindowVvRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let (window, selector, doc) = selected_window(server, auth, &input.window, &input.selector)?;
    let _admitted = admitted(server, auth, peer, &selector)?;
    Ok((
        json!({
            "window": window.as_str(),
            "vv": base64::engine::general_purpose::STANDARD.encode(doc.oplog_vv().encode()),
        }),
        None,
    ))
}

fn search(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
    budgets: ResidenceOperationBudgets,
) -> Result<Answer, AppError> {
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
    let admission = admitted(server, auth, peer, &selector)?;
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
    let mut rows = Vec::with_capacity(input.limit);
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
            let selected = oneiron::sync::filtered_window_doc_for(
                &server.vault,
                &doc.doc,
                &window,
                crate::handler::selector_grant_scope(),
                &selector,
                admission.withhold(),
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
        ) && admission
            .allows_item(id)
            .map_err(|_| AppError::internal_server_error("search admission unavailable"))?
        {
            hits.push(json!({"entityId": id.to_hex(), "score": score, "window": window.as_str()}));
            rows.push(id);
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
    Ok((
        json!({"hits": hits, "source": "home", "complete": true}),
        Some(rows),
    ))
}

/// Keeps a sealed packet of a private world's window that the sending
/// machine reads (OF-534 G7). The home opens nothing; a refused sender,
/// world or packet looks missing.
fn sealed_put(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    auth.require(CoreScope::Write)?;
    let input: SealedPutRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let window = WindowKey::try_new(input.window).ok_or_else(AppError::invalid_params)?;
    let packet = base64::engine::general_purpose::STANDARD
        .decode(input.packet)
        .map_err(|_| AppError::invalid_params())?;
    let (id, seq) =
        shelve_sealed_window(&server.vault, peer, &window, &packet, input.retire_through)
            .map_err(|_| AppError::not_found("sealed window", None))?;
    Ok((json!({"id": id.to_hex(), "seq": seq}), Some(Vec::new())))
}

/// The live sealed packets after one arrival, of the worlds the proved
/// machine reads.
fn sealed_list(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: SealedListRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let entries = sealed_shelf_after(&server.vault, peer, input.after)
        .map_err(|_| AppError::not_found("sealed shelf", None))?;
    let entries: Vec<Value> = entries
        .into_iter()
        .map(|entry| {
            json!({"id": entry.id.to_hex(), "window": entry.window.as_str(), "seq": entry.seq})
        })
        .collect();
    Ok((json!({"entries": entries}), Some(Vec::new())))
}

/// One live or retired sealed packet, for a proved machine that reads its
/// world.
fn sealed_get(server: &SyncServer, peer: PeerMachine, params: Value) -> Result<Answer, AppError> {
    let input: SealedGetRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let id = SealedContentId::from_hex(&input.id).map_err(|_| AppError::invalid_params())?;
    let (window, packet) = sealed_shelf_packet(&server.vault, peer, &id)
        .map_err(|_| AppError::not_found("sealed packet", None))?
        .ok_or_else(|| AppError::not_found("sealed packet", None))?;
    Ok((
        json!({
            "id": id.to_hex(),
            "window": window.as_str(),
            "packet": base64::engine::general_purpose::STANDARD.encode(packet),
        }),
        Some(Vec::new()),
    ))
}

/// The signed authority entries the proved machine lacks, parents first
/// (OF-469). Only a machine of the owner's is served; any other looks missing.
fn authority_tail(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: AuthorityTailRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(input.held)
        .map_err(|_| AppError::invalid_params())?;
    if raw.len() % 32 != 0 {
        return Err(AppError::invalid_params());
    }
    let held: std::collections::BTreeSet<oneiron::authority::AuthorityEntryHash> = raw
        .chunks_exact(32)
        .map(|hash| <[u8; 32]>::try_from(hash).map_err(|_| AppError::invalid_params()))
        .collect::<Result<_, _>>()?;
    let entries = authority_tail_for(&server.vault, peer, &held, input.limit)
        .map_err(|_| AppError::not_found("authority history", None))?;
    let entries: Vec<String> = entries
        .iter()
        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
        .collect();
    Ok((json!({"entries": entries}), Some(Vec::new())))
}
