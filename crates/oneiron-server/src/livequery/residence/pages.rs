//! A residence search served in pages (FIX 8865): a search for more hits
//! than one page carries is never refused for its count. The home ranks the
//! caller's whole request, as deep as it must to hold that many grant-selected
//! hits or every match, at the second the first page named, and answers one
//! page of that list with the list's revision. Each later page ranks again: a
//! list that changed since names another revision, and the device starts
//! over, so no answer mixes two lists. The grant and a forwarded caller are
//! checked again after every page, as for a search of one call.

use std::collections::{HashMap, HashSet};

use base64::Engine;
use oneiron::EntityId;
use oneiron::authority::PeerMachine;
use oneiron::sync::residence::{
    RESIDENCE_PAGE_REPLY_BYTES, ResidenceAdmission, ResidenceSearchCursor,
    home_search_page_candidates, residence_search_revision,
};
use oneiron::sync::residence_operation_budgets::ResidenceOperationBudgets;
use oneiron::sync::schema::read_window_list;
use oneiron::sync::{SyncSelector, WindowKey};
use serde_json::json;

use super::{
    Answer, AppError, CoreAuth, ForwardedAttribution, SearchRequest, SyncServer, admitted,
    bound_selector, device_search_read_key,
};

/// A later page whose list changed since the first: the device starts over.
fn search_changed() -> AppError {
    AppError::new(
        "SEARCH_REVISION_CHANGED",
        "the search's ranked list changed during paging",
        ["Restart the search from its first page."],
    )
}

/// One page of a search served in pages, with the cursor of the next. A
/// forwarded search's verified caller is written to `attribution`, as for
/// a search of one call (FIX 3550).
pub(super) fn search_pages(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    input: SearchRequest,
    budgets: ResidenceOperationBudgets,
    attribution: &mut Option<ForwardedAttribution>,
) -> Result<Answer, AppError> {
    let selector_wire = base64::engine::general_purpose::STANDARD
        .decode(&input.selector)
        .map_err(|_| AppError::invalid_params())?;
    let selector = bound_selector(server, auth, &input.selector)?;
    // A forwarded caller reads under its own credential, at the locality its
    // device signed, and the device's selector stays the second ceiling
    // every hit passes.
    let forwarded = input.forwarded_caller(server, peer, &selector)?;
    *attribution = forwarded
        .as_ref()
        .map(|forwarded| ForwardedAttribution::of(&forwarded.caller));
    let admission = match &forwarded {
        Some(caller) => caller.admission(server, peer, &selector)?,
        None => admitted(server, auth, peer, &selector)?,
    };
    let grant_before = server
        .vault
        .get_raw(&selector.grant_id)
        .map_err(|_| AppError::internal_server_error("grant unavailable"))?
        .ok_or_else(|| AppError::not_found("grant", None))?;
    let actor = match &forwarded {
        Some(caller) => caller.read_key(),
        None => device_search_read_key(server, auth)?,
    };
    let as_of = match &input.page {
        Some(page) => page.as_of,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs()),
    };
    let current_windows: HashSet<_> = read_window_list(&server.root_doc).into_iter().collect();
    let mut selected_by_window = HashMap::new();
    // The ranking starts as deep as a search of one call reads and doubles
    // until it holds the request or every match.
    let mut window = input.limit.max(oneiron::memory::caps::MAX_SEARCH_LIMIT);
    let hits = loop {
        let (candidates, ranked) = home_search_page_candidates(
            &server.vault,
            actor.clone(),
            &input.query,
            window,
            input.scope.as_ref(),
            as_of,
        )
        .map_err(|_| AppError::internal_server_error("scoped search unavailable"))?;
        let mut hits = Vec::new();
        for (id, score, key) in candidates {
            if !current_windows.contains(&key) {
                continue;
            }
            if selects(
                server,
                &selector,
                &admission,
                &mut selected_by_window,
                id,
                &key,
            )? {
                hits.push((id, score, key));
                if hits.len() == input.limit {
                    break;
                }
            }
        }
        if hits.len() == input.limit || ranked < window {
            break hits;
        }
        window = window.saturating_mul(2);
    };
    let listed: Vec<(EntityId, WindowKey)> =
        hits.iter().map(|(id, _, key)| (*id, key.clone())).collect();
    let revision = residence_search_revision(
        &input.query,
        input.limit,
        &selector_wire,
        input.scope.as_ref(),
        as_of,
        &listed,
    );
    let offset = match &input.page {
        Some(page) if page.revision != revision => return Err(search_changed()),
        Some(page) => usize::try_from(page.offset)
            .ok()
            .filter(|offset| *offset <= hits.len())
            .ok_or_else(AppError::invalid_params)?,
        None => 0,
    };
    // One page slice, cut short only to fit one reply.
    let mut page = Vec::new();
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    // FIX 7608 slice 4: a marked repo item is shown by its copy id.
    let aliases = oneiron::sync::selector::RepoCopyAliases::read(&server.vault)
        .map_err(|_| AppError::internal_server_error("search aliases unavailable"))?;
    for (id, score, key) in hits.iter().skip(offset).take(budgets.search_limit) {
        let shown = aliases.shown(id).to_hex();
        let hit = json!({"entityId": shown, "score": score, "window": key.as_str()});
        let size = hit.to_string().len();
        if !page.is_empty() && bytes.saturating_add(size) > RESIDENCE_PAGE_REPLY_BYTES {
            break;
        }
        bytes = bytes.saturating_add(size);
        page.push(hit);
        rows.push(*id);
    }
    let end = offset.saturating_add(page.len());
    let next = (end < hits.len()).then(|| ResidenceSearchCursor {
        offset: end as u64,
        revision: revision.clone(),
        as_of,
    });
    // The app credential, grant and selector are rechecked after the page,
    // and a forwarded caller too.
    let selector = bound_selector(server, auth, &input.selector)?;
    if forwarded.is_some() {
        input
            .forwarded_caller(server, peer, &selector)
            .inspect_err(|_| *attribution = None)?;
    }
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
        json!({
            "hits": page, "source": "home", "complete": next.is_none(),
            "revision": revision, "nextCursor": next,
        }),
        Some(rows),
    ))
}

/// Whether `id` in `window` passes the device's grant selector and this
/// request's admission, as a search of one call judges each hit.
fn selects(
    server: &SyncServer,
    selector: &SyncSelector,
    admission: &ResidenceAdmission<'_>,
    selected_by_window: &mut HashMap<WindowKey, loro::LoroDoc>,
    id: EntityId,
    window: &WindowKey,
) -> Result<bool, AppError> {
    if !selected_by_window.contains_key(window) {
        let doc = server
            .reassert_manager
            .open_window(window)
            .map_err(|_| AppError::internal_server_error("search window unavailable"))?;
        // Home search reads LMDB, whose latest local writes can be ahead of
        // an already-open Loro window.
        oneiron::sync::window::reverse_rematerialize(&server.vault, &doc.doc, window)
            .map_err(|_| AppError::internal_server_error("search window unavailable"))?;
        let selected = oneiron::sync::filtered_window_doc_for(
            &server.vault,
            &doc.doc,
            window,
            crate::handler::selector_grant_scope(),
            selector,
            admission.withhold(),
        )
        .map_err(|_| AppError::not_found("grant", None))?;
        selected_by_window.insert(window.clone(), selected);
    }
    let selected = selected_by_window
        .get(window)
        .ok_or_else(|| AppError::internal_server_error("search window unavailable"))?;
    Ok(matches!(
        selected.get_map("entities").get(&id.to_hex()),
        Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(_)))
    ) && admission
        .allows_item(id)
        .map_err(|_| AppError::internal_server_error("search admission unavailable"))?)
}
