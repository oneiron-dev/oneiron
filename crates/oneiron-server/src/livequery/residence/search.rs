//! A window's home search: the candidates a residence search returns for one query.
//! `search` is its call surface, dispatched by `run`.
//! The residence root defines `SearchRequest`; `oneiron::sync::residence` owns the candidates.

use super::*;

pub(super) fn search(
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
    {
        return Err(AppError::invalid_params());
    }
    // More hits than one page carries are served in pages (FIX 8865).
    if input.limit > budgets.search_limit || input.page.is_some() {
        return pages::search_pages(server, auth, peer, input, budgets);
    }
    let selector = bound_selector(server, auth, &input.selector)?;
    // A forwarded caller reads under its own credential, and the device's
    // selector stays the second ceiling every hit passes.
    let forwarded = input.forwarded_caller(server, peer, &selector)?;
    let admission = match &forwarded {
        Some(caller) => ResidenceAdmission::load(
            &server.vault,
            caller.caller(),
            peer,
            crate::handler::selector_grant_scope(),
            &selector,
        )
        .map_err(|_| AppError::not_found("item", None))?,
        None => admitted(server, auth, peer, &selector)?,
    };
    let grant_before = server
        .vault
        .get_raw(&selector.grant_id)
        .map_err(|_| AppError::internal_server_error("grant unavailable"))?
        .ok_or_else(|| AppError::not_found("grant", None))?;
    let proof = match &forwarded {
        Some(caller) => caller.caller(),
        None => auth.verified_slip().ok_or_else(AppError::unauthorized)?,
    };
    let candidates = home_search_candidates(
        &server.vault,
        proof,
        &input.query,
        input.limit,
        input.scope.as_ref(),
    )
    .map_err(|_| AppError::internal_server_error("scoped search unavailable"))?;
    let current_windows: std::collections::HashSet<_> =
        read_window_list(&server.root_doc).into_iter().collect();
    let mut selected_by_window = std::collections::HashMap::new();
    let mut hits = Vec::new();
    let mut rows = Vec::new();
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
    // The app credential, grant and selector are rechecked after the search,
    // and a forwarded caller too: a revoked or replaced grant never returns a
    // cached answer.
    let selector = bound_selector(server, auth, &input.selector)?;
    if forwarded.is_some() {
        input.forwarded_caller(server, peer, &selector)?;
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
        json!({"hits": hits, "source": "home", "complete": true}),
        Some(rows),
    ))
}
