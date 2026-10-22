//! A window's residence index: its paged projection, touches, promotions and version vector.
//! `index`, `touch`, `promote` and `window_vv` are its call surface, dispatched by `run`.
//! The residence root defines the request DTOs and `ResidenceIndexCache`.

use super::*;

pub(super) fn index(
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
    // A positive limit past the page slice is served one slice and a cursor,
    // never refused for its count (FIX 8881).
    if input.limit == 0 || input.after.is_some() != input.revision.is_some() {
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
    let mut items = Vec::with_capacity(page_limit.min(retained.items.len()));
    // The page is cut short only to fit one reply.
    let mut reply_bytes = 0usize;
    let mut cursor = after;
    'pages: loop {
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
            if admission
                .allows_item(id)
                .map_err(|_| AppError::internal_server_error("index admission unavailable"))?
            {
                let bytes = serde_json::to_vec(&entry)
                    .map_err(|_| AppError::internal_server_error("index entry malformed"))?
                    .len();
                if !items.is_empty()
                    && reply_bytes.saturating_add(bytes) > RESIDENCE_PAGE_REPLY_BYTES
                {
                    break 'pages;
                }
                reply_bytes = reply_bytes.saturating_add(bytes);
                items.push(entry);
            }
            cursor = Some(id);
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

pub(super) fn index_changed() -> AppError {
    AppError::new(
        "INDEX_REVISION_CHANGED",
        "window index changed during paging",
        ["Restart the window index from the first page."],
    )
}

pub(super) fn touch(
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

pub(super) fn promote(
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
    // Every pad of the window's world rides with it (FIX 3789).
    let pads = admission
        .promoted_pads(&window)
        .map_err(|_| AppError::internal_server_error("window promotion unavailable"))?;
    rows.extend(pads.iter().map(|pad| pad.id));
    Ok((
        json!({
            "window": window.as_str(),
            "snapshot": base64::engine::general_purpose::STANDARD.encode(snapshot),
            "pads": pads.iter().map(|pad| json!({
                "id": pad.id.to_hex(),
                "window": pad.window,
                "raw": base64::engine::general_purpose::STANDARD.encode(&pad.row[..]),
            })).collect::<Vec<_>>(),
        }),
        Some(rows),
    ))
}

/// The home's version vector for a window, on the residence index's gate: a
/// bound selector and a machine the grant admits. An opened machine demotes
/// its promoted copy only once this covers every op it holds (OF-534). It
/// lists the rows the vector counts ops of ([`window_vv_rows`], FIX 9494),
/// so the send door judges it as it judges every answer, and a vector whose
/// rows may all leave reaches an off-device machine.
pub(super) fn window_vv(
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
        Some(window_vv_rows(&doc)),
    ))
}

/// Every row a window document's version vector counts ops of (FIX 9494):
/// each entity it holds, each row an edge in it joins, and each row it keeps
/// a tombstone for. The vector is metadata over exactly these.
fn window_vv_rows(doc: &loro::LoroDoc) -> Vec<EntityId> {
    let mut rows = Vec::new();
    let whole = |hex: &str| EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex);
    for map in ["entities", "tombstones"] {
        doc.get_map(map).for_each(|key, _| rows.extend(whole(key)));
    }
    doc.get_map("edges").for_each(|key, _| {
        let mut parts = key.splitn(3, ':');
        let source = parts.next().and_then(whole);
        let target = parts.nth(1).and_then(whole);
        rows.extend(source.into_iter().chain(target));
    });
    rows.sort_unstable();
    rows.dedup();
    rows
}
