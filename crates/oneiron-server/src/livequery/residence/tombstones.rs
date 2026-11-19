//! A followed window's tombstone id set, `residence.tombstones`
//! (FOLLOWED-WORLD-TIER1-TOMBSTONE-IDS; canon ARCH-0023b :500): a device that
//! follows the window's world learns each delete it may read, even of a
//! window the home refuses to it, and writes the delete marker. The ids are
//! the selector export's own (`window_tombstone_projection_with`), held to
//! the credential's records and channel caveats, so none names a row the
//! device could not read, and a world kept off its machine gives none.
//!
//! Paged by an id cursor over a fresh projection, with no retained cache:
//! tombstones only grow, so a page drops none, and a delete that lands behind
//! the cursor comes on the device's next pass.

use super::*;
use oneiron::sync::residence::window_tombstone_projection_with;

/// One page of a window's tombstone id set: the rows after `after`, at most
/// `limit` of them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TombstonesRequest {
    window: String,
    selector: String,
    #[serde(default)]
    after: Option<String>,
    limit: usize,
}

pub(super) fn tombstones(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
    budgets: ResidenceOperationBudgets,
) -> Result<Answer, AppError> {
    let input: TombstonesRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let after = input
        .after
        .as_deref()
        .map(|raw| {
            EntityId::from_hex(raw)
                .ok()
                .filter(|id| id.to_hex() == raw)
                .ok_or_else(AppError::invalid_params)
        })
        .transpose()?;
    if input.limit == 0 {
        return Err(AppError::invalid_params());
    }
    // A positive limit past the page slice is served one slice and a cursor,
    // never refused for its count (FIX 8881).
    let page_limit = input.limit.min(budgets.index_page_limit);
    let (window, selector, doc) = selected_window(server, auth, &input.window, &input.selector)?;
    let admission = admitted(server, auth, peer, &selector)?;
    let mut entries = window_tombstone_projection_with(
        &server.vault,
        &doc,
        &window,
        crate::handler::selector_scope::selector_grant_scope(),
        &selector,
        admission.withhold(),
    )
    .map_err(|_| AppError::internal_server_error("tombstones unavailable"))?;
    // The credential's own records and channel caveats, the bounds an id
    // judges with no row left to read: a slip that names its records names
    // every id it learns of (blind review 1 of #9592).
    entries.retain(|entry| admission.credential_allows_id(entry.entity_id));
    let start = after.map_or(0, |cursor| {
        let after = cursor.to_hex();
        entries.partition_point(|entry| entry.entity_id.to_hex() <= after)
    });
    let mut items = Vec::new();
    // The ids the page names: the send door judges them as it judges a
    // window vector's rows (FIX 9494).
    let mut rows = Vec::new();
    // The page is cut short only to fit one reply.
    let mut reply_bytes = 0usize;
    for entry in entries.iter().skip(start).take(page_limit) {
        let id = entry.entity_id.to_hex();
        let value = base64::engine::general_purpose::STANDARD.encode(&entry.value);
        let bytes = id.len() + value.len() + 32;
        if !items.is_empty() && reply_bytes.saturating_add(bytes) > RESIDENCE_PAGE_REPLY_BYTES {
            break;
        }
        reply_bytes = reply_bytes.saturating_add(bytes);
        items.push(json!({ "entityId": id, "value": value }));
        rows.push(entry.entity_id);
    }
    let next = rows
        .last()
        .filter(|_| start + rows.len() < entries.len())
        .map(EntityId::to_hex);
    Ok((
        json!({
            "window": window.as_str(),
            "items": items,
            "nextCursor": next,
        }),
        Some(rows),
    ))
}
