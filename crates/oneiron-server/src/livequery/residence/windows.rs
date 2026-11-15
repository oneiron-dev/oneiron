//! `residence.windows`: the rootless window catalogue a member lane boots from
//! (MEMBER-SYNC D6). A member holds no root document, so it cannot read the
//! window list there; it asks this instead, then `residence.index` per window.
//!
//! RULING MEMBER-SYNC-CATALOGUE = A (Engine 15 Nov 06:0x): it lists only the
//! windows that hold at least one row the caller's own `residence.index`
//! would serve, for the months it asks, a page at a time. Canon DEC-0005:335:
//! "An empty ceiling grants nothing"; a member learns nothing beyond the rows
//! it reads. Each window is judged by the same projection `residence.index`
//! serves from, under the same pinned selector and admission.
//!
//! The listing is live, not a snapshot: pages run in key order past `after`,
//! and a window that becomes readable behind a page already read is found on
//! the lane's next catalogue pass (each reconnect and refresh asks again).
//! `residence.index` carries the revision a reader holds a window at.
//!
//! A page's continuation names only a window the page listed: a window the
//! caller cannot read never ends a page, so its key (a world key names its
//! world) never reaches the caller (MEMBER-SYNC review F1). A page judges
//! windows until it has listed `limit` and found one more readable, or the
//! months asked run out, as `residence.index` reads past withheld rows to
//! fill a page; its work is bounded by the home's windows in the months
//! asked (at most 36 months).

use super::*;

/// The most months one catalogue call names.
const MAX_CATALOGUE_MONTHS: usize = 36;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsRequest {
    selector: String,
    /// The months asked for, each `YYYY-MM`.
    months: Vec<String>,
    /// The `next` of the page before: the last window it listed. The next
    /// page starts past it.
    #[serde(default)]
    after: Option<String>,
    limit: usize,
}

/// One page of the windows `params.selector` reads a row of, among the
/// home's windows of `params.months` past `params.after`, in key order. A
/// page names at most `limit` (and at most the index page limit); `next` is
/// its last listed window while another readable one follows, else null. A
/// refused credential, grant or selector looks missing, as `residence.index`
/// does.
pub(super) fn windows(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    lane: &crate::handler::selector_scope::SelectorLane,
    params: Value,
    budgets: ResidenceOperationBudgets,
) -> Result<Answer, AppError> {
    let input: WindowsRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    if input.limit == 0
        || input.months.is_empty()
        || input.months.len() > MAX_CATALOGUE_MONTHS
        || input
            .months
            .iter()
            .any(|month| month.len() != 7 || WindowKey::try_new(month.as_str()).is_none())
    {
        return Err(AppError::invalid_params());
    }
    let selector = bound_selector(server, auth, lane, &input.selector)?;
    let admission = admitted(server, auth, peer, lane, &selector)?;
    let months: std::collections::BTreeSet<&str> =
        input.months.iter().map(String::as_str).collect();
    let mut candidates: Vec<WindowKey> = read_window_list(&server.root_doc)
        .into_iter()
        .filter(|key| {
            key.as_str()
                .get(..7)
                .is_some_and(|month| months.contains(month))
                && input
                    .after
                    .as_deref()
                    .is_none_or(|after| key.as_str() > after)
        })
        .collect();
    candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    candidates.dedup();
    let limit = input.limit.min(budgets.index_page_limit.max(1));
    // FIX 7608 slice 4: rows stay source-bound, as `residence.index` names them.
    let aliases = oneiron::sync::selector::RepoCopyAliases::read(&server.vault)
        .map_err(|_| AppError::internal_server_error("catalogue aliases unavailable"))?;
    let mut listed = Vec::new();
    // The rows the page was derived from: every row of each readable window it
    // judged, the one past a full page included. The send judges them again for
    // the destination (DEC-0005), as it does `residence.index`'s rows; a reply
    // that names none is withheld from every destination off this device.
    let mut derived = Vec::new();
    let mut more = false;
    for key in &candidates {
        let window = server
            .reassert_manager
            .open_window(key)
            .map_err(|_| AppError::internal_server_error("catalogue window unavailable"))?;
        let rows = window_index_projection_with(
            &server.vault,
            &window.doc,
            key,
            lane.grant_scope(),
            &selector,
            admission.withhold(),
            budgets.title_max_chars,
            |id| admission.allows_item(id),
        )
        .map_err(|_| AppError::internal_server_error("catalogue unavailable"))?;
        if rows.is_empty() {
            continue;
        }
        for row in &rows {
            let id = EntityId::from_hex(&row.entity_id)
                .map_err(|_| AppError::internal_server_error("catalogue entry malformed"))?;
            derived.push(aliases.stored(&id));
        }
        // One readable window past a full page: the caller has more to read.
        if listed.len() == limit {
            more = true;
            break;
        }
        listed.push(key.as_str().to_owned());
    }
    // The grant, credential and selector are judged again after the page.
    bound_selector(server, auth, lane, &input.selector)?;
    let next = if more { listed.last().cloned() } else { None };
    Ok((json!({ "windows": listed, "next": next }), Some(derived)))
}
