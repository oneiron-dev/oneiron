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

use super::*;

/// The most months one catalogue call names.
const MAX_CATALOGUE_MONTHS: usize = 36;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsRequest {
    selector: String,
    /// The months asked for, each `YYYY-MM`.
    months: Vec<String>,
    /// The last window key a page before judged; the next page starts past it.
    #[serde(default)]
    after: Option<String>,
    limit: usize,
}

/// One page of the windows `params.selector` reads a row of, among the
/// home's windows of `params.months` past `params.after`, in key order. A
/// page judges at most the index page limit of windows and names at most
/// `limit`; `next` is the last key it judged while more remain. A refused
/// credential, grant or selector looks missing, as `residence.index` does.
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
        || input.months.iter().any(|month| {
            month.len() != 7 || WindowKey::try_new(month.as_str()).is_none()
        })
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
            key.as_str().get(..7).is_some_and(|month| months.contains(month))
                && input
                    .after
                    .as_deref()
                    .is_none_or(|after| key.as_str() > after)
        })
        .collect();
    candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    candidates.dedup();
    let judged = budgets.index_page_limit.max(1);
    let limit = input.limit.min(judged);
    let mut listed = Vec::new();
    let mut last = None;
    for key in candidates.iter().take(judged) {
        if listed.len() == limit {
            break;
        }
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
        if !rows.is_empty() {
            listed.push(key.as_str().to_owned());
        }
        last = Some(key.as_str().to_owned());
    }
    // The grant, credential and selector are judged again after the page.
    bound_selector(server, auth, lane, &input.selector)?;
    let more = last
        .as_deref()
        .is_some_and(|last| candidates.iter().any(|key| key.as_str() > last));
    Ok((
        json!({ "windows": listed, "next": if more { last } else { None } }),
        None,
    ))
}
