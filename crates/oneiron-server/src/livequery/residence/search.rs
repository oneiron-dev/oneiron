//! A window's home search: the candidates a residence search returns for one query.
//! `search` is its call surface, dispatched by `run`.
//! The residence root defines `SearchRequest`; `oneiron::sync::residence` owns the candidates.

use super::*;

/// A forwarded search's verified caller is written to `attribution`, for its
/// receipt to name (FIX 3550), and taken back if the caller stops verifying;
/// `off_carrier` is set when that caller sits off the carrying device, so
/// the reply's send judges its rows for an unknown destination (FIX 11991).
pub(super) fn search(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
    budgets: ResidenceOperationBudgets,
    attribution: &mut Option<ForwardedAttribution>,
    off_carrier: &mut bool,
) -> Result<Answer, AppError> {
    let input: SearchRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    oneiron::memory::caps::check_as_of(input.as_of)?;
    if input.query.trim().is_empty()
        || input.query.len() > budgets.search_query_max_bytes
        || input.limit == 0
    {
        return Err(AppError::invalid_params());
    }
    pages::search_pages(server, auth, peer, input, budgets, attribution, off_carrier)
}
