//! Query, hydrate, timeline and runtime-deferred request/response shapes.

#[cfg(test)]
pub(super) use oneiron_contracts::code_run::vault_read::default_limit;
pub use oneiron_contracts::code_run::vault_read::{
    AskRequest, CodeExecuteRequest, CodeSearchRequest, CoreBatchShortIdHydrateRequest,
    CoreHydrateRequest, CoreMemoryTimelineRequest, CoreQueryAffect, CoreQueryRequest, CountMode,
    View,
};

/// Maximum refs read in one internal named-read frame of a batch short-id
/// hydrate call (FIX 11697): a batch past it is read frame by frame, every
/// ref served, none refused for its count.
pub const VAULT_READ_MAX_BATCH_REFS: usize = 256;

/// Accepted over-fetch recipe. `Exact` is collapsed before this call.
pub(super) const fn search_fetch_limit(count_mode: CountMode, page_limit: usize) -> usize {
    match count_mode {
        CountMode::None => page_limit,
        CountMode::Estimate => page_limit.saturating_add(1),
        CountMode::Exact => {
            panic!("count mode collapses to none/estimate before fetch-limit resolution")
        }
    }
}

/// Accepted `search_meta` total: `None` reports zero, `Estimate` reports the
/// admitted over-fetch count.
pub(super) const fn search_total(count_mode: CountMode, admitted: usize) -> u64 {
    match count_mode {
        CountMode::None => 0,
        CountMode::Estimate => admitted as u64,
        CountMode::Exact => panic!("count mode collapses to none/estimate before meta resolution"),
    }
}

#[doc(hidden)]
pub use oneiron_records::code_run::vault_read::types::{
    AskResponse, CodeExecuteResponse, CodeSearchResponse, CoreBatchShortIdHydrateItem,
    CoreBatchShortIdHydrateResponse, CoreEntityRecord, CoreHydrateResponse, CoreHydrateStatus,
    CoreMemoryTimelineRecord, CoreMemoryTimelineResponse, CoreQueryMeta, CoreQueryResponse,
    CoreShortIdHydrateOutcome,
};
