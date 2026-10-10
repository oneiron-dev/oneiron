//! Raw search under a request's hard deadline (`deadlineMs`): the page reads
//! on the blocking pool, and the door answers when the deadline comes due.

use super::*;
use std::time::Duration;

/// The request's hard deadline, refused out of range with the field named.
pub(super) fn search_deadline(deadline_ms: Option<u64>) -> Result<Option<Duration>, ApiError> {
    oneiron::memory::caps::check_deadline_ms(deadline_ms)
        .map_err(|refusal| ApiError::bad_request(refusal.message, Some("deadlineMs")))?;
    Ok(deadline_ms.map(Duration::from_millis))
}

/// One raw search page: what to read, at what effort, and how to project it.
pub(super) struct SearchPage {
    pub(super) probe: SearchProbe,
    pub(super) depth: Effort,
    pub(super) view: View,
    pub(super) count_mode: CountMode,
    pub(super) page_limit: usize,
}

/// Reads and projects one page.
fn search_page(
    server: &SyncServer,
    page: SearchPage,
    deadline: Option<&RetrievalDeadline>,
) -> Result<ScopedSearchResponse, ApiError> {
    let admission = admit_deep_retrieval(server, page.depth)?;
    let scoped_read = scoped_read_for_legacy_api(server)?;
    let results = run_depth_search(
        &scoped_read,
        page.probe,
        page.depth,
        search_fetch_limit(page.count_mode, page.page_limit),
        admission.as_ref(),
        deadline,
    )?;
    let total = results.hits.len();
    let mut meta = search_meta(page.count_mode, total).with_quality(&results.retrieval_quality);
    meta.partial = results.partial;
    let response = search_depth_response(&scoped_read, &results, page.view, page.page_limit)?;
    let mut narrowing = results.narrowing;
    narrowing.push(response.receipt);
    Ok(ScopedSearchResponse {
        response: PaginatedResponse::new(response.value, None, meta),
        narrowing,
    })
}

/// The page a search answers with when its deadline came due before its read
/// finished: no hits, `meta.partial`, under the reader's receipt.
pub(super) fn cut_page(
    server: &SyncServer,
    count_mode: CountMode,
) -> Result<ScopedSearchResponse, ApiError> {
    let receipt = scoped_read_for_legacy_api(server)?
        .read_receipt(None, 0)
        .map_err(|_| ApiError::internal_server_error("read receipt failed"))?;
    let mut meta = search_meta(count_mode, 0);
    meta.partial = true;
    Ok(ScopedSearchResponse {
        response: PaginatedResponse::new(Vec::new(), None, meta),
        narrowing: vec![receipt],
    })
}

/// Runs a raw search page. With no deadline it runs inline, as it always
/// has. With one it reads on the blocking pool under that hard deadline,
/// counted from `arrived`, and the door answers when it comes due: with the
/// page if the read finished, else with [`cut_page`].
pub(super) async fn search_page_by_deadline(
    server: Arc<SyncServer>,
    arrived: Instant,
    budget: Option<Duration>,
    page: SearchPage,
) -> Result<ScopedSearchResponse, ApiError> {
    let Some(budget) = budget else {
        return search_page(&server, page, None);
    };
    let count_mode = page.count_mode;
    let reader = Arc::clone(&server);
    let task = tokio::task::spawn_blocking(move || {
        let deadline = RetrievalDeadline::hard(arrived, budget);
        search_page(&reader, page, Some(&deadline))
    });
    let due = tokio::time::Instant::from_std(arrived + budget);
    match tokio::time::timeout_at(due, task).await {
        Ok(joined) => {
            joined.unwrap_or_else(|_| Err(ApiError::internal_server_error("search did not finish")))
        }
        Err(_) => cut_page(&server, count_mode),
    }
}
