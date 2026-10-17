//! Raw search under a request's hard deadline (`deadlineMs`): the page reads
//! on the blocking pool, and the door answers when the deadline comes due.

use super::*;
use crate::auth::CoreAuth;
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
    /// The credential the door admitted; the page reads under its key.
    pub(super) auth: CoreAuth,
}

/// Reads and projects one page under the request's deep-retrieval
/// `admission` (none below the paid efforts).
pub(super) fn search_page(
    server: &SyncServer,
    page: SearchPage,
    admission: Option<&DeepAdmission>,
    deadline: Option<&RetrievalDeadline>,
) -> Result<ScopedSearchResponse, ApiError> {
    let scoped_read = scoped_read_for_legacy_api(server, &page.auth)?;
    let results = run_depth_search(
        &scoped_read,
        page.probe,
        page.depth,
        search_fetch_limit(page.count_mode, page.page_limit),
        admission,
        deadline,
    )?;
    let total = results.hits.len();
    let mut meta = search_meta(page.count_mode, total).with_quality(&results.retrieval_quality);
    meta.partial = results.partial;
    let mut bodies =
        projection::BodyBudget::new(&server.vault, server.config.limits.projection_body_bytes);
    let response = search_depth_response(
        &scoped_read,
        &results,
        page.view,
        page.page_limit,
        &mut bodies,
    )?;
    let mut narrowing = results.narrowing;
    narrowing.push(response.receipt);
    Ok(ScopedSearchResponse {
        response: PaginatedResponse::new(response.value, None, meta),
        narrowing,
        residence: None,
    })
}

/// The page a search answers with when its deadline came due before its read
/// finished: no hits, `meta.partial`, under the reader's receipt.
fn cut_page(
    server: &SyncServer,
    auth: &CoreAuth,
    count_mode: CountMode,
) -> Result<ScopedSearchResponse, ApiError> {
    let receipt = scoped_read_for_legacy_api(server, auth)?
        .read_receipt(None, 0)
        .map_err(|_| ApiError::internal_server_error("read receipt failed"))?;
    let mut page = unread_page(count_mode);
    page.narrowing.push(receipt);
    Ok(page)
}

/// The page a search answers with when its deadline came due before it read
/// anything: no hits, `meta.partial`, and no receipt.
fn unread_page(count_mode: CountMode) -> ScopedSearchResponse {
    let mut meta = search_meta(count_mode, 0);
    meta.partial = true;
    ScopedSearchResponse {
        response: PaginatedResponse::new(Vec::new(), None, meta),
        narrowing: Vec::new(),
        residence: None,
    }
}

/// Runs a raw search page, admitted first. With no deadline it runs inline,
/// as it always has; with one, [`read_by_deadline`] reads it.
pub(super) async fn search_page_by_deadline(
    server: Arc<SyncServer>,
    arrived: Instant,
    budget: Option<Duration>,
    page: SearchPage,
) -> Result<ScopedSearchResponse, ApiError> {
    let admission = admit_deep_retrieval(&server, page.depth)?;
    match budget {
        None => search_page(&server, page, admission.as_ref(), None),
        Some(budget) => {
            let count_mode = page.count_mode;
            let auth = page.auth.clone();
            read_by_deadline(
                server,
                arrived,
                budget,
                count_mode,
                auth,
                move |server, deadline| {
                    search_page(server, page, admission.as_ref(), Some(deadline))
                },
            )
            .await
        }
    }
}

/// Runs `read` on the blocking pool under the hard deadline `budget`,
/// counted from `arrived`; the caller has already admitted the request, so
/// every refusal precedes the answer. The read first publishes [`cut_page`], off the
/// async thread because the reader's receipt reads the store, and the door
/// answers when the deadline comes due: with the page if the read finished,
/// else with the cut page. When the read has not reached even that (the
/// blocking pool had not started it, or proving the host's root slip waits
/// on a writer), the door answers with no hits and no receipt, marked
/// partial: nothing was read.
pub(super) async fn read_by_deadline(
    server: Arc<SyncServer>,
    arrived: Instant,
    budget: Duration,
    count_mode: CountMode,
    auth: CoreAuth,
    read: impl FnOnce(&SyncServer, &RetrievalDeadline) -> Result<ScopedSearchResponse, ApiError>
    + Send
    + 'static,
) -> Result<ScopedSearchResponse, ApiError> {
    let (publish, ready) = std::sync::mpsc::sync_channel(1);
    let task = tokio::task::spawn_blocking(move || {
        let deadline = RetrievalDeadline::hard(arrived, budget);
        // The door reads at most one; a closed slot is moot.
        let _ = publish.try_send(cut_page(&server, &auth, count_mode)?);
        read(&server, &deadline)
    });
    let due = tokio::time::Instant::from_std(arrived + budget);
    match tokio::time::timeout_at(due, task).await {
        Ok(joined) => {
            joined.unwrap_or_else(|_| Err(ApiError::internal_server_error("search did not finish")))
        }
        Err(_) => Ok(ready.try_recv().unwrap_or_else(|_| unread_page(count_mode))),
    }
}
