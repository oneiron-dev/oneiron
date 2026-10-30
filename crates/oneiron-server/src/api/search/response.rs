//! A raw search's depth read and its page projection: the one effort dial
//! both raw search endpoints enter, and the page each projects under its
//! scoped read.

use super::*;

/// The one place both raw search endpoints enter the effort dial.
///
/// Shared so the two cannot drift into different tier semantics for the same
/// `depth` value, and so a hit's own accounting stays where it belongs: these
/// endpoints return a paginated hit list with no place to report backend
/// spend, so a deep read here settles its lease against what it actually
/// spent and reports nothing further.
pub(super) fn run_depth_search(
    scoped_read: &ScopedRead<'_>,
    probe: SearchProbe,
    effort: Effort,
    limit: usize,
    admission: Option<&DeepAdmission>,
    deadline: Option<&RetrievalDeadline>,
) -> Result<DepthSearchResult, ApiError> {
    // A zero-limit page was an empty 200 on this endpoint before the dial
    // existed, and the dial is not the place to turn it into a refusal.
    if limit == 0 {
        return Ok(DepthSearchResult {
            narrowing: vec![
                scoped_read
                    .read_receipt(None, 0)
                    .map_err(|_| ApiError::internal_server_error("read receipt failed"))?,
            ],
            ..Default::default()
        });
    }
    let request = DepthSearchRequest {
        deadline,
        probe,
        effort,
        limit,
        session_scope: None,
        lease: admission.map(DeepAdmission::lease),
        backend: admission.map(DeepAdmission::search_backend),
        token_budget: None,
    };
    let result = scoped_read.search_with_effort(&request);
    if let Some(admission) = admission {
        admission.record_usage(result.as_ref().map_or_else(
            |failure| failure.tokens_used,
            |retrieved| retrieved.tokens_used,
        ));
    }
    let result = result.map_err(|failure| depth_search_error(failure.error));
    match admission {
        Some(admission) => admission.finish(result),
        None => result,
    }
}

pub(crate) fn search_fetch_limit(count_mode: CountMode, page_limit: usize) -> usize {
    match count_mode {
        CountMode::None => page_limit,
        CountMode::Estimate => page_limit.saturating_add(1),
        CountMode::Exact => unreachable!("search responses never report exact counts"),
    }
}

pub(crate) fn search_meta(count_mode: CountMode, estimated_total: usize) -> ResponseMeta {
    match count_mode {
        CountMode::None => ResponseMeta::none(),
        CountMode::Estimate => ResponseMeta::estimate(estimated_total as u64),
        CountMode::Exact => unreachable!("search responses never report exact counts"),
    }
}

#[cfg(test)]
pub(crate) fn search_response(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    results: Vec<oneiron::ScoredEntity>,
    view: View,
    page_limit: usize,
) -> Result<oneiron::claim::ScopedReadResult<Vec<Value>>, ApiError> {
    let mut bodies = projection::BodyBudget::new(
        scoped_read.vault(),
        crate::config::LimitsConfig::default().projection_body_bytes,
    );
    search_response_with_revisions(
        scoped_read,
        results,
        None,
        view,
        page_limit,
        None,
        None,
        &mut bodies,
    )
}

pub(super) fn search_depth_response(
    scoped_read: &ScopedRead<'_>,
    results: &DepthSearchResult,
    view: View,
    page_limit: usize,
    bodies: &mut projection::BodyBudget<'_>,
) -> Result<oneiron::claim::ScopedReadResult<Vec<Value>>, ApiError> {
    // finish_scoped appends the final intersection of the channel receipts.
    let requested = results
        .narrowing
        .last()
        .map(|receipt| receipt.applied.as_filter());
    search_response_with_revisions(
        scoped_read,
        results.hits.clone(),
        Some(&results.revisions),
        view,
        page_limit,
        None,
        requested.as_ref(),
        bodies,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the one page projection"
)]
pub(crate) fn search_response_with_revisions(
    scoped_read: &ScopedRead<'_>,
    results: Vec<oneiron::ScoredEntity>,
    revisions: Option<&std::collections::HashMap<oneiron::EntityId, oneiron::memory::RevisionRef>>,
    view: View,
    page_limit: usize,
    observations: Option<&mut oneiron::context_board::SessionReadSet>,
    requested: Option<&oneiron::RetrievalFilter>,
    bodies: &mut projection::BodyBudget<'_>,
) -> Result<oneiron::claim::ScopedReadResult<Vec<Value>>, ApiError> {
    let selected: Vec<_> = results
        .into_iter()
        .filter_map(|result| {
            let mode = match revisions {
                Some(revisions) => oneiron::memory::ReadMode::Pinned(*revisions.get(&result.id)?),
                None => oneiron::memory::ReadMode::Indexed,
            };
            Some((result, mode))
        })
        .collect();
    let refs: Vec<_> = selected
        .iter()
        .map(|(row, mode)| oneiron::claim::PointRead::id(row.id).at(*mode))
        .collect();
    let read = scoped_read.read(&refs, requested).map_err(|error| {
        tracing::error!(kind = ?error.kind(), "search projection failed");
        ApiError::internal_server_error("search projection failed")
    })?;
    let mut receipt = read.receipt;
    let mut staged = observations.as_deref().cloned();
    let mut response = Vec::with_capacity(selected.len().min(page_limit));
    for ((result, mode), row) in selected.into_iter().zip(read.value) {
        let Some(oneiron::claim::ReadRow {
            entity_type,
            learned_at,
            body: Some(body),
            ..
        }) = row
        else {
            continue;
        };
        // All overfetch rows were validated in the page snapshot. Observe only served rows.
        if response.len() >= page_limit {
            continue;
        }
        // A body is decoded, to project it or to observe it, only while the
        // page's body budget holds it; Standard alone projects none.
        let decoded =
            (matches!(view, View::Standard) && staged.is_none()) || bodies.admits(body.len());
        if decoded
            && let Some(observations) = staged.as_mut()
            && let Some(successor) = observations
                .observe_snapshot(
                    scoped_read,
                    result.id,
                    entity_type,
                    &body,
                    matches!(view, View::Full),
                )
                .map_err(|error| {
                    tracing::error!(kind = ?error.kind(), "search observation failed");
                    ApiError::internal_server_error("search projection failed")
                })?
        {
            receipt.restrict_with(&successor);
        }
        let mut value = if matches!(view, View::Standard) {
            json!({"id": result.id.to_hex(), "score": result.score})
        } else if decoded {
            projection::project_entity_parts(&result.id, entity_type, learned_at, &body, view)
        } else {
            bodies.omitted(&result.id, entity_type, learned_at, &body, view, mode)
        };
        if matches!(view, View::Full)
            && let Value::Object(object) = &mut value
        {
            object.insert("score".to_owned(), json!(result.score));
        }
        response.push(value);
    }
    if let (Some(target), Some(staged)) = (observations, staged) {
        *target = staged;
    }
    Ok(oneiron::claim::ScopedReadResult {
        value: response,
        receipt,
    })
}
