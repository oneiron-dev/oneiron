//! A rerank call over more documents than one provider request carries
//! (FIX 9514). The documents go in batches of at most [`BATCH_DOCUMENTS`],
//! in order, each one request on the call's one admitted lease, so the run
//! meters and settles the whole call once, on its usage summed over every
//! batch. Each batch's scores land at their documents' places in one full
//! result, every document scored once, in the caller's order and never cut
//! to a top few. A batch that fails fails the call: a shorter list is never
//! an answer.
//! Entry: `rerank_batches`.
use std::collections::BTreeMap;

use oneiron::llm::limit;
use oneiron::{FatalLlmError, LlmResult, RetryableLlmError};
use serde_json::{Value as JsonValue, json};

use super::{RERANK_PATH, RerankBackend, indexed_scores, transport};
use crate::models::served::{SERVED_MODEL_KEY, record_served_model};

/// The most documents one provider request carries: a transport's batch,
/// never a limit on the call.
const BATCH_DOCUMENTS: usize = 50;

/// One provider request's documents, and where the first of them sits in
/// the call.
pub(super) struct RerankBatch<'a> {
    pub(super) offset: usize,
    pub(super) documents: &'a [&'a str],
}

/// What one batch's request answered: a score per document in its order,
/// the tokens it counted, and its usage as the provider sent it, stamped
/// with the model it said it served.
pub(super) struct BatchAnswer {
    pub(super) scores: Vec<f32>,
    pub(super) tokens: u64,
    pub(super) usage: JsonValue,
}

/// `documents` in batches, in order.
pub(super) fn rerank_batches<'a>(
    documents: &'a [&'a str],
) -> impl Iterator<Item = RerankBatch<'a>> + 'a {
    documents
        .chunks(BATCH_DOCUMENTS)
        .enumerate()
        .map(|(index, documents)| RerankBatch {
            offset: index * BATCH_DOCUMENTS,
            documents,
        })
}

/// Lands `batch`'s `answered` scores, one per document of it in order, at
/// their places in the call's `scores`, each place once. `None` when the
/// batch answered for other documents than it sent.
pub(super) fn merge_indexed_scores(
    scores: &mut [Option<f32>],
    batch: &RerankBatch<'_>,
    answered: Vec<f32>,
) -> Option<()> {
    if answered.len() != batch.documents.len() {
        return None;
    }
    for (index, score) in answered.into_iter().enumerate() {
        let place = scores.get_mut(batch.offset.checked_add(index)?)?;
        if place.is_some() {
            return None;
        }
        *place = Some(score);
    }
    Some(())
}

/// The call's usage from each batch's, in order: one batch's as it came, as
/// a call of one batch always reported; several as their summed tokens
/// beside each batch's own, naming the served model when every batch named
/// the same one.
pub(super) fn joined_usage(mut usages: Vec<JsonValue>, tokens: u64) -> JsonValue {
    if let [usage] = usages.as_mut_slice() {
        return std::mem::take(usage);
    }
    let served = usages
        .first()
        .and_then(|usage| usage.get(SERVED_MODEL_KEY))
        .cloned();
    let same = usages
        .iter()
        .all(|usage| usage.get(SERVED_MODEL_KEY) == served.as_ref());
    let mut joined = json!({ "total_tokens": tokens, "batches": usages });
    record_served_model(Some(&mut joined), served.filter(|_| same));
    joined
}

impl RerankBackend {
    /// One batch's request to its scores: the query and the batch's
    /// documents, sent once.
    pub(super) async fn send_batch(
        &self,
        wire_model: &str,
        query: &str,
        batch: &RerankBatch<'_>,
    ) -> LlmResult<BatchAnswer> {
        let body = json!({
            "model": wire_model,
            "query": query,
            "documents": batch.documents,
            "top_n": batch.documents.len(),
            "return_documents": false,
        });
        let mut reply = self
            .http
            .post_json(RERANK_PATH, &BTreeMap::new(), &body)
            .await
            .map_err(transport)?;
        match reply.status {
            200..=299 => {}
            status if limit::is_limit_status(status, &reply.body) => {
                return Err(limit::limit_refusal(status, &reply.headers, &reply.body).into());
            }
            401 | 403 => return Err(FatalLlmError::Auth.into()),
            400..=499 => return Err(FatalLlmError::InvalidRequest.into()),
            _ => return Err(RetryableLlmError::ServerError.into()),
        }
        let scores = indexed_scores(&reply.body, batch.documents.len())
            .ok_or(FatalLlmError::EmptyResponse)?;
        let served = reply.body.get("model").cloned();
        let mut usage = match reply.body.get_mut("usage").map(JsonValue::take) {
            Some(usage @ JsonValue::Object(_)) => usage,
            _ => JsonValue::Object(serde_json::Map::new()),
        };
        let tokens = usage
            .get("total_tokens")
            .or_else(|| usage.get("prompt_tokens"))
            .and_then(JsonValue::as_u64)
            .unwrap_or(0);
        record_served_model(Some(&mut usage), served);
        Ok(BatchAnswer {
            scores,
            tokens,
            usage,
        })
    }
}
