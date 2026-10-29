//! The rerank transport: the `reranker` role's rungs speak `/v1/rerank`, the
//! indexed-scores protocol OpenAI-compatible model servers serve beside chat
//! (`{model, query, documents}` in, `{results: [{index, relevance_score}],
//! usage}` out).
//!
//! A rerank call is a model call like any other: it rides an [`LlmRequest`]
//! through the seat's ladder, so each rung it reaches is admitted on its own
//! permit and sent through the run's gate, and its digest covers the query
//! and every document that leave ([`rerank_request`]). The answer comes back
//! as one score per document, in order ([`rerank_scores`]), however many
//! documents the call names: they go in batches on its one permit
//! ([`batches`], FIX 9514).
use std::collections::BTreeMap;

use oneiron::llm::SingleRouteBackend;
use oneiron::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, FatalLlmError, LlmBackend,
    LlmCapability, LlmError, LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmResult, LlmStreamResult, LlmUsage, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, RetryableLlmError, TierPrecedence,
};
use serde_json::Value as JsonValue;

use super::http::{HttpFailure, ProviderHttp};

mod batches;
use batches::{joined_usage, merge_indexed_scores, rerank_batches};

/// The protocol path, joined to the provider's base URL.
const RERANK_PATH: &str = "/v1/rerank";

/// The purpose a rerank call is admitted under.
const RERANK_PURPOSE: &str = "rerank";

/// The rerank call for `query` over `documents`, at `locality`: the query is
/// the first user message, and each document one text part of the second,
/// in order. The ladder names the model.
pub(crate) fn rerank_request(
    query: &str,
    documents: &[&str],
    locality: ModelLocality,
) -> LlmRequest {
    let purpose = CallPurpose::Other {
        name: RERANK_PURPOSE.to_owned(),
    };
    let text = |text: &str| ContentPart::Text {
        text: text.to_owned(),
    };
    LlmRequest {
        model: ModelId::new("seat/reranker@unbound").expect("a well-formed placeholder id"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(RERANK_PURPOSE.into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![text(query)],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: documents.iter().copied().map(text).collect(),
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

/// One score per document, in order, from a rerank call's answer.
pub(crate) fn rerank_scores(response: &LlmResponse) -> Option<Vec<f32>> {
    let [ContentPart::Text { text }] = response.message.content.as_slice() else {
        return None;
    };
    serde_json::from_str(text).ok()
}

/// The query and documents a rerank request carries. A rung's instruction
/// (a system message) is not part of the protocol, and is not sent.
fn parts(request: &LlmRequest) -> Option<(&str, Vec<&str>)> {
    let mut messages = request
        .messages
        .iter()
        .filter(|message| message.role != LlmMessageRole::System);
    let (Some(query), Some(documents), None) = (messages.next(), messages.next(), messages.next())
    else {
        return None;
    };
    let [query] = query.content.as_slice() else {
        return None;
    };
    let query = part_text(query)?;
    let documents = documents
        .content
        .iter()
        .map(part_text)
        .collect::<Option<Vec<_>>>()?;
    let refused = query.trim().is_empty()
        || documents.is_empty()
        || !request.tools.is_empty()
        || !request.params.is_empty()
        || !request.provider_options.is_empty();
    (!refused).then_some((query, documents))
}

fn part_text(part: &ContentPart) -> Option<&str> {
    match part {
        ContentPart::Text { text } => Some(text),
        _ => None,
    }
}

/// One provider's rerank client. It serves the reranker rungs on that
/// provider, each by its own wire model.
pub(super) struct RerankBackend {
    http: ProviderHttp,
    /// Each served engine model id, and the name the provider knows it by.
    wire_models: BTreeMap<ModelId, String>,
}

impl RerankBackend {
    pub(super) fn new(http: ProviderHttp, wire_models: BTreeMap<ModelId, String>) -> Self {
        Self { http, wire_models }
    }
}

/// One `.send()` per batch over [`ProviderHttp`], in order, which follows no
/// redirect and never resends: a run's gate may wrap this backend.
impl oneiron::llm::SingleSend for RerankBackend {}

impl SingleRouteBackend for RerankBackend {
    fn preflight(&self, request: &LlmRequest, stream: bool) -> LlmResult<()> {
        if stream || !self.wire_models.contains_key(&request.model) || parts(request).is_none() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(())
    }
}

impl LlmBackend for RerankBackend {
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        false
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            self.preflight(&request, false)?;
            let (query, documents) = parts(&request).ok_or(FatalLlmError::InvalidRequest)?;
            let wire_model = &self.wire_models[&request.model];
            let mut scores = vec![None; documents.len()];
            let mut tokens = 0u64;
            let mut usages = Vec::new();
            for batch in rerank_batches(&documents) {
                let answer = self.send_batch(wire_model, query, &batch).await?;
                merge_indexed_scores(&mut scores, &batch, answer.scores)
                    .ok_or(FatalLlmError::EmptyResponse)?;
                tokens = tokens.saturating_add(answer.tokens);
                usages.push(answer.usage);
            }
            let scores: Vec<f32> = scores
                .into_iter()
                .collect::<Option<_>>()
                .ok_or(FatalLlmError::EmptyResponse)?;
            let usage = joined_usage(usages, tokens);
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: serde_json::to_string(&scores)
                            .map_err(|_| FatalLlmError::EmptyResponse)?,
                    }],
                },
                usage: LlmUsage {
                    input: LlmInputUsage {
                        total: tokens,
                        ..LlmInputUsage::default()
                    },
                    output: Default::default(),
                    raw_provider: usage,
                },
                finish_reason: oneiron::llm::FinishReason::Stop,
                // A reranker's scores assert no record (FIX 3416).
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// Every document's score, in document order: each index once, each score a
/// finite number. Anything else is no answer.
fn indexed_scores(body: &JsonValue, count: usize) -> Option<Vec<f32>> {
    let results = body.get("results")?.as_array()?;
    if results.len() != count {
        return None;
    }
    let mut scores = vec![None; count];
    for row in results {
        let index = usize::try_from(row.get("index")?.as_u64()?).ok()?;
        // A relevance score is compared, never summed: f32 holds its order.
        let score = row.get("relevance_score")?.as_f64()? as f32;
        if !score.is_finite() || scores.get(index)?.is_some() {
            return None;
        }
        scores[index] = Some(score);
    }
    scores.into_iter().collect()
}

pub(super) fn transport(failure: HttpFailure) -> LlmError {
    match failure {
        HttpFailure::Timeout => RetryableLlmError::Timeout.into(),
        // A media reply this machine could not allocate (FIX 8615) is no
        // fault of the provider's answer: the call may be tried again.
        HttpFailure::Connection | HttpFailure::StreamCut | HttpFailure::OutOfMemory => {
            RetryableLlmError::ServerError.into()
        }
        HttpFailure::Malformed | HttpFailure::EventTooLarge | HttpFailure::BodyTooLarge => {
            FatalLlmError::EmptyResponse.into()
        }
    }
}
