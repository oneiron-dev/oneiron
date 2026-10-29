//! The follower's requests (FIX 7510): a suffix's call over the retained
//! prefix, and a keyframe's fold call. A suffix's call is the instruction,
//! then one user message: the keyframe, the frames already sent (each its
//! stored bytes), the new frames, and last the one-shot question. The
//! retained prefix's last part carries the host's cache boundary, so a
//! provider that caches by marked blocks can reuse it; one with no
//! rendering for it sends a plain call. Frames name no id: the question
//! names each span's entity candidates by its call's own `P<n>` labels,
//! read back through the same map, bound into the request's identity.

use std::collections::BTreeMap;

use serde::Serialize;

use super::super::call_labels::{CallLabelMap, LabelKind};
use crate::code_run::{CacheBoundary, mark_cache_boundary};
use crate::dreamer_wake::follower::{AskWork, Asked, Pin};
use crate::dreamer_wake::{SpanBand, SpanKind, SpanOrigin};
use crate::error::{Error, Result};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, Scope, ScopeResource, TierPrecedence,
};

const ROUTE_DOMAIN: &[u8] = b"oneiron:dreamer-follower:route:v1";

/// One span as the question shows it: its ordinal in the suffix, where its
/// words are, the words, its cheap reading and its candidates' labels.
#[derive(Serialize)]
struct SpanView {
    span: usize,
    frame: String,
    chunk: u32,
    text: String,
    kind: SpanKind,
    entity: Option<String>,
    novel: Option<bool>,
    origin: serde_json::Value,
    confidence: u8,
    band: SpanBand,
    candidates: Vec<String>,
}

#[derive(Serialize)]
struct QuestionView {
    spans: Vec<SpanView>,
}

/// The labels a suffix's call names its candidates by: each span's
/// candidates in span order, numbered from `P1` as they first appear.
pub(super) fn labels(asked: &[Asked]) -> CallLabelMap {
    let mut labels = CallLabelMap::default();
    for entry in asked {
        for id in &entry.asked.candidates {
            labels.assign(LabelKind::Entity, *id);
        }
    }
    labels
}

/// The question part of a suffix: every span it asks about, one each.
pub(super) fn question(asked: &[Asked]) -> Result<String> {
    let labels = labels(asked);
    let label = |id: crate::EntityId| {
        labels
            .label(LabelKind::Entity, id)
            .as_ref()
            .map(ToString::to_string)
    };
    let spans = asked
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let span = &entry.asked.span;
            SpanView {
                span: index + 1,
                frame: format!("F{}", entry.asked.frame),
                chunk: entry.asked.chunk,
                text: entry.quote.clone(),
                kind: span.kind,
                entity: span.entity.and_then(label),
                novel: span.novel,
                origin: match span.origin {
                    SpanOrigin::Rule { rules, class } => {
                        serde_json::json!({"rule": {"rules": rules, "class": class}})
                    }
                    SpanOrigin::SavedTag { index, .. } => {
                        serde_json::json!({"saved_tag": {"index": index}})
                    }
                },
                confidence: span.confidence,
                band: span.band,
                candidates: entry
                    .asked
                    .candidates
                    .iter()
                    .filter_map(|id| label(*id))
                    .collect(),
            }
        })
        .collect();
    serde_json::to_string(&QuestionView { spans })
        .map_err(|_| Error::InvalidConfig("follower question encoding".into()))
}

/// The model and locality a follower call goes out on, hashed: a change
/// resends the prefix cold under a new epoch.
pub(super) fn route_digest(model: &ModelId, locality: ModelLocality) -> [u8; 32] {
    let locality = format!("{locality:?}");
    *blake3::Hasher::new()
        .update(ROUTE_DOMAIN)
        .update(&(model.as_str().len() as u64).to_be_bytes())
        .update(model.as_str().as_bytes())
        .update(locality.as_bytes())
        .finalize()
        .as_bytes()
}

/// A suffix's call: the retained prefix's last part (the instruction's,
/// when no part is retained) marked as its cache boundary.
pub(super) fn ask_request(
    model: &ModelId,
    locality: ModelLocality,
    keyless: bool,
    work: &AskWork,
    labels: &CallLabelMap,
) -> Result<LlmRequest> {
    let mut content: Vec<ContentPart> = work
        .prefix
        .iter()
        .map(|text| ContentPart::Text { text: text.clone() })
        .collect();
    let retained = content.len();
    content.extend(
        work.fresh
            .iter()
            .map(|text| ContentPart::Text { text: text.clone() }),
    );
    content.push(ContentPart::Text {
        text: work.question.clone(),
    });
    let mut request = request(
        model,
        locality,
        keyless,
        &work.pins,
        work.instruction.clone(),
        content,
    );
    labels.bind_request(&mut request, None);
    let boundary = match retained.checked_sub(1) {
        Some(part) => CacheBoundary::Message { message: 1, part },
        None => CacheBoundary::Message {
            message: 0,
            part: 0,
        },
    };
    mark_cache_boundary(&mut request, boundary)
        .map_err(|_| Error::InvalidConfig("follower cache boundary".into()))?;
    Ok(request)
}

/// A keyframe fold's call over one group of parts.
pub(super) fn fold_request(
    model: &ModelId,
    locality: ModelLocality,
    keyless: bool,
    instruction: &str,
    group: &[String],
    pins: &[Pin],
) -> LlmRequest {
    let content = group
        .iter()
        .map(|text| ContentPart::Text { text: text.clone() })
        .collect();
    request(
        model,
        locality,
        keyless,
        pins,
        instruction.to_owned(),
        content,
    )
}

fn request(
    model: &ModelId,
    locality: ModelLocality,
    keyless: bool,
    pins: &[Pin],
    system: String,
    content: Vec<ContentPart>,
) -> LlmRequest {
    let scope = Scope {
        readable: pins
            .iter()
            .map(|pin| ScopeResource::DocumentVersion {
                document: pin.document,
                version: pin.version.clone(),
            })
            .collect(),
        ..Scope::default()
    };
    LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope,
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality,
            host_keyless: keyless,
        }
        .with_purpose_defaults(),
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text { text: system }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content,
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}
