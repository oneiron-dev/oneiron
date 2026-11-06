//! Whole-row composition passes with separate citation and producer cohorts.
use std::collections::BTreeSet;

use oneiron::retrieval_depth::{BackendSpend, RetrievalError, RetrievalResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::frame::FrameEstimate;
use super::sources::{self, Pin};
use super::{Backend, MemoryReasonComposeRequest, MemoryReasonComposition, call, invalid};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Composed {
    answer: String,
    source_short_ids: Vec<String>,
    confidence: f32,
    gaps: Vec<String>,
    declined: bool,
}

struct Unit {
    draft: Composed,
    // All inputs can influence prose, even when the model does not cite them.
    producers: BTreeSet<usize>,
}

pub(super) fn compose(
    backend: &Backend,
    request: &MemoryReasonComposeRequest<'_>,
) -> RetrievalResult<BackendSpend<MemoryReasonComposition>> {
    let pins = sources::compose_pins(backend, request.evidence)?;
    let schema = schema();
    let rows: Vec<_> = request
        .evidence
        .iter()
        .map(|row| {
            json!({
                "shortId":row.short_id,"kind":row.kind,"text":row.text,"confidence":row.confidence,
            })
        })
        .collect();
    let whole = map_data(request, &rows);
    let Some(frame) = FrameEstimate::sample(backend) else {
        let mut answered = single(backend, request, whole, schema, &pins)?;
        answered
            .value
            .gaps
            .push("model frame metadata is incomplete; evidence was sent whole".into());
        return Ok(answered);
    };
    if frame.fits(&whole, &schema) {
        return single(backend, request, whole, schema, &pins);
    }

    let mut spent = 0_u64;
    let mut gaps = Vec::new();
    let mut units = Vec::new();
    let mut start = 0;
    while start < rows.len() {
        let mut end = start + 1;
        while end < rows.len() && frame.fits(&map_data(request, &rows[start..=end]), &schema) {
            end += 1;
        }
        let data = map_data(request, &rows[start..end]);
        if !frame.fits(&data, &schema) {
            gaps.push(format!(
                "whole evidence row exceeds the estimated model frame: {}",
                request.evidence[start].short_id
            ));
        }
        let allowed: BTreeSet<_> = request.evidence[start..end]
            .iter()
            .map(|row| row.short_id.clone())
            .collect();
        let parsed = pass(
            backend,
            request,
            data,
            &schema,
            &pins[start..end],
            &mut spent,
        )?;
        match parsed.and_then(|draft| valid(draft, &allowed)) {
            Some(draft) => {
                gaps.extend(draft.gaps.iter().cloned());
                units.push(Unit {
                    draft,
                    producers: (start..end).collect(),
                });
            }
            None => gaps.push(unusable(&allowed)),
        }
        start = end;
    }

    while units.len() > 1 {
        // A reduction must consume at least two units. Free or unmeasured
        // calls cannot otherwise supply a termination bound.
        let pair = (0..units.len()).find_map(|left| {
            (left + 1..units.len()).find_map(|right| {
                let data = reduce_data(request, &units[left], &units[right]);
                frame.fits(&data, &schema).then_some((left, right, data))
            })
        });
        let Some((left, right, data)) = pair else {
            gaps.push("remaining drafts do not fit together in the estimated model frame; using the full evidence".into());
            return Ok(fallback(spent, gaps));
        };
        let allowed: BTreeSet<_> = units[left]
            .draft
            .source_short_ids
            .iter()
            .chain(&units[right].draft.source_short_ids)
            .cloned()
            .collect();
        let producers: BTreeSet<_> = units[left]
            .producers
            .union(&units[right].producers)
            .copied()
            .collect();
        let pass_pins: Vec<_> = producers.iter().map(|&index| pins[index].clone()).collect();
        let parsed = pass(backend, request, data, &schema, &pass_pins, &mut spent)?;
        units.remove(right);
        units.remove(left);
        match parsed.and_then(|draft| valid(draft, &allowed)) {
            Some(draft) => {
                gaps.extend(draft.gaps.iter().cloned());
                units.push(Unit { draft, producers });
            }
            None => gaps.push(unusable(&allowed)),
        }
    }
    let Some(unit) = units.pop() else {
        gaps.push("no usable composition draft; using the full evidence".into());
        return Ok(fallback(spent, gaps));
    };
    let mut value = composition(unit.draft);
    value.gaps = gaps;
    Ok(BackendSpend {
        value,
        tokens_used: spent,
    })
}

fn single(
    backend: &Backend,
    request: &MemoryReasonComposeRequest<'_>,
    data: Value,
    schema: Value,
    pins: &[Pin],
) -> RetrievalResult<BackendSpend<MemoryReasonComposition>> {
    let answered = backend.generate_json(data, schema, pins, Some(request.token_budget))?;
    let tokens_used = answered.tokens_used;
    let parsed =
        serde_json::from_str(&call::text(&answered.value)).map_err(|_| RetrievalError {
            error: invalid("memory reason composition is not the requested JSON"),
            tokens_used,
        })?;
    Ok(BackendSpend {
        value: composition(parsed),
        tokens_used,
    })
}

fn pass(
    backend: &Backend,
    request: &MemoryReasonComposeRequest<'_>,
    data: Value,
    schema: &Value,
    pins: &[Pin],
    spent: &mut u64,
) -> RetrievalResult<Option<Composed>> {
    let answered = backend
        .generate_json(
            data,
            schema.clone(),
            pins,
            Some(request.token_budget.saturating_sub(*spent)),
        )
        .map_err(|mut failure| {
            failure.tokens_used = failure.tokens_used.saturating_add(*spent);
            failure
        })?;
    *spent = spent.saturating_add(answered.tokens_used);
    Ok(serde_json::from_str(&call::text(&answered.value)).ok())
}

fn valid(mut draft: Composed, allowed: &BTreeSet<String>) -> Option<Composed> {
    if draft.declined
        || draft.answer.trim().is_empty()
        || draft.source_short_ids.is_empty()
        || !draft.confidence.is_finite()
    {
        return None;
    }
    for cited in &mut draft.source_short_ids {
        *cited = cited.trim().to_owned();
        if !allowed.contains(cited) {
            return None;
        }
    }
    Some(draft)
}

fn unusable(allowed: &BTreeSet<String>) -> String {
    format!(
        "unusable composition draft for sources: {}",
        allowed
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn composition(draft: Composed) -> MemoryReasonComposition {
    MemoryReasonComposition {
        answer: draft.answer,
        source_short_ids: draft.source_short_ids,
        confidence: draft.confidence,
        gaps: draft.gaps,
        declined: draft.declined,
    }
}

fn fallback(tokens_used: u64, gaps: Vec<String>) -> BackendSpend<MemoryReasonComposition> {
    BackendSpend {
        tokens_used,
        value: MemoryReasonComposition {
            answer: String::new(),
            source_short_ids: Vec::new(),
            confidence: 0.0,
            gaps,
            declined: true,
        },
    }
}

fn map_data(request: &MemoryReasonComposeRequest<'_>, rows: &[Value]) -> Value {
    json!({"operation":"compose","question":request.question,
        "depth":request.depth,"format":request.format,"evidence":rows})
}

fn reduce_data(request: &MemoryReasonComposeRequest<'_>, left: &Unit, right: &Unit) -> Value {
    json!({"operation":"compose","question":request.question,
        "depth":request.depth,"format":request.format,"drafts":[left.draft,right.draft]})
}

fn schema() -> Value {
    json!({"type":"object","properties":{
        "answer":{"type":"string"},"sourceShortIds":{"type":"array","items":{"type":"string"}},
        "confidence":{"type":"number","minimum":0,"maximum":1},
        "gaps":{"type":"array","items":{"type":"string"}},"declined":{"type":"boolean"}},
        "required":["answer","sourceShortIds","confidence","gaps","declined"],"additionalProperties":false})
}
