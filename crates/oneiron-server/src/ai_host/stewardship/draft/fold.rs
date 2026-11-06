//! Provider-failure-driven evidence splitting and pairwise draft synthesis.
use oneiron::dreamer_runner::maintenance::representation::{
    PrematerializedDraft, RepresentationContext, RepresentationDraft, RepresentationPlanner,
};
use oneiron::dreamer_runner::maintenance::stewardship::StewardshipDraftRequest;
use oneiron::{Error, Vault};

use super::{DraftFailure, DraftPass, DraftStage, GeneratedDraft, at, generate_draft, now};
use crate::ai_host::stewardship::Drafter;
use crate::ai_host::stewardship::sources::{EvidenceSpan, contains_sources, covers};
use crate::models::ModelRuntime;

pub(super) async fn draft_fold(
    vault: &Vault,
    runtime: &ModelRuntime,
    drafter: Drafter,
    draft: &StewardshipDraftRequest,
    first_failure: DraftFailure,
) -> oneiron::Result<DraftPass> {
    let mut pending = Vec::new();
    if draft.request.evidence.len() > 1 {
        split(draft.clone(), &mut pending);
    } else if let Some(span) = first_failure.overflow_span().and_then(|span| span.split()) {
        push_spans(draft.clone(), span, &mut pending);
    } else {
        return failed(vault, draft, first_failure);
    }
    let mut answers = Vec::new();
    while let Some(part) = pending.pop() {
        if let Some(outcome) = moved(vault, draft)? {
            return Ok(outcome);
        }
        match generate_draft(
            vault,
            runtime,
            drafter,
            &part.draft,
            &[],
            part.span.as_ref(),
        )
        .await
        {
            Ok(answer) => answers.push(answer),
            Err(failure)
                if failure.stage == DraftStage::Call && part.draft.request.evidence.len() > 1 =>
            {
                split(part.draft, &mut pending);
            }
            Err(failure) => {
                let span = if failure.context_overflow() {
                    part.span.or_else(|| failure.overflow_span())
                } else {
                    None
                };
                if let Some(spans) = span.and_then(|span| span.split()) {
                    push_spans(part.draft, spans, &mut pending);
                } else {
                    return failed(vault, draft, failure);
                }
            }
        }
    }
    while answers.len() > 1 {
        if let Some(outcome) = moved(vault, draft)? {
            return Ok(outcome);
        }
        let right = answers.pop().expect("two draft parts");
        let left = answers.pop().expect("two draft parts");
        let parts = [left, right];
        let joined = joined_request(draft, &parts);
        match generate_draft(vault, runtime, drafter, &joined, &parts, None).await {
            Ok(answer) if !answer.text.trim().is_empty() => answers.push(answer),
            Ok(_)
            | Err(DraftFailure {
                stage: DraftStage::Call,
                ..
            }) => {
                answers.extend(parts);
                return schedule_parts(vault, draft, answers);
            }
            Err(failure) => return failed(vault, draft, failure),
        }
    }
    schedule_parts(vault, draft, answers)
}

/// A failed synthesis need not discard completed drafts. This is a local
/// composition, not an answer from a new destination or a new model call.
fn schedule_parts(
    vault: &Vault,
    draft: &StewardshipDraftRequest,
    answers: Vec<GeneratedDraft>,
) -> oneiron::Result<DraftPass> {
    if let Some(outcome) = moved(vault, draft)? {
        return Ok(outcome);
    }
    let served = joined_request(draft, &answers);
    let mut expected = Vec::with_capacity(answers.len());
    let mut text = String::new();
    let mut coverage = Vec::new();
    for answer in answers {
        if !text.is_empty() {
            text.push_str("\n\n");
        }
        text.push_str(&answer.text);
        expected.push(answer.snapshot.context);
        coverage.extend(answer.coverage);
    }
    let mut planner = FoldedDraft {
        expected,
        coverage,
        inner: PrematerializedDraft { text },
    };
    match vault.schedule_stewardship_draft(&served, &mut planner, now()) {
        Ok(outcome) => Ok(DraftPass::Done(outcome)),
        Err(error) => failed(vault, draft, at(DraftStage::Schedule)(error)),
    }
}

fn joined_request(
    draft: &StewardshipDraftRequest,
    answers: &[GeneratedDraft],
) -> StewardshipDraftRequest {
    let mut joined = draft.clone();
    joined.request.evidence.clear();
    joined.request.voice.clear();
    for answer in answers {
        for source in &answer.served.request.evidence {
            if !joined.request.evidence.contains(source) {
                joined.request.evidence.push(*source);
            }
        }
        for source in &answer.served.request.voice {
            if !joined.request.voice.contains(source) {
                joined.request.voice.push(*source);
            }
        }
    }
    joined
}

struct DraftPart {
    draft: StewardshipDraftRequest,
    span: Option<EvidenceSpan>,
}

fn push_spans(
    draft: StewardshipDraftRequest,
    (left, right): (EvidenceSpan, EvidenceSpan),
    pending: &mut Vec<DraftPart>,
) {
    pending.push(DraftPart {
        draft: draft.clone(),
        span: Some(right),
    });
    pending.push(DraftPart {
        draft,
        span: Some(left),
    });
}

fn split(mut draft: StewardshipDraftRequest, pending: &mut Vec<DraftPart>) {
    let mut older = draft.clone();
    older.request.evidence = draft
        .request
        .evidence
        .split_off(draft.request.evidence.len() / 2);
    pending.push(DraftPart {
        draft: older,
        span: None,
    });
    pending.push(DraftPart { draft, span: None });
}

fn moved(vault: &Vault, draft: &StewardshipDraftRequest) -> oneiron::Result<Option<DraftPass>> {
    Ok(match vault.stewardship_draft_request(draft.proposal)? {
        None => Some(DraftPass::Gone),
        Some(current) if current != *draft => Some(DraftPass::Moved(current)),
        Some(_) => None,
    })
}

fn failed(
    vault: &Vault,
    draft: &StewardshipDraftRequest,
    failure: DraftFailure,
) -> oneiron::Result<DraftPass> {
    Ok(moved(vault, draft)?.unwrap_or_else(|| DraftPass::Failed(failure, draft.clone())))
}

/// Planning must cite the exact inputs of every completed part or synthesis.
struct FoldedDraft {
    expected: Vec<RepresentationContext>,
    coverage: Vec<EvidenceSpan>,
    inner: PrematerializedDraft,
}

impl RepresentationPlanner for FoldedDraft {
    fn plan(&mut self, context: &RepresentationContext) -> oneiron::Result<RepresentationDraft> {
        if !self.expected.iter().all(|expected| {
            contains_sources(context, expected)
                && expected
                    .evidence
                    .iter()
                    .all(|source| covers(source, &self.coverage))
        }) {
            return Err(Error::InvalidClaimBody("stewardship fold sources changed"));
        }
        self.inner.plan(context)
    }
}
