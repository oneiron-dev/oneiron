//! Provider-failure-driven evidence splitting and pairwise draft synthesis.
use oneiron::dreamer_runner::maintenance::representation::{
    PrematerializedDraft, RepresentationContext, RepresentationDraft, RepresentationPlanner,
};
use oneiron::dreamer_runner::maintenance::stewardship::StewardshipDraftRequest;
use oneiron::{Error, Vault};

use super::{DraftFailure, DraftPass, DraftStage, GeneratedDraft, at, generate_draft, now};
use crate::ai_host::stewardship::Drafter;
use crate::ai_host::stewardship::sources::contains_sources;
use crate::models::ModelRuntime;

pub(super) async fn draft_fold(
    vault: &Vault,
    runtime: &ModelRuntime,
    drafter: Drafter,
    draft: &StewardshipDraftRequest,
) -> oneiron::Result<DraftPass> {
    let mut pending = Vec::new();
    split(draft.clone(), &mut pending);
    let mut answers = Vec::new();
    while let Some(part) = pending.pop() {
        if let Some(outcome) = moved(vault, draft)? {
            return Ok(outcome);
        }
        match generate_draft(vault, runtime, drafter, &part, &[]).await {
            Ok(answer) => answers.push(answer),
            Err(failure)
                if failure.stage == DraftStage::Call && part.request.evidence.len() > 1 =>
            {
                split(part, &mut pending);
            }
            Err(failure) => return failed(vault, draft, failure),
        }
    }
    while answers.len() > 1 {
        if let Some(outcome) = moved(vault, draft)? {
            return Ok(outcome);
        }
        let right = answers.pop().expect("two draft parts");
        let left = answers.pop().expect("two draft parts");
        let parts = [left, right];
        let mut joined = draft.clone();
        joined.request.evidence.clear();
        joined.request.voice.clear();
        for part in &parts {
            for source in &part.served.request.evidence {
                if !joined.request.evidence.contains(source) {
                    joined.request.evidence.push(*source);
                }
            }
            for source in &part.served.request.voice {
                if !joined.request.voice.contains(source) {
                    joined.request.voice.push(*source);
                }
            }
        }
        match generate_draft(vault, runtime, drafter, &joined, &parts).await {
            Ok(answer) => answers.push(answer),
            Err(failure) => return failed(vault, draft, failure),
        }
    }
    if let Some(outcome) = moved(vault, draft)? {
        return Ok(outcome);
    }
    let answer = answers.pop().expect("nonempty split evidence");
    let mut planner = FoldedDraft {
        expected: answer.snapshot.context,
        inner: PrematerializedDraft { text: answer.text },
    };
    match vault.schedule_stewardship_draft(&answer.served, &mut planner, now()) {
        Ok(outcome) => Ok(DraftPass::Done(outcome)),
        Err(error) => failed(vault, draft, at(DraftStage::Schedule)(error)),
    }
}

fn split(mut draft: StewardshipDraftRequest, pending: &mut Vec<StewardshipDraftRequest>) {
    let mut older = draft.clone();
    older.request.evidence = draft
        .request
        .evidence
        .split_off(draft.request.evidence.len() / 2);
    pending.push(older);
    pending.push(draft);
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

/// Planning must cite the input revision the synthesis actually received.
struct FoldedDraft {
    expected: RepresentationContext,
    inner: PrematerializedDraft,
}

impl RepresentationPlanner for FoldedDraft {
    fn plan(&mut self, context: &RepresentationContext) -> oneiron::Result<RepresentationDraft> {
        if !contains_sources(context, &self.expected) {
            return Err(Error::InvalidClaimBody("stewardship fold sources changed"));
        }
        self.inner.plan(context)
    }
}
