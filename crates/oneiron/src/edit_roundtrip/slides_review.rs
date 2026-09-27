//! Bounded typed review of slide/shape units into one retained comment proposal.
//!
//! The host supplies access-checked text and rendered image evidence for the
//! exact deck bytes. No provider output may select the principal, receipt,
//! comment anchor, or settle authority. The existing PPTX writer owns OOXML.

use super::EditProposal;
use super::pptx::{
    PptxAuthor, PptxCommentAction, PptxCommentPatch, PptxCommentTarget, PptxError,
    PptxProposalError, inspect_pptx, run_comment_roundtrip,
};
use crate::EntityId;
use crate::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionDial, DecisionQuestion, DecisionReceipt, DecisionRung,
    ProviderDecision, ProviderPin, TypedDecision,
};
use crate::{Error, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const BATCH_SIZE: usize = 8;
const MAX_UNITS: usize = 4096;
const MAX_TEXT: usize = 1_048_576;
const MAX_IMAGE: usize = 16 * 1024 * 1024;

/// One caller-approved unit and its inspected text and rendered image. The
/// renderer must have rendered these exact `base` bytes; its identity is saved
/// beside the deck frontier, not treated as PowerPoint oracle evidence.
#[derive(Debug, Clone)]
pub struct SlideReviewUnit {
    pub target: PptxCommentTarget,
    pub text: String,
    pub review_image: Vec<u8>,
    pub renderer: String,
}

/// Host-injected provider seat. Calls are bounded batches of at most eight;
/// results are positional and malformed batches fail the entire preview.
/// Each provider must use the access/egress posture chosen by the host.
pub trait SlideReviewProvider {
    fn pin(&self) -> ProviderPin;
    fn decide_batch(
        &self,
        question: &DecisionQuestion,
        units: &[SlideReviewUnit],
    ) -> Result<Vec<ProviderDecision>>;
}

/// User-configured display words, including the severity words in comments.
/// No question, glossary, prompt or user-facing label is compiled into Rust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlideReviewLabels {
    pub yes: String,
    pub no: String,
    pub low: String,
    pub middle: String,
    pub high: String,
}

impl SlideReviewLabels {
    fn validate(&self) -> Result<()> {
        if [&self.yes, &self.no, &self.low, &self.middle, &self.high]
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > 128)
        {
            return Err(invalid("invalid slide review labels"));
        }
        Ok(())
    }
    fn comment(&self, answer: &DecisionAnswer, probability: f64, band: DecisionBand) -> String {
        let severity = if probability < band.low {
            &self.low
        } else if probability > band.high {
            &self.high
        } else {
            &self.middle
        };
        let text = match answer {
            DecisionAnswer::Noul(true) => self.yes.clone(),
            DecisionAnswer::Noul(false) => self.no.clone(),
            DecisionAnswer::Choice(value) => value.clone(),
            DecisionAnswer::Score(value) => value.to_string(),
            DecisionAnswer::Abstain => unreachable!("abstentions never create comments"),
        };
        format!("{severity}: {text}")
    }
}

/// Bound to its exported comment and exact source version. Settlement keeps
/// this record with the consume-once receipt, not just a client-side preview.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlideJudgment {
    pub thread_id: EntityId,
    pub target: PptxCommentTarget,
    pub decision: TypedDecision,
    pub renderer: String,
    pub frontier: [u8; 32],
    /// Hash of the exact text and image passed to the selected answerer.
    pub evidence_hash: [u8; 32],
    pub judged_version: Option<u64>,
    pub comment: String,
    /// Runtime display words pinned so settle can recheck comment semantics.
    pub labels: SlideReviewLabels,
}

#[derive(Debug, Clone)]
pub struct SlideReviewRun {
    /// `None` when every unit abstained; no empty or phantom write is settled.
    pub proposal: Option<EditProposal>,
    pub abstained: Vec<PptxCommentTarget>,
}

/// One typed ask, whose principal and display configuration are fixed by the
/// caller, never by a provider result. The host supplies its eligible rungs.
pub struct SlideReviewRequest<'a> {
    pub units: &'a [SlideReviewUnit],
    pub question: &'a DecisionQuestion,
    pub principal: EntityId,
    pub answered_by: EntityId,
    pub author: &'a PptxAuthor,
    pub dial: DecisionDial,
    pub labels: &'a SlideReviewLabels,
    pub providers: &'a [&'a dyn SlideReviewProvider],
    pub run_ref: &'a str,
    pub at: u64,
}

/// One question over selected slide/shape units, via adjacent provider rungs.
/// A band answer or abstention moves at most one rung; missing rungs fail
/// closed. Errors and malformed output leave no partial proposal behind.
pub fn review_slides(
    base: &[u8],
    base_version: Option<u64>,
    request: &SlideReviewRequest<'_>,
) -> std::result::Result<SlideReviewRun, SlideReviewError> {
    let SlideReviewRequest {
        units,
        question,
        principal,
        answered_by,
        author,
        dial,
        labels,
        providers,
        run_ref,
        at,
    } = *request;
    question.validate()?;
    dial.band.validate()?;
    labels.validate()?;
    if dial.first > dial.ceiling
        || dial.ceiling == DecisionRung::Human
        || units.len() > MAX_UNITS
        || providers.is_empty()
    {
        return Err(invalid("invalid slide review selection or dial").into());
    }
    for (index, provider) in providers.iter().enumerate() {
        let pin = provider.pin();
        if pin.rung
            != rung_from(dial.first, index).ok_or_else(|| invalid("invalid provider sequence"))?
            || pin.rung > dial.ceiling
            || pin.rung == DecisionRung::Human
            || pin.model.trim().is_empty()
            || pin.version.trim().is_empty()
            || pin.model.len() > 256
            || pin.version.len() > 256
        {
            return Err(invalid("invalid provider sequence").into());
        }
    }
    if providers.last().map(|p| p.pin().rung) != Some(dial.ceiling) {
        return Err(invalid("missing review provider rung").into());
    }
    let inspection = inspect_pptx(base)?;
    if !inspection.signature_parts.is_empty() {
        return Err(PptxError::SignedPackage.into());
    }
    let mut seen = HashSet::new();
    for unit in units {
        if unit.target.slide == 0
            || !inspection.slides.iter().any(|slide| {
                slide.slide == unit.target.slide
                    && unit
                        .target
                        .slide_creation_id
                        .is_none_or(|id| slide.creation_id == Some(id))
            })
            || !seen.insert((unit.target.slide, unit.target.shape_creation_id.clone()))
            || unit.text.is_empty()
            || unit.text.len() > MAX_TEXT
            || unit.review_image.is_empty()
            || unit.review_image.len() > MAX_IMAGE
            || unit.renderer.trim().is_empty()
            || unit.renderer.len() > 256
        {
            return Err(invalid("invalid slide review unit or missing evidence").into());
        }
    }
    let frontier = *blake3::hash(base).as_bytes();
    let mut judgments = Vec::new();
    let mut patches = Vec::new();
    let mut abstained = Vec::new();
    for chunk in units.chunks(BATCH_SIZE) {
        let mut pending: Vec<usize> = (0..chunk.len()).collect();
        let mut pins: Vec<Vec<ProviderPin>> = vec![Vec::new(); chunk.len()];
        for (rung, provider) in providers.iter().enumerate() {
            if pending.is_empty() {
                break;
            }
            let selected: Vec<_> = pending.iter().map(|&i| chunk[i].clone()).collect();
            let results = provider.decide_batch(question, &selected)?;
            if results.len() != selected.len() {
                return Err(invalid("malformed review batch length").into());
            }
            let mut next = Vec::new();
            for (index, result) in pending.iter().copied().zip(results) {
                if !question.contract.accepts(&result.answer)
                    || match result.answer {
                        DecisionAnswer::Abstain => result.probability.is_some(),
                        _ => !result
                            .probability
                            .is_some_and(|p| p.is_finite() && (0.0..=1.0).contains(&p)),
                    }
                {
                    return Err(invalid("malformed review answer").into());
                }
                pins[index].push(provider.pin());
                let in_band = result.probability.is_some_and(|p| dial.band.contains(p));
                if (result.answer == DecisionAnswer::Abstain || in_band)
                    && rung + 1 < providers.len()
                {
                    next.push(index);
                    continue;
                }
                if result.answer == DecisionAnswer::Abstain {
                    abstained.push(chunk[index].target.clone());
                    continue;
                }
                let probability = result
                    .probability
                    .ok_or_else(|| invalid("missing review probability"))?;
                let unit = &chunk[index];
                let thread_id = EntityId::now();
                let decision = TypedDecision {
                    answer: result.answer,
                    probability: Some(probability),
                    evidence: Vec::new(),
                    in_band,
                    receipt: DecisionReceipt {
                        question: question.id,
                        question_version: question.version,
                        principal,
                        providers: pins[index].clone(),
                        band: dial.band,
                        band_version: 0,
                        evidence_versions: Vec::new(),
                        cost_per_thousand: None,
                    },
                    human_ask: None,
                };
                let comment = labels.comment(&decision.answer, probability, dial.band);
                patches.push(PptxCommentPatch {
                    asked_by: principal,
                    answered_by,
                    author: author.clone(),
                    thread_id,
                    comment_id: thread_id,
                    at,
                    action: PptxCommentAction::Add {
                        target: unit.target.clone(),
                        text: comment.clone(),
                    },
                });
                judgments.push(SlideJudgment {
                    thread_id,
                    target: unit.target.clone(),
                    decision,
                    renderer: unit.renderer.clone(),
                    frontier,
                    evidence_hash: evidence_hash(unit),
                    judged_version: base_version,
                    comment,
                    labels: labels.clone(),
                });
            }
            pending = next;
        }
    }
    if patches.is_empty() {
        return Ok(SlideReviewRun {
            proposal: None,
            abstained,
        });
    }
    let mut proposal = run_comment_roundtrip(base, &patches, run_ref)?;
    proposal.base_version = base_version;
    proposal.manifest.slide_judgments = judgments;
    Ok(SlideReviewRun {
        proposal: Some(proposal),
        abstained,
    })
}

fn evidence_hash(unit: &SlideReviewUnit) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for field in [
        unit.text.as_bytes(),
        &unit.review_image,
        unit.renderer.as_bytes(),
    ] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

fn rung_from(first: DecisionRung, steps: usize) -> Option<DecisionRung> {
    let rungs = [
        DecisionRung::Rule,
        DecisionRung::Local,
        DecisionRung::SystemOne,
        DecisionRung::Big,
    ];
    rungs
        .iter()
        .position(|r| *r == first)
        .and_then(|i| rungs.get(i + steps).copied())
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}

/// Validate the receipt against the actual comment ops at the settle door.
/// A public manifest is not a source of authority to invent judgment receipts.
pub(crate) fn verify_judgments(proposal: &EditProposal) -> Result<()> {
    let rows = &proposal.manifest.slide_judgments;
    if rows.is_empty() {
        return Ok(());
    }
    let patches: Vec<_> = proposal
        .manifest
        .ops
        .iter()
        .filter_map(|op| {
            if let super::EditOp::PptxComment { patch } = op {
                Some(patch)
            } else {
                None
            }
        })
        .collect();
    if proposal.format != super::OfficeFormat::Pptx || rows.len() != patches.len() {
        return Err(invalid("review receipt/comment mismatch"));
    }
    for (row, patch) in rows.iter().zip(patches) {
        let super::pptx::PptxCommentAction::Add { target, text } = &patch.action else {
            return Err(invalid("review receipt requires a new comment"));
        };
        let decision = &row.decision;
        let probability = decision
            .probability
            .ok_or_else(|| invalid("missing review probability"))?;
        if decision.answer == DecisionAnswer::Abstain {
            return Err(invalid("abstentions cannot create comments"));
        }
        if row.thread_id != patch.thread_id
            || row.thread_id != patch.comment_id
            || row.target != *target
            || row.comment != *text
            || decision.receipt.principal != patch.asked_by
            || !probability.is_finite()
            || !(0.0..=1.0).contains(&probability)
            || decision.receipt.band.validate().is_err()
            || row.labels.validate().is_err()
            || row.comment
                != row
                    .labels
                    .comment(&decision.answer, probability, decision.receipt.band)
            || decision.in_band != decision.receipt.band.contains(probability)
            || decision.receipt.question_version == 0
            || decision.receipt.providers.is_empty()
            || row.frontier != proposal.base_content_hash
            || row.judged_version != proposal.base_version
            || row.renderer.trim().is_empty()
            || row.renderer.len() > 256
        {
            return Err(invalid("review receipt/comment mismatch"));
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SlideReviewError {
    #[error(transparent)]
    Vault(#[from] Error),
    #[error(transparent)]
    Pptx(#[from] PptxError),
    #[error(transparent)]
    Proposal(#[from] PptxProposalError),
}

impl Vault {
    /// Review one artifact head. Keep/discard through the existing consume-once
    /// edit-settle door; a changed head is retained as a stale preview.
    pub fn review_blob_artifact_slides(
        &self,
        artifact: &EntityId,
        request: &SlideReviewRequest<'_>,
    ) -> std::result::Result<SlideReviewRun, SlideReviewError> {
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact)?
            .ok_or(Error::EntityNotFound)?;
        if super::OfficeFormat::from_media_type(&body.media_type)? != super::OfficeFormat::Pptx {
            return Err(PptxError::InvalidPatch.into());
        }
        let bytes = self
            .read_blob_artifact_version(artifact, head.version)?
            .ok_or(Error::EntityNotFound)?;
        review_slides(&bytes, Some(head.version), request)
    }
}

#[cfg(test)]
mod tests;
