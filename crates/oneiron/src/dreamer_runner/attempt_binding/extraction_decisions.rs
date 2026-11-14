//! Request rules and facet dispatch for a checked extraction verdict pack.
//!
//! The engine checks every contract before borrowing the attempt's native read
//! resources. A host without an extraction loan still refuses the checked pack.

use super::{BoundFacet, DreamerAttemptBinding, facet_refused};
use crate::llm::decision::{AnswerContract, DecisionRung};
use crate::memory::{MemoryError, MemoryResult};
use crate::model_decision::MAX_DECISION_STATE_BYTES;
use crate::verbs::{
    AiVerdict, AiVerdictRequest, AiVerdictReversibility, ExtractionPack, ExtractionPart,
    ExtractionRead,
};

impl DreamerAttemptBinding {
    /// Dispatches a verdict only to the handler owned by its admitted facet.
    pub(super) fn verdict(&self, input: AiVerdictRequest) -> MemoryResult<AiVerdict> {
        match self.facet {
            BoundFacet::ConflictSettle => self.settlement_verdict(input),
            BoundFacet::Extraction => self.extraction_verdict(input),
            BoundFacet::Strength => Err(facet_refused(self.facet)),
        }
    }

    /// Checks one extraction pack before running its lent native read, when available.
    fn extraction_verdict(&self, input: AiVerdictRequest) -> MemoryResult<AiVerdict> {
        let pack: ExtractionPack =
            serde_json::from_value(input.state.clone().unwrap_or(serde_json::Value::Null))
                .map_err(|error| {
                    MemoryError::bad_request(format!("invalid extraction pack state: {error}"))
                })?;
        check_pack_bounds(&pack)?;
        check_extraction_request(&input, &pack)?;
        let checked = self.checked_extraction_pack(&pack)?;
        self.execute_extraction_pack(&input, &checked)
    }
}

/// Checks the existing verdict controls and the first question's wire contract.
fn check_extraction_request(input: &AiVerdictRequest, pack: &ExtractionPack) -> MemoryResult<()> {
    crate::request_limits::check_deadline_ms(input.deadline_ms)?;
    if input.routine
        || input.image.is_some()
        || input.misses != 0
        || input.until_ms.is_some()
        || !input.evidence.is_empty()
    {
        return Err(MemoryError::bad_request(
            "an extraction verdict takes only its pack evidence, no image, routine, misses or subgoal clock",
        ));
    }
    if input.ceiling == Some(DecisionRung::Human) {
        return Err(MemoryError::bad_request_with(
            "ai.verdict never queues an owner ask",
            &["Name a ceiling below human, or ask the owner through ask."],
        ));
    }
    if input.reversibility != AiVerdictReversibility::ReversibleRead {
        return Err(MemoryError::bad_request(
            "an extraction verdict requires reversible_read reversibility",
        ));
    }
    let wording = match pack.read {
        ExtractionRead::Correction | ExtractionRead::CorrectionFinal => "correction",
        ExtractionRead::Resolution | ExtractionRead::ResolutionFinal => "resolution",
        ExtractionRead::IdentityFinal => "identity",
    };
    if input.question != wording {
        return Err(MemoryError::bad_request(
            "the extraction wording key must match the pack's first question family",
        ));
    }
    let first = pack.questions.first().ok_or_else(|| {
        MemoryError::bad_request("an extraction pack needs at least one question")
    })?;
    match &input.contract {
        AnswerContract::Choice { options } if options == &first.options => Ok(()),
        _ => Err(MemoryError::bad_request(
            "the extraction Choice contract must equal question 0 options in order",
        )),
    }
}

/// Bounds each unbounded native row collection by the native decision state bound.
fn check_pack_bounds(pack: &ExtractionPack) -> MemoryResult<()> {
    let lengths = [
        pack.candidates.len(),
        pack.listed.len(),
        pack.priors.len(),
        pack.questions.len(),
        pack.earlier.len(),
    ];
    if lengths
        .iter()
        .any(|length| *length > MAX_DECISION_STATE_BYTES)
        || pack
            .candidates
            .iter()
            .any(|candidate| candidate.evidence.len() > MAX_DECISION_STATE_BYTES)
    {
        return Err(MemoryError::bad_request(
            "an extraction pack collection exceeds the native decision state bound",
        ));
    }
    if let ExtractionPart::Page { page, pages } = pack.part
        && (pages == 0 || page >= pages)
    {
        return Err(MemoryError::bad_request(
            "an extraction page needs pages >= 1 and a zero-based page below pages",
        ));
    }
    Ok(())
}
