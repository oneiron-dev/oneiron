//! Verification of retained slide judgment rows.
//! Entry: `verify_judgments`.
//! Review record types remain in the parent module.

use super::*;

/// The encoder, preview and settlement share the same row validity; every
/// row a review writes is kept, whatever their number (FIX 9819).
/// Uniqueness is checked independently of PPTX replay so discard cannot
/// persist a row the selected writer (or the ledger decoder) would reject.
pub(crate) fn validate_judgment_rows(rows: &[SlideJudgment]) -> Result<()> {
    let mut threads = HashSet::new();
    let mut units = HashSet::new();
    for row in rows {
        let shape = row
            .target
            .shape_creation_id
            .as_deref()
            .map(|id| {
                uuid::Uuid::parse_str(id)
                    .map_err(|_| invalid("invalid slide judgment shape identity"))
            })
            .transpose()?;
        if !threads.insert(row.thread_id) || !units.insert((row.target.slide, shape)) {
            return Err(invalid("duplicate slide judgment thread or unit"));
        }
    }
    Ok(())
}

/// Validate the receipt against the actual comment ops at the settle door.
/// A public manifest is not a source of authority to invent judgment receipts.
pub(crate) fn verify_judgments(proposal: &EditProposal) -> Result<()> {
    verify_rows(proposal, false)
}

/// [`verify_judgments`] for answers the engine carried onto a newer head at
/// Keep: each still names the deck revision it was judged against, which may
/// be older than the proposal's base.
pub(crate) fn verify_carried_judgments(proposal: &EditProposal) -> Result<()> {
    verify_rows(proposal, true)
}

pub(super) fn verify_rows(proposal: &EditProposal, carried: bool) -> Result<()> {
    let rows = &proposal.manifest.slide_judgments;
    validate_judgment_rows(rows)?;
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
        let PptxCommentAction::Add { target, text } = &patch.action else {
            return Err(invalid("review receipt requires a new comment"));
        };
        let decision = &row.decision;
        let receipt = &decision.receipt;
        let probability = decision
            .probability
            .ok_or_else(|| invalid("missing review probability"))?;
        if decision.answer == DecisionAnswer::Abstain || decision.human_ask.is_some() {
            return Err(invalid("abstentions cannot create comments"));
        }
        if row.thread_id != patch.thread_id
            || row.thread_id != patch.comment_id
            || row.target != *target
            || row.comment != *text
            || receipt.principal != patch.asked_by
            || !probability.is_finite()
            || !(0.0..=1.0).contains(&probability)
            || receipt.band.validate().is_err()
            || row.labels.validate().is_err()
            || row.answer_contract.validate().is_err()
            || !row.answer_contract.accepts(&decision.answer)
            || row.comment
                != row
                    .labels
                    .comment(&decision.answer, probability, receipt.band)
            || (row.band_mode == BandMode::Enforce && receipt.band_version == 0)
            || !ladder_route(row, probability)
            || !PairedReading::readings_valid(
                &receipt.paired,
                &receipt.person,
                receipt.question,
                &receipt.providers,
            )
            || receipt.question_version == 0
            || receipt.evidence_versions.iter().any(|version| {
                version.body_hash != row.frontier
                    && !row.media.iter().any(|entry| {
                        entry.served == MediaServed::Full && entry.reference.evidence() == version
                    })
            })
            || row
                .media
                .iter()
                .any(|entry| medium_hash(&entry.reference) != row.render_hash)
            || row.location.as_ref().is_some_and(|location| {
                !location.within()
                    || SlideLocation::of(
                        &decision.answer,
                        (location.slide_width, location.slide_height),
                    )
                    .as_ref()
                        != Some(location)
            })
            || row.presence.as_ref().is_some_and(|presence| {
                presence.answer != DecisionAnswer::Noul(true)
                    || !pins_climb(&presence.receipt.providers)
                    || presence.in_band
                    || presence.human_ask.is_some()
                    || presence.receipt.principal != receipt.principal
                    || !row.answer_contract.locates()
            })
            || row.anchor.slide_part.is_empty()
            || row.anchor.shape.is_some() != target.shape_creation_id.is_some()
            || (!carried
                && (row.frontier != proposal.base_content_hash
                    || row.judged_version != proposal.base_version))
            || row.renderer.trim().is_empty()
            || row.renderer.len() > 256
        {
            return Err(invalid("review receipt/comment mismatch"));
        }
    }
    Ok(())
}

/// Whether the receipt is one the shared ladder writes for an answered unit
/// below the person, on the decision clock (FIX 9821). Each completed read
/// is pinned, rung over rung, and the last answered: rungs that abstained
/// before it passed the question on. Then the first answer stands (clear,
/// or taken at the cut outside its band), or a stronger rung read it again
/// for its cause, past any rung that abstained on the way. Which earlier
/// pin abstained is not on the receipt, so none is assumed.
pub(super) fn ladder_route(row: &SlideJudgment, probability: f64) -> bool {
    let decision = &row.decision;
    let receipt = &decision.receipt;
    let Some(time) = receipt.time else {
        return false;
    };
    let enforced_margin = decision.in_band && row.band_mode == BandMode::Enforce;
    let Some((last, earlier)) = receipt.providers.split_last() else {
        return false;
    };
    if !pins_climb(&receipt.providers) || time.answered != Some(last.rung) {
        return false;
    }
    match time.reasoning {
        Reasoning::NotNeeded => {
            time.stop == StopCause::Done
                && decision.in_band == receipt.band.contains(probability)
                && !enforced_margin
        }
        Reasoning::Skipped(_) | Reasoning::Cut(_) => {
            time.stop == StopCause::Deadline
                && !decision.in_band
                && !receipt.band.contains(probability)
        }
        Reasoning::Ran(cause) => {
            !earlier.is_empty()
                && time.stop == StopCause::Done
                && match cause {
                    ReasoningCause::SmallMargin => enforced_margin,
                    // The reading that asked for the step is an earlier read's.
                    ReasoningCause::PairedHigh => {
                        !enforced_margin
                            && receipt
                                .paired
                                .iter()
                                .any(|reading| earlier.contains(&reading.provider))
                    }
                    ReasoningCause::SecondMeasurement => false,
                }
        }
    }
}

/// Whether `pins` are a ladder's completed reads: each a named provider
/// below the person, each rung above the one before it.
pub(super) fn pins_climb(pins: &[crate::llm::decision::ProviderPin]) -> bool {
    pins.iter().all(|pin| {
        !pin.model.trim().is_empty()
            && !pin.version.trim().is_empty()
            && pin.rung != DecisionRung::Human
    }) && pins.windows(2).all(|pair| pair[1].rung > pair[0].rung)
}
