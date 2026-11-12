//! Campaign copy review (ARCH-0059 #copy-review): the campaign's reviewer
//! checks each body version a step sends against the campaign's voice guide
//! before the send.
//!
//! The judge is a model call, so it runs on the host before the leg's drive
//! ([`Vault::review_enrollment_copy`]) and stores one verdict per body
//! version. The Gate's copy-review stage ([`campaign_copy_review_gate`]) only
//! reads that verdict on its own transaction: a governed campaign's send whose
//! copy failed, or has no passing verdict yet, is held for the owner's
//! approve-once press, as a compliance hold is. A campaign pinned to human
//! review holds every send for that press.
//!
//! Only a campaign that names a voice guide or pins human review is governed;
//! every other campaign sends as before.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{CampaignProgramOutbound, CampaignProgramStep};
use crate::attempt_queue::AttemptRecord;
use crate::campaign::surface::{
    CampaignDefinition, CopyReviewMode, load_registered_campaign_in_txn,
};
use crate::error::{Error, Result};
use crate::gate::{ApprovalTarget, ExternalEffectGateInput};
use crate::llm::decision::DecisionLadder;
use crate::model_decision::catalogue::CAMPAIGN_COPY_REVIEW;
use crate::model_decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionRung,
    ProviderPin, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

/// The reason classes a copy review answers with. The first is the passing
/// class; each other names what a failing body breaks in the voice guide.
pub const COPY_REVIEW_REASONS: [&str; 6] = [
    "on_voice",
    "tone",
    "vocabulary",
    "claims",
    "length",
    "other",
];

/// The dial a copy review runs under unless the host picks another. It ends
/// below Human: the owner's review of a held send is the approve-once press,
/// never a queued person ask.
pub const CAMPAIGN_COPY_REVIEW_DIAL: DecisionDial = DecisionDial {
    first: DecisionRung::Local,
    ceiling: DecisionRung::Big,
    band: DecisionBand {
        low: 0.35,
        high: 0.65,
    },
};

/// The host's wording of the two copy-review questions.
pub struct CampaignCopyReviewWording {
    /// The yes-or-no question: does the body follow the voice guide?
    pub follows_voice: String,
    /// The reason-class question, answered from [`COPY_REVIEW_REASONS`].
    pub reason: String,
}

/// The shared decision path a campaign's copy review goes through: the
/// host's ladder, the dial and learned bands, the wording, and each review's
/// anytime budget. The answers are for the campaign's owner. A provider sees
/// only the voice guide's text, the subject and the body.
pub struct CampaignCopyReviewDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: CampaignCopyReviewWording,
    /// Each review's one clock, from when it is asked.
    pub budget: Duration,
}

/// One body version's stored review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyReviewVerdict {
    /// Whether the body follows the voice guide.
    pub passed: bool,
    /// The judge's P(the body follows the guide), when it gave one.
    pub probability: Option<f64>,
    /// The judge's reason class, one of [`COPY_REVIEW_REASONS`].
    pub reason: String,
    /// The voice guide NOTE the body was checked against.
    pub voice_guide_ref: EntityId,
    /// Digest of that guide's text when it was checked: an edited guide
    /// asks again.
    pub voice_guide_digest: [u8; 32],
    /// The providers that answered whether the body follows the guide.
    pub judge: Vec<ProviderPin>,
    /// When the review was stored, engine seconds.
    pub reviewed_at: u64,
}

/// What [`Vault::review_enrollment_copy`] did for one attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum CopyReviewOutcome {
    /// Copy review does not govern this send: not a campaign leg with an
    /// outward call, or the campaign names no voice guide and pins no human
    /// review.
    NotGoverned,
    /// The campaign pins human review: no judge runs, and the send holds
    /// for the owner's press.
    HumanReview,
    /// A stored verdict already covers this body under the current guide.
    Cached(CopyReviewVerdict),
    /// The judge reviewed the body now, and its verdict is stored.
    Reviewed(CopyReviewVerdict),
    /// The judge gave no answer; nothing is stored and the send holds.
    Abstained,
}

/// Why the Gate holds a governed campaign's send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyReviewHold {
    /// The stored verdict says the body does not follow the voice guide.
    Failed,
    /// No passing verdict covers the body: none was stored (no judge seat,
    /// or the judge abstained), the guide changed since, or the campaign
    /// pins human review.
    Missing,
}

impl CopyReviewHold {
    /// The receipt reason the Gate records beside the hold.
    pub(crate) const fn receipt_reason(self) -> &'static str {
        match self {
            Self::Failed => "copy_review_failed",
            Self::Missing => "copy_review_missing",
        }
    }
}

/// The verdict key: the campaign, then the body digest the retained request
/// already pins (the frozen payload with its email subject framed).
type VerdictKey = (EntityId, [u8; 32]);

/// (campaign, body digest) → that body version's review.
const VERDICTS: SideTable<VerdictKey, CopyReviewVerdict, Named> =
    SideTable::new(&side_table::CAMPAIGN_COPY_REVIEW_VERDICT);

impl Vault {
    /// Reviews the body the claimed enrollment `attempt` would send, once
    /// per body version, before the host drives its outward leg. A verdict
    /// stored for this body under the campaign's current voice guide is
    /// reused; otherwise the judge is asked and its verdict stored. The
    /// Gate's copy-review stage reads that verdict when the leg runs.
    ///
    /// # Errors
    ///
    /// Storage and decode errors, a voice guide whose text does not read,
    /// and a judge that fails. The send then holds: no verdict covers it.
    pub fn review_enrollment_copy(
        &self,
        attempt: &AttemptRecord,
        decisions: &CampaignCopyReviewDecisions<'_>,
    ) -> Result<CopyReviewOutcome> {
        if attempt.kind != super::CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND {
            return Ok(CopyReviewOutcome::NotGoverned);
        }
        let payload = super::decode_enrollment_attempt_payload(&attempt.payload)?;
        let event = super::campaign_enrollment_event(self, payload.membership_event_ref)?
            .ok_or(Error::EntityNotFound)?;
        let step = super::runner::resolve_program_step(self, &payload, &event)?;
        let Some(outbound) = step.outbound.as_ref() else {
            return Ok(CopyReviewOutcome::NotGoverned);
        };
        let Some(record) =
            crate::campaign::surface::load_registered_campaign(self, event.campaign_ref)?
        else {
            return Ok(CopyReviewOutcome::NotGoverned);
        };
        let definition = &record.definition;
        if !definition.copy_review_governs() {
            return Ok(CopyReviewOutcome::NotGoverned);
        }
        let Some(guide) = definition.voice_guide_ref else {
            return Ok(CopyReviewOutcome::HumanReview);
        };
        if definition.copy_review == CopyReviewMode::Human {
            return Ok(CopyReviewOutcome::HumanReview);
        }
        let guide_text = self.note_text(guide)?;
        let guide_digest = *blake3::hash(guide_text.as_bytes()).as_bytes();
        let key = (
            event.campaign_ref,
            super::approval::outbound_payload_digest(outbound),
        );
        let stored = {
            let txn = self.store.env.read_txn()?;
            VERDICTS.get(&self.store, &txn, &key)?
        };
        if let Some(verdict) = stored
            && verdict.voice_guide_ref == guide
            && verdict.voice_guide_digest == guide_digest
        {
            return Ok(CopyReviewOutcome::Cached(verdict));
        }
        let Some(verdict) = judge_copy(
            decisions,
            definition,
            guide,
            &guide_text,
            guide_digest,
            outbound,
            self.store.clock.now_recorded_at(),
        )?
        else {
            return Ok(CopyReviewOutcome::Abstained);
        };
        self.with_write_txn_grouped(|wtxn| VERDICTS.put(self, wtxn, &key, &verdict))?;
        Ok(CopyReviewOutcome::Reviewed(verdict))
    }

    /// The stored review of the body `step` sends for `campaign_ref`, if any.
    ///
    /// # Errors
    ///
    /// Storage and decode errors.
    pub fn campaign_copy_review_verdict(
        &self,
        campaign_ref: EntityId,
        step: &CampaignProgramStep,
    ) -> Result<Option<CopyReviewVerdict>> {
        let Some(outbound) = step.outbound.as_ref() else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        VERDICTS.get(
            &self.store,
            &txn,
            &(
                campaign_ref,
                super::approval::outbound_payload_digest(outbound),
            ),
        )
    }
}

/// Asks the judge whether `outbound`'s body follows the voice guide, and why,
/// as one pack. `None` when the judge abstains on the first question.
fn judge_copy(
    decisions: &CampaignCopyReviewDecisions<'_>,
    definition: &CampaignDefinition,
    guide: EntityId,
    guide_text: &str,
    guide_digest: [u8; 32],
    outbound: &CampaignProgramOutbound,
    reviewed_at: u64,
) -> Result<Option<CopyReviewVerdict>> {
    let follows_question = CAMPAIGN_COPY_REVIEW.question(
        &[b"follows_voice"],
        decisions.wording.follows_voice.clone(),
        AnswerContract::Noul,
    )?;
    let reason_question = CAMPAIGN_COPY_REVIEW.question(
        &[b"reason"],
        decisions.wording.reason.clone(),
        AnswerContract::Choice {
            options: COPY_REVIEW_REASONS
                .iter()
                .copied()
                .map(String::from)
                .collect(),
        },
    )?;
    let state = serde_json::json!({
        "voice_guide": guide_text,
        "subject": outbound.subject,
        "body": String::from_utf8_lossy(&outbound.payload),
    });
    let answers = decisions.ladder.run_pack(
        &[&follows_question, &reason_question],
        definition.owner_actor,
        &[],
        &state,
        decisions.dial,
        &decisions.bands,
        Reversibility::ReversibleRead,
        &RetrievalDeadline::hard(Instant::now(), decisions.budget),
    )?;
    let Some(follows) = answers.first() else {
        return Ok(None);
    };
    let DecisionAnswer::Noul(passed) = follows.answer else {
        return Ok(None);
    };
    let reason = match answers.get(1).map(|answer| &answer.answer) {
        Some(DecisionAnswer::Choice(class)) if COPY_REVIEW_REASONS.contains(&class.as_str()) => {
            class.clone()
        }
        _ if passed => COPY_REVIEW_REASONS[0].to_owned(),
        _ => "other".to_owned(),
    };
    Ok(Some(CopyReviewVerdict {
        passed,
        probability: follows.probability,
        reason,
        voice_guide_ref: guide,
        voice_guide_digest: guide_digest,
        judge: follows.receipt.providers.clone(),
        reviewed_at,
    }))
}

/// The Gate's copy-review stage (ARCH-0059 #copy-review), a pure read on
/// the Gate's own transaction. It governs a campaign leg only (an effect
/// whose approve-once target is a campaign leg): an agent-direct send has no
/// campaign body to review. `None` when the stage does not hold the send.
pub(crate) fn campaign_copy_review_gate(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<Option<CopyReviewHold>> {
    let Some(ApprovalTarget::Campaign(facts)) = effect.provenance.approval_target.as_ref() else {
        return Ok(None);
    };
    let Some(record) = load_registered_campaign_in_txn(store, txn, facts.campaign_ref)? else {
        return Ok(None);
    };
    let definition = &record.definition;
    if !definition.copy_review_governs() {
        return Ok(None);
    }
    let Some(guide) = definition.voice_guide_ref else {
        return Ok(Some(CopyReviewHold::Missing));
    };
    if definition.copy_review == CopyReviewMode::Human {
        return Ok(Some(CopyReviewHold::Missing));
    }
    let Some(step) = super::program::campaign_program_step_in_store_txn(
        store,
        txn,
        facts.program_ref,
        facts.step_ref,
    )?
    else {
        return Ok(Some(CopyReviewHold::Missing));
    };
    let Some(outbound) = step.outbound.as_ref() else {
        return Ok(None);
    };
    let key = (
        facts.campaign_ref,
        super::approval::outbound_payload_digest(outbound),
    );
    Ok(match VERDICTS.get(store, txn, &key)? {
        Some(verdict) if verdict.voice_guide_ref == guide && verdict.passed => None,
        Some(verdict) if verdict.voice_guide_ref == guide => Some(CopyReviewHold::Failed),
        _ => Some(CopyReviewHold::Missing),
    })
}

/// The copy review a held campaign send's owner ask states: the campaign's
/// review mode and, when a verdict covers the body, its reason class.
/// `None` when copy review does not govern the campaign.
pub(super) fn copy_review_ask_state_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    campaign_ref: EntityId,
    program_ref: EntityId,
    step_ref: EntityId,
) -> Result<Option<serde_json::Value>> {
    let Some(record) = load_registered_campaign_in_txn(store, txn, campaign_ref)? else {
        return Ok(None);
    };
    if !record.definition.copy_review_governs() {
        return Ok(None);
    }
    let verdict = match super::program::campaign_program_step_in_store_txn(
        store,
        txn,
        program_ref,
        step_ref,
    )?
    .and_then(|step| step.outbound)
    {
        Some(outbound) => VERDICTS.get(
            store,
            txn,
            &(
                campaign_ref,
                super::approval::outbound_payload_digest(&outbound),
            ),
        )?,
        None => None,
    };
    Ok(Some(serde_json::json!({
        "mode": record.definition.copy_review.as_str(),
        "passed": verdict.as_ref().map(|verdict| verdict.passed),
        "reason": verdict.map(|verdict| verdict.reason),
    })))
}
