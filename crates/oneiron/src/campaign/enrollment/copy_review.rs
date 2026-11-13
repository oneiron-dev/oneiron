//! Campaign copy review (ARCH-0059 #copy-review): the campaign's reviewer
//! checks each body version a step sends against the campaign's voice guide
//! before the send.
//!
//! The judge is a model call, so it runs on the host before the leg's drive
//! ([`Vault::review_enrollment_copy`]) and stores one verdict per body
//! version. It reads the voice guide as the campaign's owner reads it, through
//! the scoped NOTE read, so a provider never sees a guide its owner cannot
//! read. The Gate's copy-review stage ([`campaign_copy_review_gate`]) only
//! reads that verdict on its own transaction, for the prepared send's own body
//! and the guide's live version: a governed campaign's send whose copy failed,
//! or has no passing verdict for that body at that version, is held for the
//! owner's approve-once press, as a compliance hold is. A campaign pinned to
//! human review holds every send for that press.
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
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::gate::{ApprovalTarget, ExternalEffectGateInput};
use crate::llm::decision::DecisionLadder;
use crate::model_decision::catalogue::CAMPAIGN_COPY_REVIEW;
use crate::model_decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionRung,
    ProviderPin, Reversibility,
};
use crate::note::{NoteReadRequest, NoteReadView, NoteVersion};
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
/// only the voice guide's text as the owner reads it, the subject and the
/// body.
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
    /// That guide's version when it was checked: the verdict covers a send
    /// only while the guide's live version is this one, so an edited guide
    /// asks again and holds the send until it does.
    pub voice_guide_version: NoteVersion,
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
    /// The campaign's owner cannot read the voice guide through the scoped
    /// NOTE read (its grants, the diary gate, an erased or missing NOTE): no
    /// judge is asked, nothing is stored, and the send holds.
    GuideUnreadable,
}

/// Why the Gate holds a governed campaign's send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyReviewHold {
    /// The stored verdict says the body does not follow the voice guide.
    Failed,
    /// No passing verdict covers the body: none was stored (no judge seat,
    /// the judge abstained, or the owner cannot read the guide), the guide
    /// changed or does not read since, or the campaign pins human review.
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
/// already pins (the frozen payload with its email subject framed). The Gate
/// reads it with the prepared send's own digest, never the live step's.
type VerdictKey = (EntityId, [u8; 32]);

/// The reason the copy review's scoped read of the voice guide states (a
/// diary entry's read receipt names it).
const VOICE_GUIDE_READ_REASON: &str = "campaign copy review against its voice guide";

/// (campaign, body digest) → that body version's review.
const VERDICTS: SideTable<VerdictKey, CopyReviewVerdict, Named> =
    SideTable::new(&side_table::CAMPAIGN_COPY_REVIEW_VERDICT);

impl Vault {
    /// Reviews the body the claimed enrollment `attempt` would send, once
    /// per body version, before the host drives its outward leg. The voice
    /// guide is read as the campaign's owner reads it (the scoped NOTE read:
    /// grants and the diary gate); a guide the owner cannot read asks no
    /// judge. A verdict stored for this body at the guide's current version
    /// is reused; otherwise the judge is asked and its verdict stored. The
    /// Gate's copy-review stage reads that verdict when the leg runs.
    ///
    /// # Errors
    ///
    /// Storage and decode errors, and a judge that fails. The send then
    /// holds: no verdict covers it.
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
        let Some(guide_view) = read_voice_guide(self, definition.owner_actor, guide)? else {
            return Ok(CopyReviewOutcome::GuideUnreadable);
        };
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
            && verdict.voice_guide_version == guide_view.version
        {
            return Ok(CopyReviewOutcome::Cached(verdict));
        }
        let Some(verdict) = judge_copy(
            decisions,
            definition,
            guide,
            guide_view,
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

/// The voice guide `guide` as the campaign's `owner` reads it: the scoped
/// NOTE read, with the NOTE's kind policy, the owner's current grants and the
/// diary gate a private or diary NOTE needs. `None` when that read does not
/// admit the guide, or refuses it.
fn read_voice_guide(
    vault: &Vault,
    owner: EntityId,
    guide: EntityId,
) -> Result<Option<NoteReadView>> {
    // The vault's owner reads as the owner Human; any other campaign owner
    // is an agent, and reads only what its grants cover. The snapshot closes
    // before the read opens its own.
    let class = {
        let txn = vault.store.env.read_txn()?;
        if crate::memory::actor_is_vault_owner_in_txn(vault, &txn, owner, EdgeActorClass::Human)
            .unwrap_or(false)
        {
            EdgeActorClass::Human
        } else {
            EdgeActorClass::Agent
        }
    };
    let read = vault.memory(owner, class).read_note(&NoteReadRequest {
        note_ref: guide.to_hex(),
        reason: Some(VOICE_GUIDE_READ_REASON.to_owned()),
        version: None,
        spans: Vec::new(),
    });
    // A refused read is a guide the owner cannot read: the send holds, and
    // no provider sees the guide.
    Ok(read.ok().and_then(|result| result.value))
}

/// Asks the judge whether `outbound`'s body follows the voice guide, and why,
/// as one pack. `None` when the judge abstains on the first question.
fn judge_copy(
    decisions: &CampaignCopyReviewDecisions<'_>,
    definition: &CampaignDefinition,
    guide: EntityId,
    guide_view: NoteReadView,
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
        "voice_guide": guide_view.markdown,
        "subject": outbound.subject,
        "body": String::from_utf8_lossy(&outbound.payload),
    });
    let answers = decisions.ladder.run_pack(
        &[&follows_question, &reason_question],
        definition.owner_actor,
        &[guide],
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
        voice_guide_version: guide_view.version,
        judge: follows.receipt.providers.clone(),
        reviewed_at,
    }))
}

/// The stored verdict that covers the body `payload_digest` names for
/// `campaign_ref` under the voice guide `guide` as `store` holds it now: one
/// judged against that guide at its live version. `None` when none covers it:
/// none was stored, the guide changed, was replaced or was deleted since, or
/// its document does not read (an unreadable guide holds the send, as a
/// changed one does).
fn covering_verdict_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    campaign_ref: EntityId,
    payload_digest: [u8; 32],
    guide: EntityId,
) -> Result<Option<CopyReviewVerdict>> {
    let Some(verdict) = VERDICTS.get(store, txn, &(campaign_ref, payload_digest))? else {
        return Ok(None);
    };
    if verdict.voice_guide_ref != guide {
        return Ok(None);
    }
    let state = crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, &guide)?;
    if state.deleted || state.stale {
        return Ok(None);
    }
    let Ok(live) = crate::note::documents::live_version_in_store_txn(store, txn, guide) else {
        return Ok(None);
    };
    Ok((live == verdict.voice_guide_version).then_some(verdict))
}

/// The Gate's copy-review stage (ARCH-0059 #copy-review), a pure read on
/// the Gate's own transaction. It governs a campaign leg only (an effect
/// whose approve-once target is a campaign leg): an agent-direct send has no
/// campaign body to review. It reads the verdict for the prepared send's own
/// body digest (the frozen envelope's, which the target pins), never the live
/// step's, so a step edited after the send was prepared cannot lend it
/// another body's verdict. `None` when the stage does not hold the send.
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
    Ok(
        match covering_verdict_in_txn(store, txn, facts.campaign_ref, facts.payload_digest, guide)?
        {
            Some(verdict) if verdict.passed => None,
            Some(_) => Some(CopyReviewHold::Failed),
            None => Some(CopyReviewHold::Missing),
        },
    )
}

/// The copy review a held campaign send's owner ask states: the campaign's
/// review mode and, when a verdict covers the held send's body
/// (`payload_digest`) at the guide's live version, its result and reason
/// class, as the Gate read them. `None` when copy review does not govern the
/// campaign.
pub(super) fn copy_review_ask_state_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    campaign_ref: EntityId,
    payload_digest: [u8; 32],
) -> Result<Option<serde_json::Value>> {
    let Some(record) = load_registered_campaign_in_txn(store, txn, campaign_ref)? else {
        return Ok(None);
    };
    if !record.definition.copy_review_governs() {
        return Ok(None);
    }
    let verdict = match record.definition.voice_guide_ref {
        Some(guide) if record.definition.copy_review != CopyReviewMode::Human => {
            covering_verdict_in_txn(store, txn, campaign_ref, payload_digest, guide)?
        }
        _ => None,
    };
    Ok(Some(serde_json::json!({
        "mode": record.definition.copy_review.as_str(),
        "passed": verdict.as_ref().map(|verdict| verdict.passed),
        "reason": verdict.map(|verdict| verdict.reason),
    })))
}
