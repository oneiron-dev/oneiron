//! Blind campaign judge inputs and taste decisions through the shared decision ladder.
//! Entry type: `CampaignTasteDecisions`.
//! Owns these definitions, re-exported by `crate::autoreason_campaign`.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{CampaignError, CampaignResult};
use crate::EntityId;
use crate::llm::decision::catalogue::CAMPAIGN_TASTE;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionLadder,
    DecisionRung, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;

/// External gold anchor a taste judgment was scored against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignGoldAnchor {
    /// Dataset id of the anchor.
    pub dataset_id: String,
    /// Dataset revision of the anchor.
    pub revision: String,
    /// Digest of the anchored gold content.
    pub gold_digest: String,
}

/// The only payload a campaign judge is shown.
///
/// It carries no arm, strategy, round, run id, candidate ref, model tier or
/// campaign ref, and `deny_unknown_fields` keeps a caller from smuggling one
/// back in through a decoded payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct BlindCampaignJudgeInput {
    /// Claim text under judgment.
    pub claim: String,
    /// Evidence references backing the claim.
    pub evidence_refs: Vec<String>,
    /// Held-out gold anchor the judge scores against.
    pub held_out_gold: CampaignGoldAnchor,
}

/// One arm's taste on a split, as the shared decision path answered it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignTaste {
    /// Quality score, finite in `[0, 1]`.
    pub score: f64,
    /// Binary usefulness reading, `None` when it abstained; audit-only — never
    /// read by verdict or validation logic.
    pub useful: Option<bool>,
    /// Digest of the external gold anchor the score was asked against.
    pub external_anchor_digest: String,
}

/// The dial a taste pack runs under unless the host picks another. It ends
/// below Human: a campaign report queues no person ask.
pub const CAMPAIGN_TASTE_DIAL: DecisionDial = DecisionDial {
    first: DecisionRung::Local,
    ceiling: DecisionRung::Big,
    band: DecisionBand {
        low: 0.35,
        high: 0.65,
    },
};

/// The host's wording of the two taste questions.
pub struct CampaignTasteWording {
    /// The `[0, 1]` quality score's question.
    pub score: String,
    /// The usefulness reading's yes-or-no question.
    pub useful: String,
}

/// The shared decision path a campaign's taste goes through: the host's
/// ladder, the principal the answers are for, the dial and learned bands, the
/// wording, and each pack's anytime budget. A provider sees only the
/// [`BlindCampaignJudgeInput`], as the call's bounded state.
pub struct CampaignTasteDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: CampaignTasteWording,
    /// Each taste pack's one clock, from when it is asked.
    pub budget: Duration,
}

impl CampaignTasteDecisions<'_> {
    /// Asks the score and the usefulness reading as one pack over the blind
    /// input. The anchor digest is carried from the input, never chosen by a
    /// model; a score that abstains is no grade and refuses the report.
    pub(super) fn taste(&self, input: &BlindCampaignJudgeInput) -> CampaignResult<CampaignTaste> {
        if input.held_out_gold.gold_digest.is_empty() {
            return Err(CampaignError::ReportMismatch {
                reason: "taste judgment has no external anchor digest",
            });
        }
        let score = CAMPAIGN_TASTE.question(
            &[b"score"],
            self.wording.score.clone(),
            AnswerContract::Score { min: 0.0, max: 1.0 },
        )?;
        let useful = CAMPAIGN_TASTE.question(
            &[b"useful"],
            self.wording.useful.clone(),
            AnswerContract::Noul,
        )?;
        let state = serde_json::to_value(input).map_err(|_| CampaignError::ReportMismatch {
            reason: "blind judge input does not encode",
        })?;
        let decisions = self.ladder.run_pack(
            &[&score, &useful],
            self.principal,
            &[],
            &state,
            self.dial,
            &self.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), self.budget),
        )?;
        let DecisionAnswer::Score(score) = decisions[0].answer else {
            return Err(CampaignError::ReportMismatch {
                reason: "taste decision gave no score",
            });
        };
        let useful = match decisions[1].answer {
            DecisionAnswer::Noul(useful) => Some(useful),
            _ => None,
        };
        Ok(CampaignTaste {
            score,
            useful,
            external_anchor_digest: input.held_out_gold.gold_digest.clone(),
        })
    }
}

pub(super) fn validate_taste(taste: &CampaignTaste) -> CampaignResult<()> {
    if !is_unit_interval_f64(taste.score) {
        return Err(CampaignError::ReportMismatch {
            reason: "taste score must be finite in [0, 1]",
        });
    }
    if taste.external_anchor_digest.is_empty() {
        return Err(CampaignError::ReportMismatch {
            reason: "taste judgment has no external anchor digest",
        });
    }
    Ok(())
}

fn is_unit_interval_f64(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}
