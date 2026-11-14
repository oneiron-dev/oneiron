//! The archive judge (ARM05 P3; ARCH-0053 #output-archive; RULING
//! ARCHIVE-QUALITY-RULER, 13 Nov 22:47): one output revision's placement and
//! quality score, asked of the host's decision ladder for the campaign's
//! controller. The engine reads the pin, the task, the output at its
//! revision and the pinned judge rubric in one snapshot. Outside any writer
//! it asks one typed choice per pinned axis over that axis's bins (an
//! embedding-cluster campaign instead embeds the output on its pinned
//! on-device embedder, with no model judgment) and one typed score in
//! `0..=1` under the rubric. It records the placement and score producer
//! records only when every answer was made at its band's high mark with no
//! person asked. An abstain, a person ask, a deadline, no rung or an
//! uncertain answer records nothing and names why: no bin is invented.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::axes_job::{SAMPLE_TEXT_BYTES, clip};
use super::producers::{self, ArchivePlacementBasis};
use super::records::{self, CampaignArchivePlacement};
use super::{
    ArchiveAxis, ArchiveDescriptor, ArchiveOutputRef, ArchiveOutputScore, CampaignArchivePin,
};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, HumanAskReason, MAX_DECISION_STATE_BYTES, TypedDecision,
};
use crate::skill_optimize::JudgeRubric;
use crate::store::embedding::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingPayload,
};
use crate::{EntityId, Error, Result, Vault};

/// `vault.research.archive.judge`'s request: one output revision of a
/// campaign root, under the descriptor revision the caller read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveJudge {
    pub root: EntityId,
    pub descriptor_revision: String,
    pub output: ArchiveOutputRef,
}

/// The judge's answer: the placement and the score
/// `vault.research.archive.record` takes, each naming the producer record
/// the engine wrote.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveJudged {
    pub placement: CampaignArchivePlacement,
    pub score: ArchiveOutputScore,
}

/// What one judge question asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveJudgeQuestion {
    /// Which of a pinned axis's bins the output falls in.
    Placement { axis: String, bins: Vec<String> },
    /// How well the output carries out its task, under the pinned judge
    /// rubric.
    Score,
}

/// One question the judge asks the host's ladder.
#[derive(Debug, Clone)]
pub struct ArchiveJudgeAsk {
    pub question: ArchiveJudgeQuestion,
    /// What names the question beside its family and wording: the descriptor
    /// revision and the axis, or the pinned ruler.
    pub key: Vec<String>,
    /// What the rungs read: the task, the response, and the axis or the
    /// judge rubric with its pin.
    pub state: Value,
    /// The rows the state was read from.
    pub evidence: Vec<EntityId>,
}

impl ArchiveJudgeAsk {
    /// The answer the question takes: one of the axis's bins, or a score in
    /// `0..=1`.
    #[must_use]
    pub fn contract(&self) -> AnswerContract {
        match &self.question {
            ArchiveJudgeQuestion::Placement { bins, .. } => AnswerContract::Choice {
                options: bins.clone(),
            },
            ArchiveJudgeQuestion::Score => AnswerContract::Score { min: 0.0, max: 1.0 },
        }
    }
}

/// What the host lends the judge: its decision ladder, on the caller's own
/// line, and its embedder.
pub trait ArchiveJudgeHost {
    /// One typed decision for `ask`.
    ///
    /// # Errors
    ///
    /// A fault of the ladder: a budget denial, or a provider failure with
    /// time left.
    fn decide(&self, ask: &ArchiveJudgeAsk) -> Result<TypedDecision>;

    /// The vault's admitted embedder, for an embedding-cluster campaign;
    /// `None` while none serves.
    fn embedder(&self) -> Option<Arc<dyn Embedder>>;
}

/// What the judge reads in one snapshot: the pin, the task as the caller
/// reads it, the output's text at its revision and the pinned rubric.
pub(crate) struct ArchiveJudgeBrief {
    pub(crate) pin: CampaignArchivePin,
    pub(crate) task: Value,
    pub(crate) output_text: String,
    pub(crate) rubric: JudgeRubric,
}

/// The judge's premises for `input`: the installed pin at its descriptor
/// revision with its goal still current, the output's text at its revision,
/// and the rubric of the judge the pin's ruler names at its package.
pub(crate) fn premises_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &CampaignArchiveJudge,
) -> Result<(CampaignArchivePin, String, JudgeRubric)> {
    let pin = producers::current_pin_in_txn(vault, txn, input.root, &input.descriptor_revision)?;
    let text = records::output_text_in_txn(vault, txn, &input.output)?.ok_or_else(|| {
        Error::InvalidConfig("the output no longer serves at its revision".into())
    })?;
    let rubric = producers::ruler_in_txn(vault, txn, pin.quality_metric())?;
    Ok((pin, text, rubric))
}

/// The placement basis and the score decision for `brief`, or why there are
/// none. Each question runs on `host` in order: every placement first, then
/// the score.
pub(crate) fn judgment(
    brief: &ArchiveJudgeBrief,
    input: &CampaignArchiveJudge,
    host: &dyn ArchiveJudgeHost,
) -> Result<std::result::Result<(ArchivePlacementBasis, TypedDecision), String>> {
    let basis = match brief.pin.descriptor() {
        ArchiveDescriptor::Axes { axes } => {
            let mut decisions = Vec::with_capacity(axes.len());
            for axis in axes {
                let ask = placement_ask(brief, input, axis);
                fits(&ask)?;
                let decision = host.decide(&ask)?;
                let what = format!("the {} placement", axis.name);
                if let Err(why) = decided(&decision) {
                    return Ok(Err(format!("{what} {why}")));
                }
                match &decision.answer {
                    DecisionAnswer::Choice(bin) if axis.bins.contains(bin) => {}
                    _ => return Ok(Err(format!("{what} answered no pinned bin"))),
                }
                decisions.push(decision);
            }
            ArchivePlacementBasis::Judgment { decisions }
        }
        ArchiveDescriptor::EmbeddingClusters { model_revision, .. } => {
            match embedding(brief, input, host, model_revision)? {
                Ok(embedding) => ArchivePlacementBasis::Embedding {
                    model_revision: model_revision.clone(),
                    embedding,
                },
                Err(reason) => return Ok(Err(reason)),
            }
        }
    };
    let ask = score_ask(brief, input);
    fits(&ask)?;
    let decision = host.decide(&ask)?;
    if let Err(why) = decided(&decision) {
        return Ok(Err(format!("the quality score {why}")));
    }
    if !matches!(decision.answer, DecisionAnswer::Score(quality)
        if quality.is_finite() && (0.0..=1.0).contains(&quality))
    {
        return Ok(Err("the quality score answered no score in 0..=1".into()));
    }
    Ok(Ok((basis, decision)))
}

/// Records the placement and the score in one writer, through the
/// producers' own writers, which check the premises again.
pub(crate) fn mint_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: CampaignArchiveJudge,
    basis: ArchivePlacementBasis,
    score: TypedDecision,
    principal: EntityId,
) -> Result<CampaignArchiveJudged> {
    let placement = producers::mint_placement_in_txn(
        vault,
        txn,
        input.root,
        &input.descriptor_revision,
        input.output.clone(),
        basis,
        principal,
    )?;
    let score = producers::mint_score_in_txn(
        vault,
        txn,
        input.root,
        &input.descriptor_revision,
        input.output,
        score,
        principal,
    )?;
    Ok(CampaignArchiveJudged { placement, score })
}

/// Whether `decision` is an answer the archive takes: made at its band's
/// high mark with no person asked, as the replay judge's scores are
/// (`ai_host/eval_measurement/score.rs` `decided`). Else why not.
fn decided(decision: &TypedDecision) -> std::result::Result<(), String> {
    if let Some(reason) = decision.human_ask {
        return Err(format!("was not answered ({})", reason_name(reason)));
    }
    if decision.answer == DecisionAnswer::Abstain {
        return Err("abstained".into());
    }
    if !decision
        .probability
        .is_some_and(|p| p >= decision.receipt.band.high)
    {
        return Err("was uncertain: answered below its band's high mark".into());
    }
    Ok(())
}

/// A person-ask reason by its wire name.
fn reason_name(reason: HumanAskReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{reason:?}"))
}

/// A state past one decision's bound is never cut and judged.
fn fits(ask: &ArchiveJudgeAsk) -> Result<()> {
    if serde_json::to_vec(&ask.state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES) {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "the task, output and rubric are past one decision's state bound; nothing is cut and judged"
                .into(),
        ))
    }
}

fn sorted(mut rows: Vec<EntityId>) -> Vec<EntityId> {
    rows.sort();
    rows.dedup();
    rows
}

fn placement_ask(
    brief: &ArchiveJudgeBrief,
    input: &CampaignArchiveJudge,
    axis: &ArchiveAxis,
) -> ArchiveJudgeAsk {
    ArchiveJudgeAsk {
        question: ArchiveJudgeQuestion::Placement {
            axis: axis.name.clone(),
            bins: axis.bins.clone(),
        },
        key: vec![input.descriptor_revision.clone(), axis.name.clone()],
        state: json!({
            "task": brief.task,
            "response": brief.output_text,
            "axis": axis.name,
            "bins": axis.bins,
        }),
        evidence: sorted(vec![input.output.entity, brief.pin.task()]),
    }
}

fn score_ask(brief: &ArchiveJudgeBrief, input: &CampaignArchiveJudge) -> ArchiveJudgeAsk {
    let metric = brief.pin.quality_metric();
    ArchiveJudgeAsk {
        question: ArchiveJudgeQuestion::Score,
        key: vec![metric.metric_id.clone(), metric.revision.clone()],
        state: json!({
            "task": brief.task,
            "response": brief.output_text,
            "judge_rubric": brief.rubric.text,
            "judge_rubric_pin": {
                "skill": brief.rubric.skill.to_hex(),
                "version": brief.rubric.version,
                "digest": blake3::Hash::from_bytes(brief.rubric.digest).to_hex().as_str(),
            },
        }),
        evidence: sorted(vec![
            input.output.entity,
            brief.pin.task(),
            brief.rubric.skill,
        ]),
    }
}

/// The output's embedding on the pinned embedder, read as the Coach's
/// clusters read their samples: on this device only, clipped alike.
fn embedding(
    brief: &ArchiveJudgeBrief,
    input: &CampaignArchiveJudge,
    host: &dyn ArchiveJudgeHost,
    model_revision: &str,
) -> Result<std::result::Result<Vec<f64>, String>> {
    let Some(embedder) = host.embedder() else {
        return Ok(Err("no embedder serves on this host".into()));
    };
    if embedder.locality() != EmbedderLocality::OnDevice {
        return Ok(Err(
            "the output's words stay on this device, and the admitted embedder is not on it".into(),
        ));
    }
    if embedder.model_id() != model_revision {
        return Ok(Err(
            "the admitted embedder is not the one the descriptor pins".into(),
        ));
    }
    let text = clip(brief.output_text.clone(), SAMPLE_TEXT_BYTES);
    if text.trim().is_empty() {
        return Ok(Err("a blank output takes no embedding".into()));
    }
    let token = blake3::hash(text.as_bytes()).as_bytes().to_vec();
    let vectors = embedder.embed(&[PendingEmbeddingInput {
        entity_id: input.output.entity,
        payload: PendingEmbeddingPayload::SummaryText(text),
        pending_embedding_token: token,
    }])?;
    match vectors.as_slice() {
        [vector] if vector.len() == embedder.dimensions() => {
            Ok(Ok(vector.iter().copied().map(f64::from).collect()))
        }
        _ => Err(Error::InvariantViolation(
            "an embedder answered one archive output with other than one vector",
        )),
    }
}
