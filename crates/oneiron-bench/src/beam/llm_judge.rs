//! The production model-scored BEAM door: pin validation, three votes, no reward feedback.
use super::{
    BeamError, BeamResult,
    judge::{AnswerPromptPin, JUDGE_VOTE_COUNT, run_majority_judge_card},
    llm_host::{HostConfig, ModelPin, ModelSession},
    model::JudgeMetadata,
    model_usage::sum_costs,
    nuggets::{NuggetJudgment, WedgeBucket},
    report_model::{CostComponentReport, ScoreReport},
    scorer::FixedBeamScorer,
};
use oneiron::{BudgetLease, CallPurpose};
use serde::{Deserialize, Serialize};
use std::path::Path;
const BEAM_JUDGE: &str = "openai/gpt-4.1-mini@2025-04-14";
const LME_JUDGE: &str = "openai/gpt-4o@2024-08-06";
/// The `beam-replicate@3e12035` pass shows its judge this literal in place of
/// the probing question, as upstream 3e12035 did (ARCH-0042 `beam:D9`).
pub(super) const REPLICATE_PLACEHOLDER_QUESTION: &str = "<question>";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum JudgeBenchmark {
    Beam,
    LongMemEvalS,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JudgeConfig {
    pub benchmark: JudgeBenchmark,
    pub instruction: AnswerPromptPin,
    pub model: ModelPin,
    pub card: JudgeMetadata,
    /// The upstream 3e12035 judge prompt. When set, every judgment also runs
    /// the `beam-replicate@3e12035` pass under this pin, apart from the
    /// `beam-fixed` pass and with the placeholder question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicate_instruction: Option<AnswerPromptPin>,
}
impl JudgeConfig {
    pub(super) fn validate_dataset(&self, dataset: &str) -> BeamResult<()> {
        let matches = match self.benchmark {
            JudgeBenchmark::Beam => {
                dataset == "beam" || dataset.starts_with("beam-") || dataset.starts_with("beam_")
            }
            JudgeBenchmark::LongMemEvalS => {
                dataset == "longmemeval-s" || dataset.starts_with("longmemeval-s-")
            }
        };
        if !matches {
            return Err(BeamError::JudgeCardInvalid {
                reason: "judge benchmark does not match the loaded dataset identity".into(),
            });
        }
        Ok(())
    }

    pub(super) fn validate(&self, runtime_answer_prompt: &str) -> BeamResult<()> {
        self.card
            .require_majority_vote_card(runtime_answer_prompt)?;
        if self.instruction.content.trim().is_empty()
            || !self
                .instruction
                .matches_exact_text(&self.instruction.content)
        {
            return Err(BeamError::JudgeCardInvalid {
                reason: "judge instruction content and sha256 must match".into(),
            });
        }
        if let Some(replicate) = &self.replicate_instruction {
            if self.benchmark != JudgeBenchmark::Beam {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "the beam-replicate@3e12035 pass is a BEAM column; this judge scores another benchmark".into(),
                });
            }
            if replicate.content.trim().is_empty()
                || !replicate.matches_exact_text(&replicate.content)
            {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "replicate judge instruction content and sha256 must match".into(),
                });
            }
        }
        let expected = match self.benchmark {
            JudgeBenchmark::Beam => BEAM_JUDGE,
            JudgeBenchmark::LongMemEvalS => LME_JUDGE,
        };
        let provider_model = format!(
            "{}-{}",
            self.model.model_id.name(),
            self.model.model_id.revision()
        );
        if self.model.model_id.as_str() != expected
            || self.model.provider_model != provider_model
            || self.model.temperature != 0.0
            || self.model.max_tokens != 128
            || self.card.judge_id != self.model.model_id.name()
            || self.card.version != self.model.model_id.revision()
        {
            return Err(BeamError::JudgeCardInvalid{reason:"replicate-paper judge id, revision or parameters do not match the pinned config".into()});
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JudgeItem {
    pub question: String,
    pub candidate_answer: String,
    pub gold_answer: String,
    pub ability: String,
    pub wedge_bucket: WedgeBucket,
}
#[derive(Debug, Serialize)]
pub(super) struct JudgedScore {
    pub judge: JudgeConfig,
    pub winning_tally: usize,
    pub verdict: f64,
    /// The `beam-replicate@3e12035` pass's own majority, when the config pins
    /// that pass. Its column int-casts this verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicate_winning_tally: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicate_verdict: Option<f64>,
    /// Every call of every pass.
    pub judge_cost: CostComponentReport,
    pub score: ScoreReport,
}
pub(super) fn score_item(
    session: &ModelSession,
    config: &JudgeConfig,
    runtime_answer_prompt: &str,
    item: &JudgeItem,
) -> BeamResult<JudgedScore> {
    config.validate(runtime_answer_prompt)?;
    let passes = 1 + usize::from(config.replicate_instruction.is_some());
    // Both passes are admitted before any call.
    let leases = session.reserve_calls(JUDGE_VOTE_COUNT * passes)?;
    let mut costs = Vec::new();
    let (verdict, winning_tally) = judge_pass(
        session,
        config,
        runtime_answer_prompt,
        &config.instruction,
        &judge_input(item, &item.question)?,
        &leases[..JUDGE_VOTE_COUNT],
        &mut costs,
    )?;
    // Its own calls under its own pin: never the fixed verdicts relabeled.
    let replicate = match &config.replicate_instruction {
        Some(instruction) => Some(judge_pass(
            session,
            config,
            runtime_answer_prompt,
            instruction,
            &judge_input(item, REPLICATE_PLACEHOLDER_QUESTION)?,
            &leases[JUDGE_VOTE_COUNT..],
            &mut costs,
        )?),
        None => None,
    };
    Ok(JudgedScore {
        judge: config.clone(),
        winning_tally,
        verdict,
        replicate_winning_tally: replicate.map(|(_, tally)| tally),
        replicate_verdict: replicate.map(|(replicate_verdict, _)| replicate_verdict),
        judge_cost: sum_costs(&costs)?,
        score: FixedBeamScorer.score_nuggets(&[NuggetJudgment {
            value: verdict,
            replicate_value: replicate.map(|(replicate_verdict, _)| replicate_verdict),
            ability: item.ability.clone(),
            wedge_bucket: item.wedge_bucket,
        }])?,
    })
}
/// Ability and wedge labels classify the report, not the judge's evidence.
fn judge_input(item: &JudgeItem, question: &str) -> BeamResult<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "question": question,
        "candidate_answer": item.candidate_answer,
        "gold_answer": item.gold_answer,
    }))?)
}
/// One three-call majority under `instruction`: the verdict on the 0..1
/// nugget scale and its winning tally.
fn judge_pass(
    session: &ModelSession,
    config: &JudgeConfig,
    runtime_answer_prompt: &str,
    instruction: &AnswerPromptPin,
    input: &str,
    leases: &[BudgetLease],
    costs: &mut Vec<CostComponentReport>,
) -> BeamResult<(f64, usize)> {
    let decision = run_majority_judge_card(&config.card, runtime_answer_prompt, |index| {
        let (answer, cost) = session.invoke_with_lease(
            &config.model,
            CallPurpose::Eval,
            &instruction.content,
            input,
            Some(&leases[index]),
        )?;
        costs.push(cost);
        match answer.trim() {
            "0" => Ok(0_u8),
            "0.5" => Ok(1),
            "1" => Ok(2),
            _ => Err(BeamError::Comparability {
                reason: "judge returned an invalid nugget verdict".into(),
            }),
        }
    })
    .map_err(|error| {
        use super::judge::{MajorityJudgeError, MajorityVoteError};
        match error {
            MajorityJudgeError::Card(error) => error,
            MajorityJudgeError::Vote(MajorityVoteError::CallFailures { attempts }) => {
                BeamError::Comparability {
                    reason: format!(
                        "{} of three judge calls failed",
                        attempts.iter().filter(|a| a.is_err()).count()
                    ),
                }
            }
            MajorityJudgeError::Vote(MajorityVoteError::Tie { votes }) => {
                BeamError::Comparability {
                    reason: format!("no majority among {} judge votes", votes.len()),
                }
            }
        }
    })?;
    Ok((f64::from(decision.verdict) / 2.0, decision.vote_count))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeRun {
    host: HostConfig,
    judge: JudgeConfig,
    answer_prompt: String,
    item: JudgeItem,
}
pub(super) fn run(path: &Path) -> BeamResult<JudgedScore> {
    let run: JudgeRun = serde_json::from_slice(&std::fs::read(path)?)?;
    run.judge.validate(&run.answer_prompt)?;
    let session = ModelSession::connect(run.host, std::slice::from_ref(&run.judge.model))?;
    score_item(&session, &run.judge, &run.answer_prompt, &run.item)
}
#[cfg(test)]
mod tests;
