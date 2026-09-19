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
use oneiron::CallPurpose;
use serde::{Deserialize, Serialize};
use std::path::Path;
const BEAM_JUDGE: &str = "openai/gpt-4.1-mini@2025-04-14";
const LME_JUDGE: &str = "openai/gpt-4o@2024-08-06";
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
}
impl JudgeConfig {
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
    let input = serde_json::to_string(item)?;
    let leases = session.reserve_calls(JUDGE_VOTE_COUNT)?;
    let mut costs = Vec::new();
    let decision = run_majority_judge_card(&config.card, runtime_answer_prompt, |index| {
        let (answer, cost) = session.invoke_with_lease(
            &config.model,
            CallPurpose::Eval,
            &config.instruction.content,
            &input,
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
    let verdict = f64::from(decision.verdict) / 2.0;
    Ok(JudgedScore {
        judge: config.clone(),
        winning_tally: decision.vote_count,
        verdict,
        judge_cost: sum_costs(&costs)?,
        score: FixedBeamScorer.score_nuggets(&[NuggetJudgment {
            value: verdict,
            ability: item.ability.clone(),
            wedge_bucket: item.wedge_bucket,
        }])?,
    })
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
