//! The host's slow retrieval loop reviewer (census L1-18, ARCH-0053
//! #tune-retrieval): the Coach's model runs the owner's imported
//! `tune-oneiron-retrieval` skill, its SKILL.md the instruction, over the
//! engine's brief, and answers with one proposal. The engine checks the
//! proposal and keeps it as an offer; nothing is applied. With no Coach seat
//! the review asks nothing and the job ends; the next published run queues
//! another.
use std::collections::BTreeMap;

use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::dreamer_runner::maintenance::retrieval_skill_review::{
    RetrievalSkillBrief, RetrievalSkillReviewer, RetrievalTuningKnob, RetrievalTuningProposal,
    RetrievalTuningProposalKind,
};
use oneiron::limit_ask::EngineLimit;
use oneiron::store::RetrievalRunId;
use oneiron::{EntityId, Error, LlmMessageRole, Vault};
use serde::Deserialize;
use serde_json::json;

use super::super::coach_health::coach_role;
use super::super::code_fix::{HostModels, message};
use crate::server::SyncServer;

/// The purpose the review is metered and routed under.
const PURPOSE: &str = "coach_retrieval_skill_review";
/// What one review may spend; the server-wide and payer ceilings still bind.
const REVIEW_BUDGET_UNITS: u64 = 1 << 20;
/// The skill's file the Coach runs; the rest of the brief goes as data.
const SKILL_FILE: &str = "SKILL.md";
/// The answer's shape, after the skill's own instruction.
const ANSWER_SHAPE: &str = "Answer with one JSON object and nothing else: \
{\"kind\": \"owner_recommendation\" | \"learner_reseed\" | \"engine_work\" | \"collect_evidence\", \
\"symptom\": the symptom with its run counts and time window, \
\"causes_checked\": [each cause you checked, in order, and what it showed], \
\"knob\": null | {\"learner_setting\": \"max_runs\" | \"learning_rate\" | \"min_reward_count\"} \
| {\"blend_weight\": signal} | {\"owner_pin\": signal} | {\"other\": the knob as references/knobs.md names it}, \
\"slice\": null | the slice, \"change\": null | the change from and to, \
\"evidence_runs\": [the \"run\" ids, from the data, that show the symptom]}. \
A signal is one of \"recency\", \"salience\", \"confidence\", \"gravity\", \"relevance\".";

/// One `coach.retrieval_skill_review` job on the Coach's seat.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let runtime = server.ai.model_runtime();
    if runtime.seat(coach_role(runtime)).is_none() {
        tracing::debug!("no seat serves the Coach: the retrieval skill review asks nothing");
        return Ok(());
    }
    let attempt = EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?;
    let reviewer = HostReviewer {
        models: HostModels::open(
            server,
            format!("coach-retrieval-skill-review:{}", attempt.to_hex()),
            PURPOSE,
            REVIEW_BUDGET_UNITS,
        )?,
        vault: server.vault(),
    };
    let receipt = server
        .vault()
        .run_coach_retrieval_skill_review(admitted, &reviewer, now)?;
    tracing::debug!(
        kind = ?receipt.proposal.kind,
        disposition = ?receipt.disposition,
        "the Coach reviewed retrieval against its skill"
    );
    Ok(())
}

/// The Coach's model on the skill.
struct HostReviewer<'a> {
    models: HostModels<'a>,
    vault: &'a Vault,
}

impl RetrievalSkillReviewer for HostReviewer<'_> {
    fn review(&self, brief: &RetrievalSkillBrief) -> oneiron::Result<RetrievalTuningProposal> {
        let skill = brief
            .files
            .iter()
            .find(|file| file.path == SKILL_FILE)
            .ok_or_else(|| {
                Error::InvalidConfig("the imported retrieval skill holds no SKILL.md".into())
            })?;
        let data = brief_data(brief).to_string();
        // The brief goes to the model whole; its size is measured (Rule 5).
        let _ = self
            .vault
            .measure_limit(EngineLimit::MaintenanceTextBytes, data.len() as u64);
        let text = self
            .models
            .generate(
                self.models.coach(),
                vec![
                    message(
                        LlmMessageRole::System,
                        format!("{}\n\n{ANSWER_SHAPE}", skill.text),
                    ),
                    message(LlmMessageRole::User, data),
                ],
            )?
            .ok_or_else(|| {
                Error::InvalidConfig("no seat took the Coach's retrieval review".into())
            })?;
        parse_proposal(&text).ok_or_else(|| {
            Error::InvalidConfig("the Coach's retrieval review answer holds no proposal".into())
        })
    }
}

/// The brief as the model reads it: the skill's other files, then the
/// receipts. A run goes as its counts, signals and reasons, never its result
/// ids or trace.
fn brief_data(brief: &RetrievalSkillBrief) -> serde_json::Value {
    let mut outcomes: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    for outcome in &brief.outcomes {
        outcomes
            .entry(outcome.run_id.to_hex())
            .or_default()
            .push(json!({
                "key": outcome.key,
                "reward": outcome.reward,
                "accepted": outcome.accepted,
                "gated": outcome.reward_evidence.is_some(),
                "updated_at": outcome.updated_at,
            }));
    }
    let runs: Vec<serde_json::Value> = brief
        .runs
        .iter()
        .map(|run| {
            let id = run.run_id.to_hex();
            json!({
                "outcomes": outcomes.remove(&id).unwrap_or_default(),
                "run": id,
                "started_at": run.started_at,
                "action": run.action,
                "elapsed_us": run.elapsed_us,
                "iteration": run.state.iteration,
                "signals": run.signals,
                "results": run.result_ids.len(),
                "in_scope": run.total_in_scope,
                "empty_reason": run.empty_reason,
                "degraded": !run.degradation.is_empty(),
            })
        })
        .collect();
    json!({
        "skill": {
            "id": brief.skill.skill_id,
            "version": brief.skill.version,
            "hub_commit": brief.skill.commit,
        },
        "files": brief
            .files
            .iter()
            .filter(|file| file.path != SKILL_FILE)
            .map(|file| json!({"path": file.path, "text": file.text}))
            .collect::<Vec<_>>(),
        "blend": brief.blend,
        "pins": brief.pins,
        "latency_baseline_us": brief
            .latency_baseline
            .map(|(p50, p95)| json!({"p50": p50, "p95": p95})),
        "learner": {
            "max_runs": brief.learner.max_runs,
            "learning_rate": brief.learner.learning_rate,
            "min_reward_count": brief.learner.min_reward_count,
        },
        "retention": brief
            .retention
            .map(|(max_age_secs, max_runs)| json!({"max_age_secs": max_age_secs, "max_runs": max_runs})),
        "capture": true,
        "runs": runs,
    })
}

/// The review's answer as the Coach writes it.
#[derive(Deserialize)]
struct ProposalWire {
    kind: RetrievalTuningProposalKind,
    symptom: String,
    #[serde(default)]
    causes_checked: Vec<String>,
    #[serde(default)]
    knob: Option<RetrievalTuningKnob>,
    #[serde(default)]
    slice: Option<String>,
    #[serde(default)]
    change: Option<String>,
    #[serde(default)]
    evidence_runs: Vec<String>,
}

/// The one JSON object in the answer; `None` when there is none, or when it
/// cites a run id that is not 32 hex digits. A well-formed id the brief does
/// not hold reaches the engine, which refuses the proposal.
fn parse_proposal(text: &str) -> Option<RetrievalTuningProposal> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    let wire: ProposalWire = serde_json::from_str(text.get(start..=end)?).ok()?;
    let evidence_runs = wire
        .evidence_runs
        .iter()
        .map(String::as_str)
        .map(RetrievalRunId::from_hex)
        .collect::<Option<Vec<_>>>()?;
    Some(RetrievalTuningProposal {
        kind: wire.kind,
        symptom: wire.symptom,
        causes_checked: wire.causes_checked,
        knob: wire.knob,
        slice: wire.slice,
        change: wire.change,
        evidence_runs,
    })
}
