//! Door for `tests/skill_optimize_file_edits.rs` (census L9-02): enqueues the
//! Coach's optimize attempt, drafts on one named skill through the optimize
//! job's own drafting door (the selector's ranking is not under test), reads
//! the package tree a skill serves, and supplies a held-out judge that scores
//! instructions by whether they name a marker phrase.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Value, json};

use crate::attempt_queue::{
    AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome,
};
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome, EnqueueDreamerSkillOptimizeAttempt,
};
use crate::error::{Error, Result};
use crate::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionLadder,
    DecisionProvider, DecisionQuestion, DecisionRung, HumanDecisionQueue, HumanDecisionRequest,
    ProviderDecision, ProviderPin, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::skill_hub::HubPackage;
use crate::skill_optimize::{
    GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes, HonestyReplay, SkillOptimizeAuthor,
    SkillOptimizeDecisions, SkillOptimizeOutcome, SkillReplayResponse, SkillReplayResponses,
    judgment_kind,
};
use crate::{EntityId, TimeRange, Vault};

/// Enqueues one Coach `skill_optimize` attempt and takes it through claim and
/// completion, so its stored row proves the cycle a draft is born into.
/// `run` names the wake the attempt belongs to.
///
/// # Errors
///
/// Queue refusals and storage errors.
pub fn enqueue_skill_optimize_attempt(
    vault: &Vault,
    run: Option<&str>,
    now: u64,
) -> Result<AttemptId> {
    let EnqueueDreamerAttemptOutcome::Enqueued(status) = DreamerRunnerStore::new(vault)
        .enqueue_skill_optimize(EnqueueDreamerSkillOptimizeAttempt {
            input: rmpv::Value::Nil,
            parent_attempt: None,
            dedupe_key: None,
            run_id: run.map(str::to_owned),
            now,
        })?
    else {
        return Err(Error::InvalidConfig(
            "a dedupe-free optimize enqueue is never an existing row".into(),
        ));
    };
    let attempt = status.attempt;
    let queue = AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        crate::store::dreamer_attempt_kind::DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "skill-opt-files".to_owned(),
            now: now + 1,
        },
    )?
    else {
        return Err(Error::InvalidConfig(
            "the enqueued optimize attempt is not claimable".into(),
        ));
    };
    if leased.id != attempt.id {
        return Err(Error::InvalidConfig(
            "another ready optimize attempt was claimed before this one".into(),
        ));
    }
    let CompleteOutcome::Completed(_) = queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: "skill-opt-files".to_owned(),
        attempt_count: leased.attempt_count,
        now: now + 2,
    })?
    else {
        return Err(Error::InvalidConfig(
            "the leased optimize attempt did not complete".into(),
        ));
    };
    Ok(attempt.id)
}

/// Drafts on `skill` under `attempt` as the optimize job does once it has
/// chosen a target: the brief a repair reads for that one skill, then the
/// job's own author call, draft validation and proposal door.
///
/// # Errors
///
/// A target the optimizer may not revise, and everything the job's drafting
/// door refuses.
pub fn draft_on_skill(
    vault: &Vault,
    skill: &EntityId,
    attempt: AttemptId,
    author: &dyn SkillOptimizeAuthor,
    now: u64,
) -> Result<SkillOptimizeOutcome> {
    let brief = crate::skill_optimize::skill_repair_brief(vault, skill, now)?;
    crate::skill_optimize::draft_and_propose(
        vault,
        attempt,
        author,
        &brief,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        None,
        None,
    )
}

/// The package tree `skill` serves, read as the runtime skill load reads it,
/// with the record it is bound to; `None` when the skill has none.
///
/// # Errors
///
/// A missing skill, a package that differs from its record, and storage
/// errors.
pub fn served_skill_package(vault: &Vault, skill: &EntityId) -> Result<Option<HubPackage>> {
    let record = vault
        .get_skill_record(skill)?
        .ok_or(Error::EntityNotFound)?;
    let txn = vault.store.env.read_txn()?;
    vault.runtime_skill_package_in_txn(&txn, skill, &record)
}

/// The held-out judge's model revision.
const JUDGE_REVISION: &str = "fixture-judge@1";

/// Every judgment kind the gate asks, worded for the fixture.
const JUDGMENT_KINDS: [&str; 7] = [
    "score",
    "structural",
    "contrastive",
    "preference",
    "task_success",
    "honesty",
    "response_score",
];

/// A held-out judge that scores instructions naming its marker phrase 0.75
/// and every other instruction text 0.40, and answers each other judgment
/// kind the gate asks neutrally: the proposed text wins exactly when the
/// judge read the marker in it.
pub struct MarkerScorer {
    provider: MarkerProvider,
    wording: BTreeMap<String, String>,
    deadline: RetrievalDeadline,
    principal: EntityId,
}

/// A [`MarkerScorer`] whose marker is `marker`.
#[must_use]
pub fn marker_scorer(marker: &str) -> MarkerScorer {
    MarkerScorer {
        provider: MarkerProvider {
            marker: marker.to_owned(),
        },
        wording: JUDGMENT_KINDS
            .into_iter()
            .map(|kind| (kind.to_owned(), format!("fixture {kind} judgment")))
            .collect(),
        deadline: RetrievalDeadline::after(Duration::from_secs(3600)),
        principal: EntityId::now(),
    }
}

struct MarkerProvider {
    marker: String,
}

/// The person queue of the fixture ladder: there is no person to ask.
struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> Result<()> {
        Err(Error::InvalidConfig(
            "the marker judge asks no person".into(),
        ))
    }
}

fn answered(answer: DecisionAnswer) -> ProviderDecision {
    ProviderDecision {
        answer,
        probability: Some(0.9),
        paired: None,
        person: None,
        served: None,
        cost_per_thousand: None,
    }
}

impl DecisionProvider for MarkerProvider {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::SystemOne,
            model: "fixture-judge".to_owned(),
            version: "1".to_owned(),
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let kind = judgment_kind(JUDGE_REVISION, call.question, call.state);
        match kind.as_deref() {
            Some("score") => {
                let instructions = call
                    .state
                    .get("instructions")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                Ok(answered(DecisionAnswer::Score(
                    if instructions.contains(self.marker.as_str()) {
                        0.75
                    } else {
                        0.40
                    },
                )))
            }
            Some("structural" | "contrastive" | "task_success" | "response_score") => {
                Ok(answered(DecisionAnswer::Score(0.5)))
            }
            Some("preference") => Ok(answered(DecisionAnswer::Choice("first".to_owned()))),
            Some("honesty") => Ok(answered(DecisionAnswer::Noul(false))),
            other => Err(Error::InvalidConfig(
                format!("the marker judge was asked an unexpected kind: {other:?}").into(),
            )),
        }
    }
}

impl HeldOutReplayNotes for MarkerScorer {
    fn judge_revision(&self) -> &str {
        JUDGE_REVISION
    }

    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        SkillOptimizeDecisions {
            ladder: DecisionLadder {
                rule: None,
                local: None,
                system_one: Some(&self.provider),
                escalation: None,
                big: None,
                human: &NoPerson,
                human_pin: ProviderPin {
                    rung: DecisionRung::Human,
                    model: "no-person".to_owned(),
                    version: "1".to_owned(),
                },
                ask_to: None,
                paired: None,
                person: None,
                presence: None,
                correlation: None,
            },
            principal: self.principal,
            dial: DecisionDial {
                first: DecisionRung::SystemOne,
                ceiling: DecisionRung::Human,
                band: DecisionBand::default(),
            },
            bands: DecisionBandPolicy::default(),
            deadline: &self.deadline,
            wording: &self.wording,
        }
    }

    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<Value> {
        Ok(json!({ "held_out_receipts": case.held_out_receipts }))
    }

    fn replay_responses(&self, receipts: &[String]) -> Result<SkillReplayResponses> {
        let mut responses: Vec<SkillReplayResponse> = receipts
            .iter()
            .take(2)
            .map(|receipt| SkillReplayResponse {
                receipt: receipt.clone(),
                task: "fixture task".to_owned(),
                response: format!("fixture response for {receipt}"),
            })
            .collect();
        if responses.len() == 1 {
            responses.push(SkillReplayResponse {
                receipt: "fixture-solo-pair-mate".to_owned(),
                task: "fixture task".to_owned(),
                response: "fixture solo mate response".to_owned(),
            });
        }
        Ok(SkillReplayResponses {
            responses,
            rubric: None,
        })
    }

    fn record_decision(
        &self,
        _question: &DecisionQuestion,
        _decision: &TypedDecision,
        _state: &Value,
    ) -> Result<()> {
        Ok(())
    }

    fn honesty_replays(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<HonestyReplay>> {
        Ok(case
            .held_out_receipts
            .iter()
            .map(|receipt| HonestyReplay {
                receipt: receipt.clone(),
                state: json!({ "receipt": receipt }),
                objectives: vec![format!("fixture objective for {receipt}")],
            })
            .collect())
    }

    fn goal_axes(&self, _case: &HeldOutReplayCase<'_>) -> Result<Vec<GoalAxisSpec>> {
        Ok(Vec::new())
    }
}
