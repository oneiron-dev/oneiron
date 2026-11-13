//! The host's seal checker (ARCH-0079 #stuck-confession-and-the-seal,
//! OF-544): for each pending confession recheck or drawn random audit, a
//! judge that did not produce the result reads the attempt's pinned output
//! (an output handle's bytes, or the answer a resident run's result TURN
//! names) and answers, per requested objective, whether a flaw keeps it from
//! being met. A recheck shows what the agent confessed, to be examined
//! directly; a random audit shows only the objectives, so the agent's own
//! report does not steer it. The Coach pays for the calls. Each finding
//! names the checker's protocol, the role its judge ran on and the rung that
//! answered there, as the call returned it, so a completed random audit
//! freezes its contract (FIX 3611, [`checker`]). Each objective is one
//! question on the decision ladder (ARCH-0076 #decide-required,
//! DECIDE-BYPASS-2), the judge the ladder's one rung ([`SealJudge`]).
use std::sync::Mutex;
use std::time::Duration;

use oneiron::EntityId;
use oneiron::agent_dispatch::AgentDispatcher;
use oneiron::compaction::output::{OutputRef, restore_output};
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::dreamer_runner::maintenance::seal_checks::{
    SealCheck, SealChecker, SealObjectiveCheck, SealObjectiveDecision, SealObjectiveDecisions,
};
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::decision::{
    DecisionCall, DecisionPack, DecisionProvider, DecisionRung, ProviderDecision, ProviderPin,
};
use oneiron::llm::manifest::ModelRole;
use oneiron::self_heal::audit::{CheckerProtocol, SealCheckOutcome, SealCheckRequest};

use self::checker::{
    FLAW_WORDING, answers, check_state, independent, objective_data, pack_messages, protocol_digest,
};
use super::super::CHAT_ROLE;
use super::super::code_fix::HostModels;
use crate::models::ModelCallBinding;
use crate::server::SyncServer;

pub(in crate::ai_host) mod checker;

/// The purpose the checks are metered and routed under, a contribution
/// check's audit of its forks too (FIX 3611).
pub(in crate::ai_host) const PURPOSE: &str = "coach_seal_check";
/// What one job's checks may spend.
const BUDGET_UNITS: u64 = 1 << 20;
/// Pending checks one job puts to a judge: a pace, as each one asked goes
/// behind the rest for the next job.
const CHECKS_PER_JOB: usize = 8;
/// The seats a check may run on, in order: the first one whose model did not
/// produce the result checks it. One hook, so a ruling on the auditor's seat
/// changes this line.
const CHECKER_ROLES: [ModelRole; 3] = [ModelRole::Checker, ModelRole::Coach, CHAT_ROLE];
/// One check's clock on the decision ladder: longer than any judge's call,
/// so the ladder cuts no answer the judge gave.
const CHECK_BUDGET: Duration = Duration::from_secs(30 * 60);

/// One `coach.seal_checks` job: the pending checks, the ones asked longest
/// ago (or never) first.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let run_id = format!(
        "coach-seal-checks:{}",
        EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?.to_hex()
    );
    let checker = HostChecker {
        server,
        models: HostModels::open(server, run_id, PURPOSE, BUDGET_UNITS)?,
    };
    let report = server
        .vault()
        .run_coach_seal_checks(admitted, &checker, CHECKS_PER_JOB, now)?;
    tracing::debug!(?report, "the Coach ran the seal's checks");
    Ok(())
}

struct HostChecker<'a> {
    server: &'a SyncServer,
    models: HostModels<'a>,
}

impl SealChecker for HostChecker<'_> {
    fn check(
        &self,
        request: &SealCheckRequest,
        executor: &str,
        now: u64,
    ) -> oneiron::Result<SealCheck> {
        let runtime = self.server.ai.model_runtime();
        let Some(role) = CHECKER_ROLES.into_iter().find(|role| {
            runtime
                .seat(*role)
                .is_some_and(|seat| independent(seat.model.as_str(), executor))
        }) else {
            return Ok(SealCheck::Unavailable);
        };
        // An output handle names its bytes; an agent run's result TURN names
        // the answer its own run recorded, read back by that output's digest
        // and length, never by the TURN's id. Any other result is unavailable.
        let source = match OutputRef::from_handle(&request.result_ref) {
            Ok(source) => source,
            Err(_) => match AgentDispatcher::new(self.server.vault())
                .agent_run_answer(request.attempt, &request.result_ref)
            {
                Ok(Some(source)) => source,
                Ok(None) => return Ok(SealCheck::Unavailable),
                Err(error) => {
                    tracing::debug!(kind = ?error.kind(), "an agent run result could not be read");
                    return Ok(SealCheck::Unavailable);
                }
            },
        };
        let bytes = match restore_output(self.server.vault(), source) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "a sealed result could not be read");
                return Ok(SealCheck::Unavailable);
            }
        };
        // A withheld body reads as its mark, which is not the result.
        if source.verify(&bytes).is_err() {
            return Ok(SealCheck::Unavailable);
        }
        // The judge reads the result whole; its length is measured, never cut.
        let result = String::from_utf8_lossy(&bytes);
        let _ = self
            .server
            .vault()
            .measure_limit(EngineLimit::MaintenanceTextBytes, result.len() as u64);
        let asked: Vec<&str> = request
            .objectives
            .iter()
            .map(|objective| objective.objective.as_str())
            .collect();
        let Some(check) =
            SealObjectiveCheck::new(request.kind, &asked, &protocol_digest(), FLAW_WORDING)?
        else {
            // One question cannot stand for two findings.
            return Ok(SealCheck::Inconclusive);
        };
        let objectives = request
            .objectives
            .iter()
            .zip(check.questions())
            .map(|(objective, question)| objective_data(request.kind, objective, question.id))
            .collect();
        let state = check_state(request.kind, objectives, &result);
        let Some(seat) = runtime.seat(role) else {
            return Ok(SealCheck::Unavailable);
        };
        let judge = SealJudge {
            models: &self.models,
            role,
            pin: ProviderPin {
                rung: DecisionRung::Big,
                model: seat.model.as_str().to_owned(),
                version: seat.model.as_str().to_owned(),
            },
            calls: Mutex::new(Vec::new()),
        };
        let bands = self.server.decision_host().bands();
        let decided = check.decide(
            self.server.vault().coach_authority()?.entity_ref(),
            &request.result_ref,
            &state,
            &SealObjectiveDecisions {
                judge: &judge,
                bands: &bands,
                budget: CHECK_BUDGET,
            },
        )?;
        let calls = judge
            .calls
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // No seat served a call: nothing was asked.
        if calls.iter().any(Option::is_none) {
            return Ok(SealCheck::Unavailable);
        }
        // One rung answers a check: a contribution check's forks are scored
        // on it alone.
        let mut bindings = calls.into_iter().flatten();
        let Some(binding) = bindings.next() else {
            return Ok(SealCheck::Inconclusive);
        };
        let one_rung = |other: &ModelCallBinding| {
            other.rung.model == binding.rung.model
                && other.rung.locality == binding.rung.locality
                && other.route == binding.route
        };
        if !bindings.all(|other| one_rung(&other)) {
            return Ok(SealCheck::Inconclusive);
        }
        let served = binding.rung.model.as_str().to_owned();
        // A fallback rung may be the executor's own model.
        if !independent(&served, executor) {
            return Ok(SealCheck::Inconclusive);
        }
        Ok(match decided {
            SealObjectiveDecision::Decided {
                findings,
                decisions,
            } => {
                tracing::debug!(
                    reference = %request.reference,
                    decisions = decisions.len(),
                    "the seal's objectives were decided on the ladder"
                );
                SealCheck::Checked {
                    outcome: SealCheckOutcome {
                        judge_revision: served,
                        checked_at: now,
                        findings,
                    },
                    // The rung that answered, as it answered: a contribution
                    // check's forks are scored on it alone.
                    protocol: CheckerProtocol {
                        digest: protocol_digest(),
                        role,
                        judge_rung: binding.route.map(|route| (binding.rung.locality, route)),
                    },
                }
            }
            SealObjectiveDecision::Inconclusive => SealCheck::Inconclusive,
        })
    }
}

/// The independent judge as the decision ladder's one Big rung
/// (DECIDE-BYPASS-2): each pack is one call on `role`'s seat, through the
/// Coach's run and meter, and its answer is read as each question's yes/no
/// weights. `calls` keeps, per call, the rung that answered it, or none
/// when no seat served it.
struct SealJudge<'a> {
    models: &'a HostModels<'a>,
    role: ModelRole,
    pin: ProviderPin,
    calls: Mutex<Vec<Option<ModelCallBinding>>>,
}

impl DecisionProvider for SealJudge<'_> {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        let pack = DecisionPack {
            questions: std::slice::from_ref(&call.question),
            evidence: call.evidence,
            images: call.images,
            audio: call.audio,
            state: call.state,
            deadline: call.deadline,
            run: call.run,
            labels: call.labels,
        };
        self.decide_pack(&pack)?.pop().ok_or_else(|| {
            oneiron::Error::InvalidConfig("a seal judge answered no question".into())
        })
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> oneiron::Result<Vec<ProviderDecision>> {
        let messages = pack_messages(pack.state, pack.questions);
        let answered = self.models.generate_recorded(self.role, messages)?;
        let decisions = match &answered {
            Some((text, binding)) => {
                // The model that served the call answered it, its fallback
                // included.
                let served = ProviderPin {
                    rung: self.pin.rung,
                    model: binding.rung.model.as_str().to_owned(),
                    version: self.pin.version.clone(),
                };
                answers(text, pack.questions, Some(&served))
            }
            None => answers("", pack.questions, None),
        };
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(answered.map(|(_, binding)| binding));
        Ok(decisions)
    }
}
