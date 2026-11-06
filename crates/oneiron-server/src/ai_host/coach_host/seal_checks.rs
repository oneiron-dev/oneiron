//! The host's seal checker (ARCH-0079 #stuck-confession-and-the-seal,
//! OF-544): for each pending confession recheck or drawn random audit, a
//! judge that did not produce the result reads the attempt's pinned output
//! (an output handle's bytes, or the answer a resident run's result TURN
//! names) and answers, per requested objective, whether a flaw keeps it from
//! being met. A recheck shows what the agent confessed, to be examined
//! directly; a random audit shows only the objectives, so the agent's own
//! report does not steer it. The Coach pays for the calls.
use oneiron::agent_dispatch::AgentDispatcher;
use oneiron::compaction::output::{OutputRef, restore_output};
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::dreamer_runner::maintenance::seal_checks::{SealCheck, SealChecker};
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::manifest::ModelRole;
use oneiron::self_heal::audit::{SealCheckKind, SealCheckOutcome, SealCheckRequest};
use oneiron::{EntityId, LlmMessageRole};

use self::checker::{SYSTEM, independent, parse};
use super::super::CHAT_ROLE;
use super::super::code_fix::{HostModels, message};
use crate::server::SyncServer;

mod checker;

/// The purpose the checks are metered and routed under.
const PURPOSE: &str = "coach_seal_check";
/// What one job's checks may spend.
const BUDGET_UNITS: u64 = 1 << 20;
/// Pending checks one job puts to a judge: a pace, as each one asked goes
/// behind the rest for the next job.
const CHECKS_PER_JOB: usize = 8;
/// The seats a check may run on, in order: the first one whose model did not
/// produce the result checks it. One hook, so a ruling on the auditor's seat
/// changes this line.
const CHECKER_ROLES: [ModelRole; 3] = [ModelRole::Checker, ModelRole::Coach, CHAT_ROLE];

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
        let recheck = request.kind == SealCheckKind::ConfessionRecheck;
        let objectives: Vec<serde_json::Value> = request
            .objectives
            .iter()
            .map(|objective| {
                if recheck {
                    serde_json::json!({
                        "objective": objective.objective,
                        "agent_says_met": objective.met,
                        "agent_named_flaw": objective.flaw,
                        "agent_unsure_of": objective.uncertainty,
                    })
                } else {
                    serde_json::json!({ "objective": objective.objective })
                }
            })
            .collect();
        let data = serde_json::json!({
            "check": if recheck { "recheck" } else { "random_audit" },
            "objectives": objectives,
            "result": result,
        });
        let Some((text, served)) = self.models.generate_served(
            role,
            vec![
                message(LlmMessageRole::System, SYSTEM.to_owned()),
                message(LlmMessageRole::User, data.to_string()),
            ],
        )?
        else {
            return Ok(SealCheck::Unavailable);
        };
        // A fallback rung may be the executor's own model.
        if !independent(&served, executor) {
            return Ok(SealCheck::Inconclusive);
        }
        Ok(match parse(&text, request) {
            Some(findings) => SealCheck::Checked(SealCheckOutcome {
                judge_revision: served,
                checked_at: now,
                findings,
            }),
            None => SealCheck::Inconclusive,
        })
    }
}
