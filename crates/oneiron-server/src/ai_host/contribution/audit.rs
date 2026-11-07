//! The scorer of an `Audit` anchor's contribution pair (FIX 3611). A
//! completed random audit anchors the check through the contract it froze
//! when it was admitted ([`audit_contract`]): the checker's protocol, the
//! role and the exact judge that checked the original result, the rung that
//! answered for it, and the objectives it examined. Both forks are checked
//! by that judge alone, on that rung alone: its model where it ran,
//! admitted on that role, on the route it answered on and under the route
//! prompt it answered under, by digest. That prompt goes first, as it went
//! first on the audit's own call. The checks use that protocol and those
//! objectives, each fork's answer's text in the place of the result, as the
//! audit read the step's answer. Each fork passes by the audit's own rule:
//! no finding names a flaw ([`flaw_free`]). The pair waits while the
//! checker's protocol, or the judge's route or route prompt, is not the
//! frozen one, or the audit froze no rung (`AnchorUnresolved`), or that
//! judge is not served there now (`ModelUnavailable`). No other rung or
//! role stands in. The audit's quality axis is never read as a project
//! goal's axis.

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::code_run::{
    ContributionForkScorer, ContributionReplayUnavailable, ReplayAnchor, ScoredFork,
};
use oneiron::learning::Anchor;
use oneiron::learning::honesty::SEAL_QUALITY_AXIS;
use oneiron::limit_ask::EngineLimit;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::self_heal::audit::{AuditContract, SealCheckKind, audit_contract, flaw_free};
use oneiron::skill_attribution::ContributionCandidate;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, EntityId, Error, LlmMessage,
    LlmRequest, ModelId, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

use super::{answer_text, measure};
use crate::ai_host::coach_host::seal_checks::PURPOSE;
use crate::ai_host::coach_host::seal_checks::checker::{
    audit_objective, check_messages, independent, parse, protocol_digest,
};
use crate::models::RoleCall;
use crate::server::SyncServer;

/// The stored audit's scorer for one wake pass: the server its judge is
/// served on, the runtime its calls block on, and what one fork's check may
/// spend.
pub(super) struct AuditScorer<'a> {
    pub(super) server: &'a SyncServer,
    pub(super) handle: &'a tokio::runtime::Handle,
    pub(super) fork_units: u64,
}

impl ContributionForkScorer for AuditScorer<'_> {
    /// The audit's frozen contract as the pair's rubric, and its judge and
    /// protocol as the pair's scorer, while the checker's protocol is the
    /// frozen one and its judge's frozen rung is admitted now as it
    /// answered ([`AuditScorer::admit_judge`]).
    fn resolve(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
    ) -> oneiron::Result<Result<ReplayAnchor, ContributionReplayUnavailable>> {
        let Some(contract) = candidate_contract(vault, candidate)? else {
            return Ok(Err(ContributionReplayUnavailable::AnchorUnresolved));
        };
        if contract.protocol.digest != protocol_digest() {
            return Ok(Err(ContributionReplayUnavailable::AnchorUnresolved));
        }
        // The judge is admitted as a fork's check admits it, an empty
        // answer in the place of the fork's.
        let messages = audit_messages(&contract, "");
        if let Err(unavailable) = self.admit_judge(vault, &contract, messages) {
            return Ok(Err(unavailable));
        }
        Ok(Ok(ReplayAnchor {
            rubric: rubric(&contract)?,
            scorer: format!(
                "{}/seal_check:{}",
                contract.judge_revision,
                blake3::Hash::from(contract.protocol.digest).to_hex()
            ),
        }))
    }

    /// Whether the fork's answer passes the audit: the audit's judge checks
    /// it on the audit's objectives, on its frozen rung, blind to which fork
    /// it reads, and it passes when no finding names a flaw. A contract that
    /// is not the pair's anchor, a frozen rung not admitted now, a failed
    /// call and an answer that does not examine each objective decide
    /// nothing.
    fn passes(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
        anchor: &ReplayAnchor,
        fork: &ScoredFork<'_>,
        clock: &RetrievalDeadline,
    ) -> oneiron::Result<Option<bool>> {
        let Some(contract) = candidate_contract(vault, candidate)? else {
            return Ok(None);
        };
        if rubric(&contract)? != anchor.rubric {
            return Ok(None);
        }
        let asked: Vec<&str> = contract.objectives.iter().map(String::as_str).collect();
        let answer = answer_text(fork.response);
        measure(vault, EngineLimit::ContributionJudgeAnswerBytes, &answer);
        let messages = audit_messages(&contract, &answer);
        let Some(text) = self.ask_judge(vault, &contract, messages, clock)? else {
            return Ok(None);
        };
        Ok(parse(&text, &asked, fork.receipt).map(|findings| flaw_free(&findings)))
    }
}

impl AuditScorer<'_> {
    /// `messages` admitted to the audit's judge on the rung that answered
    /// the audit (FIX 3611): its model where it ran, through the frozen
    /// role's live route, which still clamps it, as the shadow and
    /// contribution forks admit a captured rung. The ladder sent on must be
    /// that rung alone, as it is configured now
    /// (`OfferLadder::for_replay_binding`): the role's rung, else the
    /// model's raw rung (FIX 18546). It must be on the route it answered on
    /// and under the route prompt it answered under, by digest. No other
    /// rung or role stands in. A judge not served there now is
    /// `ModelUnavailable`. An audit that froze no rung, no exact rung, and
    /// a moved route or prompt are `AnchorUnresolved`.
    fn admit_judge(
        &self,
        vault: &Vault,
        contract: &AuditContract,
        messages: Vec<LlmMessage>,
    ) -> Result<RoleCall, ContributionReplayUnavailable> {
        let (Some((locality, route)), Ok(model)) = (
            &contract.protocol.judge_rung,
            ModelId::new(contract.judge_revision.clone()),
        ) else {
            return Err(ContributionReplayUnavailable::AnchorUnresolved);
        };
        let purpose = CallPurpose::Other {
            name: PURPOSE.to_owned(),
        };
        let request = LlmRequest {
            model: model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(PURPOSE.to_owned())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: *locality,
                host_keyless: false,
                host_paid: false,
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        let runtime = self.server.ai.model_runtime();
        let Ok(admission) = runtime.admit_replay(vault, contract.protocol.role, request) else {
            return Err(ContributionReplayUnavailable::ModelUnavailable);
        };
        let (request, routes) = (admission.request, admission.routes);
        // The frozen rung on the role's route, else on the model's raw
        // route (FIX 18546).
        let Some((ladder, replay)) =
            routes.exact_rung(&model, *locality, route.route_prompt_digest)
        else {
            return Err(ContributionReplayUnavailable::AnchorUnresolved);
        };
        if replay.exact_prompt_digest() != route.route_prompt_digest
            || ladder.exact_replay_route_pin().as_ref() != Some(route)
        {
            return Err(ContributionReplayUnavailable::AnchorUnresolved);
        }
        Ok(RoleCall {
            request,
            ladder: Arc::clone(ladder),
        })
    }

    /// `messages` to the audit's judge alone, on its frozen rung
    /// ([`Self::admit_judge`]), with no fallback, metered on one fork's cap
    /// the Coach pays, on the pass's clock. The rung puts its configured
    /// route prompt first, as it did on the audit's own call. `None` when
    /// that rung is not admitted now or the call failed.
    fn ask_judge(
        &self,
        vault: &Vault,
        contract: &AuditContract,
        messages: Vec<LlmMessage>,
        clock: &RetrievalDeadline,
    ) -> oneiron::Result<Option<String>> {
        let Ok(call) = self.admit_judge(vault, contract, messages) else {
            return Ok(None);
        };
        let run_id = format!("coach-contribution-audit:{}", EntityId::now().to_hex());
        let guard = vault.policy_budget_guard(
            run_id.clone(),
            self.fork_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
            BudgetExhaustionPolicy::Suspend,
            vault.coach_authority()?,
        )?;
        let run = self.server.ai.model_runtime().undeclared_run(run_id, guard);
        let may_send = || !clock.decision_time_left().is_zero();
        match self.handle.block_on(call.ladder.generate_exact_within(
            &run,
            call.request,
            None,
            &may_send,
            clock.decision_time_left(),
        )) {
            Ok(response) => Ok(Some(answer_text(&response))),
            Err(error) => {
                tracing::debug!(%error, "a contribution fork's audit was not answered");
                Ok(None)
            }
        }
    }
}

/// The audit's check of `answer`: the text alone of each objective the
/// audit examined, in its order, and `answer` in the place of the result.
fn audit_messages(contract: &AuditContract, answer: &str) -> Vec<LlmMessage> {
    let objectives = contract
        .objectives
        .iter()
        .map(String::as_str)
        .map(audit_objective)
        .collect();
    check_messages(SealCheckKind::RandomAudit, objectives, answer)
}

/// The frozen contract of the audit `candidate`'s outcome names, when the
/// candidate is that audit's: an `Audit` anchor at the audit's drawn rate,
/// on the seal's quality axis with no goal revision, for an executor the
/// audit's judge is independent of.
fn candidate_contract(
    vault: &Vault,
    candidate: &ContributionCandidate,
) -> oneiron::Result<Option<AuditContract>> {
    if candidate.axis != SEAL_QUALITY_AXIS || candidate.goal_revision.is_some() {
        return Ok(None);
    }
    let Some(contract) = audit_contract(
        vault,
        &candidate.attempt_receipt,
        &candidate.outcome_receipt,
    )?
    else {
        return Ok(None);
    };
    let anchored = matches!(
        candidate.anchor,
        Anchor::Audit { rate } if rate.to_bits() == contract.rate.to_bits()
    );
    let judged_apart = independent(&contract.judge_revision, &candidate.executor);
    Ok((anchored && judged_apart).then_some(contract))
}

/// The audit's frozen contract as a pair's rubric, whole.
fn rubric(contract: &AuditContract) -> oneiron::Result<serde_json::Value> {
    serde_json::to_value(contract)
        .map_err(|error| Error::InvalidConfig(format!("audit contract: {error}")))
}
