//! The scorer of an `Audit` anchor's contribution pair (FIX 3611). A
//! completed random audit anchors the check through the contract it froze
//! when it was admitted ([`audit_contract`]): the checker's protocol, the
//! role and the exact judge that checked the original result, and the
//! objectives it examined. Both forks are checked by that judge alone, by
//! its exact route on that role, under that protocol, on those objectives,
//! each fork's answer's text in the place of the result, as the audit read
//! the step's answer. Each fork passes by the audit's own rule: no finding
//! names a flaw ([`flaw_free`]). The pair waits while the checker's
//! protocol is not the frozen one (`AnchorUnresolved`) or that judge is
//! not served now (`ModelUnavailable`). The audit's quality axis is never
//! read as a project goal's axis.

use std::collections::BTreeMap;

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
    LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

use super::{answer_text, measure};
use crate::ai_host::coach_host::seal_checks::PURPOSE;
use crate::ai_host::coach_host::seal_checks::checker::{
    audit_objective, check_messages, independent, parse, protocol_digest,
};
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
    /// frozen one and its judge is served now.
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
        if self.judge_route(&contract).is_none() {
            return Ok(Err(ContributionReplayUnavailable::ModelUnavailable));
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
    /// it on the audit's objectives, blind to which fork it reads, and it
    /// passes when no finding names a flaw. A contract that is not the
    /// pair's anchor, a judge not served now, a failed call and an answer
    /// that does not examine each objective decide nothing.
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
        let objectives = asked.iter().copied().map(audit_objective).collect();
        let answer = answer_text(fork.response);
        measure(vault, EngineLimit::ContributionJudgeAnswerBytes, &answer);
        let messages = check_messages(SealCheckKind::RandomAudit, objectives, &answer);
        let Some(text) = self.ask_judge(vault, &contract, messages, clock)? else {
            return Ok(None);
        };
        Ok(parse(&text, &asked, fork.receipt).map(|findings| flaw_free(&findings)))
    }
}

impl AuditScorer<'_> {
    /// The audit's judge and where it is served now, when its role has a
    /// seat and the judge's model is served.
    fn judge_route(&self, contract: &AuditContract) -> Option<(ModelId, ModelLocality)> {
        let runtime = self.server.ai.model_runtime();
        if runtime.seat(contract.protocol.role).is_none() {
            return None;
        }
        let model = ModelId::new(contract.judge_revision.clone()).ok()?;
        let (locality, _) = runtime.router()?.served(&model)?;
        Some((model, locality))
    }

    /// `messages` to the audit's judge alone: its own one-model ladder,
    /// admitted through its role's live route, which still clamps it, with
    /// no fallback, metered on one fork's cap the Coach pays, on the pass's
    /// clock. `None` when the judge is not served now or the call failed.
    fn ask_judge(
        &self,
        vault: &Vault,
        contract: &AuditContract,
        messages: Vec<LlmMessage>,
        clock: &RetrievalDeadline,
    ) -> oneiron::Result<Option<String>> {
        let Some((model, locality)) = self.judge_route(contract) else {
            return Ok(None);
        };
        let runtime = self.server.ai.model_runtime();
        let purpose = CallPurpose::Other {
            name: PURPOSE.to_owned(),
        };
        let request = LlmRequest {
            model,
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(PURPOSE.to_owned())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality,
                host_keyless: false,
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        let Ok(call) = runtime.admit_seat_bound(vault, contract.protocol.role, request) else {
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
        let run = runtime.undeclared_run(run_id, guard);
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
