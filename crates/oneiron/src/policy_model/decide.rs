//! Registered owner and hosted policy questions through the shared ladder.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::llm::decision::catalogue::{POLICY_HOSTED_ROW, POLICY_OWNER_ROW};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, HeldLadder, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Error, Result};

use super::binding::PolicyContentBinding;
use super::planes::PolicyPlane;
use super::prompt::{AnswerPlane, PolicyClassifyPrompt, decision_severity};
use super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::verdict::{
    PolicyClassifyVerdict, PolicyConfidence, PolicyHedgeBucket, PolicyPassAudit, PolicySkipReason,
    PolicyVerdictCategory,
};

/// One host-selected ladder snapshot for a policy plane. The host supplies its
/// providers, principal, ceiling, learned bands and clock budget. Nothing is
/// selected or enabled by default. `revision` identifies the complete provider
/// and band snapshot and must advance when either changes. `wording` asks
/// whether the candidate violates the following row; the engine adds only the
/// row itself, never an instruction of its own.
#[derive(Clone)]
pub struct PolicyDecisions {
    ladder: Arc<HeldLadder>,
    principal: EntityId,
    dial: DecisionDial,
    bands: DecisionBandPolicy,
    revision: String,
    wording: String,
    budget: Duration,
}

impl std::fmt::Debug for PolicyDecisions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyDecisions")
            .field("principal", &self.principal)
            .field("dial", &self.dial)
            .field("revision", &self.revision)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl PolicyDecisions {
    pub fn new(
        ladder: Arc<HeldLadder>,
        principal: EntityId,
        dial: DecisionDial,
        bands: DecisionBandPolicy,
        revision: String,
        wording: String,
        budget: Duration,
    ) -> Result<Self> {
        dial.band.validate()?;
        if dial.first > dial.ceiling || revision.trim().is_empty()
            || wording.trim().is_empty() || budget.is_zero()
        {
            return Err(Error::InvalidConfig("invalid policy decision configuration".into()));
        }
        Ok(Self { ladder, principal, dial, bands, revision, wording, budget })
    }

    /// A cached verdict cannot survive a change to this plane's ladder.
    pub(super) fn binding(&self) -> String {
        let slots = [
            self.ladder.rule.as_ref(),
            self.ladder.local.as_ref(),
            self.ladder.system_one.as_ref(),
            self.ladder.escalation.as_ref(),
            self.ladder.big.as_ref(),
        ];
        let pins: Vec<_> = slots.into_iter().map(|slot| slot.map(|provider| provider.pin())).collect();
        let value = serde_json::json!({
            "revision": self.revision,
            "principal": self.principal.to_hex(),
            "dial": self.dial,
            "wording": self.wording,
            "providers": pins,
            "queue": self.ladder.human_pin,
            "person_question": self.ladder.person,
            "budget_nanos": self.budget.as_nanos().to_string(),
        });
        blake3::hash(value.to_string().as_bytes()).to_hex().to_string()
    }

    pub(super) fn classify(
        &self,
        request: &PolicyClassifyRequest,
        prompt: &PolicyClassifyPrompt,
        plane: AnswerPlane<'_>,
        binding: PolicyContentBinding,
        config: &PolicyModelConfig,
        mut audit: PolicyPassAudit,
    ) -> Result<PolicyClassifyVerdict> {
        let (plane_id, family) = match &plane {
            AnswerPlane::Owner => (PolicyPlane::OwnerPolicy, POLICY_OWNER_ROW),
            AnswerPlane::Hosted(_) => (PolicyPlane::HostedLegal, POLICY_HOSTED_ROW),
        };
        if prompt.rubric_rows.is_empty() {
            return Ok(PolicyClassifyVerdict::clean_allow(binding, config, plane_id).with_audit(audit));
        }
        let document_hash = blake3::hash(prompt.system.as_bytes());
        let questions = prompt.rubric_rows.iter().map(|row| {
            family.question(
                &[document_hash.as_bytes(), row.row_ref.as_bytes(), row.action.as_str().as_bytes()],
                format!("{}\n{}", self.wording, row.text),
                AnswerContract::Noul,
            )
        }).collect::<Result<Vec<_>>>()?;
        // Never cut the policy or candidate to fit: a model must not clear a
        // candidate it only partly read. The ladder refuses an oversized state.
        let state = serde_json::json!({
            "subject": request.subject.as_str(),
            "content": prompt.user,
            "world_ref": request.world_ref,
            "project_ref": request.project_ref,
            "policy_document": prompt.system,
            "policy_rows": prompt.rubric_rows.iter().map(|row| serde_json::json!({
                "row_ref": row.row_ref, "action": row.action.as_str(), "why": row.why,
            })).collect::<Vec<_>>(),
        });
        let deadline = RetrievalDeadline::hard(Instant::now(), self.budget);
        let ladder = self.ladder.ladder();
        let decisions = ladder.run_pack(
            &questions.iter().collect::<Vec<_>>(),
            self.principal,
            &[],
            &state,
            self.dial,
            &self.bands,
            Reversibility::OutboundEffect,
            &deadline,
        );
        let decisions = match decisions {
            Ok(decisions) => decisions,
            Err(_) => return Ok(PolicyClassifyVerdict::skipped(
                PolicySkipReason::BackendUnavailable, binding, config, plane_id,
            ).with_audit(audit)),
        };
        audit.typed_decisions = decisions;
        // An unfinished row is not a clean answer for the whole policy. The
        // owner fails open visibly; the hosted caller degrades and applies
        // its own outage posture. A queued ladder ask never grants a permit.
        if audit.typed_decisions.iter().any(|decision| {
            !matches!(decision.answer, DecisionAnswer::Noul(_))
        }) {
            return Ok(PolicyClassifyVerdict::skipped(
                PolicySkipReason::ResponseUnusable, binding, config, plane_id,
            ).with_audit(audit));
        }
        let mut governing = None;
        for (row, decision) in prompt.rubric_rows.iter().zip(&audit.typed_decisions) {
            if decision.answer == DecisionAnswer::Noul(true) {
                audit.model_rule_ids.push(row.row_ref.clone());
                if governing.as_ref().is_none_or(|(old, _): &(&super::planes::PolicyRubricRow, f64)| {
                    decision_severity(row.action) > decision_severity(old.action)
                }) {
                    governing = Some((row, decision.probability.unwrap_or_default()));
                }
            }
        }
        let Some((row, probability)) = governing else {
            return Ok(PolicyClassifyVerdict::clean_allow(binding, config, plane_id).with_audit(audit));
        };
        let category = match plane {
            AnswerPlane::Owner => PolicyVerdictCategory::OwnerPolicy { row_ref: row.row_ref.clone() },
            AnswerPlane::Hosted(policy) => {
                let registered = policy.rows.iter().find(|registered| registered.row_ref == row.row_ref)
                    .ok_or_else(|| Error::InvalidConfig("policy decision named an unregistered row".into()))?;
                PolicyVerdictCategory::HostedLegal {
                    category: registered.category.clone(),
                    jurisdiction: policy.jurisdiction.clone(),
                    policy_version: policy.version.clone(),
                    row_ref: registered.row_ref.clone(),
                }
            }
        };
        let confidence = PolicyConfidence {
            calibrated: probability as f32,
            hedge_bucket: if probability >= f64::from(PolicyConfidence::HIGH.calibrated) {
                PolicyHedgeBucket::High
            } else if probability >= f64::from(PolicyConfidence::MEDIUM.calibrated) {
                PolicyHedgeBucket::Medium
            } else {
                PolicyHedgeBucket::Low
            },
        };
        Ok(PolicyClassifyVerdict::new(row.action, category, confidence, binding, config, plane_id)
            .with_audit(audit))
    }
}
