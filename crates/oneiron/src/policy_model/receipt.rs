//! Gate-ledger rows for policy verdicts.
//!
//! Enforcement that carries a signal is receipted; a clean allow is not. That
//! asymmetry is deliberate — the ledger records the times the engine acted, so
//! an act it never recorded is an act it never took.

use crate::Vault;
use crate::error::Result;
use crate::gate;
use crate::store::{GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord};

use super::planes::PolicyPlane;
use super::request::PolicyClassifyRequest;
use super::verdict::{PolicyClassifyVerdict, PolicyVerdictCategory};

impl Vault {
    pub(crate) fn append_policy_model_gate_receipt(
        &self,
        request: &PolicyClassifyRequest,
        verdict: &PolicyClassifyVerdict,
        outcome: &str,
        reason_codes: Vec<String>,
        system_notices: Vec<GateSystemNoticeRecord>,
    ) -> Result<String> {
        let decision_id = GateDecisionId::now();
        let mut wtxn = self.store.env.write_txn()?;
        self.store.append_gate_decision_in_txn(
            &mut wtxn,
            &GateDecisionRecord {
                version: 0,
                decision_id,
                created_at: crate::unix_seconds_now(),
                outcome: outcome.to_owned(),
                reason_codes,
                receipt_reasons: Vec::new(),
                system_notices,
                actor_class: "policy_model".to_owned(),
                actor_ref: request.caller_ref.clone(),
                content_kind: request.subject.as_str().to_owned(),
                policy_manifest_version: gate::POLICY_SCHEMA_VERSION.to_owned(),
                claim_id: None,
                grant_ref: None,
                diff_handle: verdict.binding.content_hash.to_vec(),
                read_frontier_hash: verdict.binding.read_frontier_hash,
                redacted_at: None,
            },
        )?;
        wtxn.commit()?;
        Ok(format!("gate:{}", decision_id.to_hex()))
    }
}

/// The `gate.`-namespaced trace a verdict contributes to its ledger row. The
/// gate ledger requires every reason code to sit under `gate.`, so policy and
/// relay codes both ride that prefix.
pub(crate) fn policy_model_reason_codes(verdict: &PolicyClassifyVerdict) -> Vec<String> {
    let mut reasons = vec![format!(
        "gate.policy_model.{}",
        verdict.decision.ledger_str()
    )];
    reasons.push(policy_model_category_reason(&verdict.category).to_owned());
    if let PolicyVerdictCategory::HostedLegal { category, .. } = &verdict.category {
        reasons.push(format!(
            "gate.policy_model.hosted_legal.{}",
            category.as_str()
        ));
    }
    reasons
}

fn policy_model_category_reason(category: &PolicyVerdictCategory) -> &'static str {
    match category {
        PolicyVerdictCategory::None => "gate.policy_model.plane.none",
        PolicyVerdictCategory::OwnerPolicy { .. } => plane_reason(PolicyPlane::OwnerPolicy),
        PolicyVerdictCategory::HostedLegal { .. } => plane_reason(PolicyPlane::HostedLegal),
    }
}

const fn plane_reason(plane: PolicyPlane) -> &'static str {
    match plane {
        PolicyPlane::OwnerPolicy => "gate.policy_model.plane.owner_policy",
        PolicyPlane::HostedLegal => "gate.policy_model.plane.hosted_legal",
    }
}
