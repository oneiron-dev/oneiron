//! Gate-ledger rows for policy verdicts.
//!
//! Enforcement that carries a signal is receipted; a clean allow the model
//! examined is not. That asymmetry is deliberate — the ledger records the times
//! the engine acted or declined to look, so an act it never recorded is an act
//! it never took.
//!
//! # The receipt is the policy-improvement loop
//!
//! Patterns are unreliable by construction, so the ledger carries every rule id
//! that fired even when the model went on to overrule it. A substrate owner
//! reading their own receipts can see which of their patterns escalate clean
//! content, which categories the model keeps naming, and how confident it was —
//! and can then fix the policy that produced all of it. That is the whole
//! reason these codes are as detailed as they are.
//!
//! # The one prose the ledger does carry
//!
//! Reason codes are tokens, but a gate row also carries system notices — and
//! one of them is prose. Under a rationale-bearing output contract the model's
//! own stated reason reaches the ledger as a [`GateSystemNoticeRecord`] on the
//! `policy.audit` channel with the `audit` audience (see
//! [`policy_model_rationale_notice`]), bounded to the ledger's body limit and
//! otherwise untouched. It is addressed to the substrate owner reading their
//! own receipts, not to the person or the model, so a host rendering reader-
//! facing notices filters it out by channel rather than by inspecting bodies.
//!
//! What never reaches the ledger: the pattern SOURCE TEXT and the policy
//! DOCUMENT. Ids and categories identify a rule; reproducing the rule is the
//! substrate owner's own config surface's job, not an audit row's.
//!
//! [`policy_model_rationale_notice`]: super::notice::policy_model_rationale_notice

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
    let Some(audit) = verdict.audit.as_deref() else {
        return reasons;
    };
    // Substrate-owner rule ids were validated to a tokenized charset at
    // registration, so they ride into a reason code as written.
    for id in &audit.matched_pattern_ids {
        reasons.push(format!("gate.policy_model.pattern_matched.{id}"));
    }
    if let Some(role) = audit.acting_pattern_role {
        reasons.push(format!("gate.policy_model.pattern_role.{}", role.as_str()));
    }
    // Model-supplied strings were never validated by anyone, so they are
    // tokenized here before they can shape a ledger key.
    for id in &audit.model_rule_ids {
        if let Some(token) = ledger_token(id) {
            reasons.push(format!("gate.policy_model.model_rule.{token}"));
        }
    }
    if let Some(token) = audit.model_confidence.as_deref().and_then(ledger_token) {
        reasons.push(format!("gate.policy_model.model_confidence.{token}"));
    }
    reasons
}

/// Longest model-supplied token a reason code will carry.
const LEDGER_TOKEN_MAX_LEN: usize = 64;

/// Folds a model-supplied string into something a ledger reader can key on:
/// lowercase, ascii alphanumeric plus `_`, `-` and `.`, everything else
/// collapsed to a single `_`, bounded. Returns `None` when nothing usable is
/// left, so an unreadable label leaves no row rather than an empty one.
fn ledger_token(value: &str) -> Option<String> {
    let mut token = String::with_capacity(value.len().min(LEDGER_TOKEN_MAX_LEN));
    for ch in value.chars() {
        if token.len() >= LEDGER_TOKEN_MAX_LEN {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            token.push(ch.to_ascii_lowercase());
        } else if !token.ends_with('_') {
            token.push('_');
        }
    }
    let token = token.trim_matches('_').to_owned();
    (!token.is_empty()).then_some(token)
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
