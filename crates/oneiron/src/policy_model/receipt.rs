//! Gate-ledger rows for policy verdicts.
//!
//! A decision the owner plane made is receipted by the door that made it,
//! once: a clean allow it examined included (FIX 7805), as one hash-only row
//! with no notice, so the ledger holds every time the engine looked. A plane
//! that is off looked at nothing and records nothing, and a door that only
//! enforces a decision another door recorded writes no second row.
//!
//! Each row names no claim, so it is sealed in the vault's own key custody
//! under the policy partition (FIX 7806) rather than stored as plain
//! MessagePack; it reads back through the ledger's one decode door.
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
//! # No model prose in the ledger
//!
//! Reason codes are tokens, and so is what the ledger keeps of a model's
//! stated reason. Under a rationale-bearing output contract the reason
//! reaches the ledger as a [`GateSystemNoticeRecord`] on the `policy.audit`
//! channel with the `audit` audience (see [`policy_model_rationale_notice`]),
//! holding the decision, the row and a digest of the reason, never its words
//! (FIX 10035): a reason can quote the candidate. The words stay on the
//! verdict the caller holds. The row is addressed to the substrate owner
//! reading their own receipts, so a host rendering reader-facing notices
//! filters it out by channel rather than by inspecting bodies.
//!
//! What never reaches the ledger: the candidate, the model's reason text, the
//! pattern SOURCE TEXT and the policy DOCUMENT. Ids and categories identify a
//! rule; reproducing the rule is the substrate owner's own config surface's
//! job, not an audit row's.
//!
//! [`policy_model_rationale_notice`]: super::notice::policy_model_rationale_notice

use crate::Vault;
use crate::error::Result;
use crate::gate;
use crate::store::{GateDecisionRecord, GateSystemNoticeRecord};

use super::planes::PolicyPlane;
use super::request::PolicyClassifyRequest;
use super::verdict::{PolicyClassifyVerdict, PolicyVerdictCategory};

impl Vault {
    /// Writes a policy verdict's gate row in the caller's transaction.
    ///
    /// Every writer's PRECONDITION must still hold at write time, so each
    /// tests it in the same transaction that writes the row — the relay
    /// receipt re-checks its policy binding there, and the owner doors settle
    /// their verdict against the policy in force there, so a manifest that
    /// moved after the pass is never receipted under a binding nobody can
    /// reproduce.
    pub(super) fn append_policy_model_gate_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        request: &PolicyClassifyRequest,
        verdict: &PolicyClassifyVerdict,
        outcome: &str,
        reason_codes: Vec<String>,
        system_notices: Vec<GateSystemNoticeRecord>,
    ) -> Result<String> {
        let mut system_notices = system_notices;
        system_notices.extend(super::notice::policy_decision_receipt_notices(verdict));
        let mutation_recorded_at = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        let decision_id = crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let mut reason_codes = reason_codes;
        if verdict.decision == super::PolicyClassifyDecision::Hold {
            let queue_ref = self.queue_policy_hold_in_txn(
                wtxn,
                request,
                verdict,
                format!("gate:{}", decision_id.to_hex()),
            )?;
            reason_codes.push(format!(
                "gate.policy_model.hold_queued.{}",
                queue_ref.rsplit(':').next().expect("queue token")
            ));
        }
        self.store.append_policy_gate_decision_in_txn(
            wtxn,
            &GateDecisionRecord {
                version: 0,
                decision_id,
                created_at: mutation_recorded_at,
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
                context: Default::default(),
                redacted_at: None,
            },
        )?;
        Ok(format!("gate:{}", decision_id.to_hex()))
    }
}

/// The `gate.`-namespaced trace a verdict contributes to its ledger row. The
/// gate ledger requires every reason code to sit under `gate.`, so policy and
/// relay codes both ride that prefix.
pub(super) fn policy_model_reason_codes(verdict: &PolicyClassifyVerdict) -> Vec<String> {
    let mut reasons = vec![format!(
        "gate.policy_model.{}",
        verdict.decision.ledger_str()
    )];
    if let Some(reason) = verdict.decision.skip_reason() {
        reasons.push(format!("gate.policy_model.skip_reason.{}", reason.as_str()));
    }
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
    // tokenized here before they can shape a ledger key. What reaches this
    // point has already been cut down to rules the plane resolved, so the
    // number of rows one answer can add is bounded by the plane's own rows.
    for id in &audit.model_rule_ids {
        if let Some(token) = ledger_token(id) {
            reasons.push(format!("gate.policy_model.model_rule.{token}"));
        }
    }
    // What the model cited that resolved to nothing. The COUNT is the row, not
    // the strings: an answer can invent unboundedly many, and a ledger reader
    // still needs to know the citation list they are looking at is partial.
    if audit.model_rule_ids_dropped > 0 {
        reasons.push(format!(
            "gate.policy_model.model_rule_ids_dropped.{}",
            audit.model_rule_ids_dropped
        ));
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
