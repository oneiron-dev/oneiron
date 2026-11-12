//! Moved from `crates/oneiron/src/store/decision_rule_rows.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::model_decision::AnswerActor;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::DecisionQuestion;
use oneiron_store::model_decision::HostRuleRef;
use serde::Deserialize;
use serde::Serialize;

/// One revision of a rule row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostRule {
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    #[schemars(with = "String")]
    pub id: EntityId,
    /// From 1.
    pub revision: u32,
    /// The question it answers, pinned whole: a new wording, contract or version is a new
    /// question, and this row does not answer it.
    pub question: DecisionQuestion,
    /// The evidence the ask was about, in the order it was asked.
    #[serde(with = "oneiron_store::model_decision::codec::entities")]
    #[schemars(with = "Vec<String>")]
    pub evidence: Vec<EntityId>,
    pub answer: DecisionAnswer,
    /// The owner's reason, as typed.
    pub reason: String,
    /// The ask whose answer wrote this revision.
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    #[schemars(with = "String")]
    pub ask: EntityId,
    pub ask_seq: u64,
    /// The owner who wrote it; erased once that owner was erased (FIX 3520).
    #[serde(with = "crate::store::decision_ask_role::answer_actor")]
    #[schemars(with = "String")]
    pub by: AnswerActor,
    /// Vault clock seconds when it was written.
    pub written_at: u64,
    /// Vault clock seconds when the owner revoked it; none while it stands.
    pub revoked_at: Option<u64>,
}

impl HostRule {
    #[must_use]
    pub fn rule_ref(&self) -> HostRuleRef {
        HostRuleRef {
            id: self.id,
            revision: self.revision,
        }
    }
}
