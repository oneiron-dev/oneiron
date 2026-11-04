//! The host's rule rows (ARCH-0076 #fit-ask, DEC-0006): every revision of
//! every rule row the authenticated owner's reason wrote, and the erase that
//! forgets the owner who wrote it (FIX 3520). The decision ladder
//! (`llm::decision::rules`) writes, reads and answers from these rows; the
//! side-table declaration's erase hook calls the erase.
use crate::deletion::names_no_actor;
use crate::model_decision::{AnswerActor, DecisionAnswer, DecisionQuestion, HostRuleRef};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// Every revision of every rule row, keyed by the rule's id and its revision.
pub(crate) const RULES: SideTable<(EntityId, u64), HostRule, Named> =
    SideTable::new(&side_table::DECISION_HOST_RULE);

/// One revision of a rule row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostRule {
    #[serde(with = "crate::model_decision::codec::entity")]
    #[schemars(with = "String")]
    pub id: EntityId,
    /// From 1.
    pub revision: u32,
    /// The question it answers, pinned whole: a new wording, contract or version is a new
    /// question, and this row does not answer it.
    pub question: DecisionQuestion,
    /// The evidence the ask was about, in the order it was asked.
    #[serde(with = "crate::model_decision::codec::entities")]
    #[schemars(with = "Vec<String>")]
    pub evidence: Vec<EntityId>,
    pub answer: DecisionAnswer,
    /// The owner's reason, as typed.
    pub reason: String,
    /// The ask whose answer wrote this revision.
    #[serde(with = "crate::model_decision::codec::entity")]
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

/// Erasing `actor` from the rule rows (FIX 3520): every revision it wrote
/// keeps its question, evidence, answer, reason and times, and names no one.
/// A standing row still answers its question, as a row is advice and never a
/// grant; the owner's revoke still stops it. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a rule row that cannot be read.
pub(crate) fn erase_rule_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut rows = Vec::new();
    for (key, mut row) in RULES.scan(&vault.store, wtxn)? {
        if row.by.forget(*actor) {
            rows.push((key, row));
        }
    }
    for (key, row) in rows {
        RULES.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}
