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

#[doc(hidden)]
pub use oneiron_verb_wire::store::decision_rule_rows::HostRule;

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
