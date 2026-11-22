//! Doors for `tests/saved_question_outcome_lane.rs`
//! (ERASED-QUESTION-KEEPS-PERSON-CHANGED-PAIRS): the standing-question erase a
//! torn review's dissent runs (FIX 12218), which no public door reaches
//! without a critic review whose prediction triage overruled.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Erases the standing question `question` whole, in one write, as the erase
/// of a torn review erases the question its dissent saved. Gives back the
/// answer claims its receipts named, which that erase then tears.
pub fn erase_standing_question(vault: &Vault, question: EntityId) -> Result<Vec<EntityId>> {
    let mut wtxn = vault.store.env.write_txn()?;
    let answers = crate::llm::decision::questions::erase_standing_question_in_txn(
        &vault.store,
        &mut wtxn,
        question,
    )?;
    wtxn.commit()?;
    Ok(answers)
}
