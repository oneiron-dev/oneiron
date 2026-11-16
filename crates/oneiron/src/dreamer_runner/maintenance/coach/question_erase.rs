//! The person-changed tables' question scrub (FIX
//! ERASED-QUESTION-KEEPS-PERSON-CHANGED-PAIRS). A question teardown that drops
//! a question version, or the whole question, drops in the same write every
//! override record of that version, in both the person and think tables. A
//! record that stayed would outlive its question's head, and the
//! person-changed pairs would then read the erased question as one no one
//! saved and pair its records with no lane to judge them. Read marks stay, as
//! the actor scrub keeps them, so a replay cannot resurrect a record.

use super::{PERSON_CHANGED, think_threshold::THINK_MISSED};
use crate::store::Store;
use crate::{EntityId, Result};

/// Drops each person-changed and quick-pick record whose question version
/// `erased(question, version)` names, in the caller's write. Every teardown
/// of a question version calls it: the standing-question erase, the
/// one-answer cascade of an erased answer claim, and the unit and principal
/// legs of an actor's erase.
pub(crate) fn erase_person_changed_question_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    erased: impl Fn(EntityId, u32) -> bool,
) -> Result<()> {
    for (source, record) in PERSON_CHANGED.scan(store, txn)? {
        if erased(record.question, record.question_version) {
            PERSON_CHANGED.delete(store, txn, &source)?;
        }
    }
    for (source, record) in THINK_MISSED.scan(store, txn)? {
        if erased(record.question, record.question_version) {
            THINK_MISSED.delete(store, txn, &source)?;
        }
    }
    Ok(())
}
