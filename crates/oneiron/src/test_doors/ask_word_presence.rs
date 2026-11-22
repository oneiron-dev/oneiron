//! A door for `tests/owner_presence_ask_word.rs` (row OWNER-CONFIRM-SHEET,
//! PR 4b-4): an answer on an owner-device surface whose proof is signed on
//! a presence check of a chosen importance, so the test pins that the write
//! refuses a word that approves an act under a proof signed for an ordinary
//! word. Compiled only under `--cfg oneiron_test_support`; never API.

use crate::memory::{Memory, MemoryResult};
use crate::task_verb::{TaskAskAnswer, TaskAskHandle, TaskAskWord};
use crate::world_keys::OwnerActImportance;

/// [`Memory::tasks_answer`] on `memory`, an owner-device surface, with the
/// word's proof signed on a presence check made at `importance` in place of
/// the importance the word's read derives. The write runs as the answer
/// door's own.
///
/// # Errors
///
/// The presence check's, the mint's, then the write's, as `tasks_answer`
/// answers them.
pub fn tasks_answer_asked_as(
    memory: &Memory<'_>,
    handle: &TaskAskHandle,
    word: &TaskAskWord,
    importance: OwnerActImportance,
) -> MemoryResult<TaskAskAnswer> {
    memory.tasks_answer_asked_as(handle, word, importance)
}
