//! Door to a guest ask's disclosure check (L7-02): the facts an ask may
//! show a guest, judged as the ask's admission judges them.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::task_verb::{TaskAskGuest, TaskAskSpec};
use crate::{EntityId, Vault};

/// Judges `spec`, an ask by `asker` that shows its facts to `person`, a guest
/// with `guest`'s companion and owner-recorded disclosure grant: the facts
/// the ask discloses, or the ask's refusal.
///
/// # Errors
///
/// The check's refusal, and storage errors.
pub fn check_disclosure(
    vault: &Vault,
    person: EntityId,
    asker: EntityId,
    guest: &TaskAskGuest,
    spec: &TaskAskSpec,
) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::task_verb::check_disclosure(vault, &txn, person, asker, guest, spec)
}
