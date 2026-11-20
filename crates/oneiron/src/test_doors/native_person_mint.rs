//! Door to the Dreamer's native person mint (FIX
//! NATIVE-CLAIM-LANDS-ON-ARCHIVED-PERSON): the binding and the writer an
//! extraction pass runs for a person its reply declares.

use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::{EntityId, Vault};

/// Binds and mints the one person a reply declares, named `name` and citing
/// the stored TURN `turn`, as an extraction pass does for an attempt whose
/// first try is `attempt` and whose queued parent is `parent`. The id is
/// derived from the parent (else the first try), the name and the TURN, so
/// two calls that agree on those name one id. Returns that id, whether or
/// not the writer wrote a row for it.
///
/// # Errors
///
/// A TURN that is not stored, a declaration that binds no id, and the
/// writer's errors.
pub fn mint_named_person(
    vault: &Vault,
    attempt: AttemptId,
    parent: Option<AttemptId>,
    turn: EntityId,
    name: &str,
) -> Result<EntityId> {
    crate::dreamer_consolidation::mint_named_person_for_test(vault, attempt, parent, turn, name)
}
