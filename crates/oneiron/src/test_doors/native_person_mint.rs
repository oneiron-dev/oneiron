//! Door to the Dreamer's native person mint (FIX
//! NATIVE-CLAIM-LANDS-ON-ARCHIVED-PERSON): the binding and the writer an
//! extraction pass runs for a person its reply declares.

use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::{EntityId, Vault};

/// Binds and mints the one person a reply declares, named `name` and citing
/// the stored TURN `turn`, as an extraction pass does. The id is derived
/// from the extraction id (`parent` when one is given, else the first try of
/// `attempt`'s retry lineage, which is `attempt` itself when it is not a
/// queued retry), the normalized name, the TURN and where the name first
/// stands in its text; the exposure axes are absent. Two calls that agree on
/// those name one id. Neither id needs a queue row. Returns that id, whether
/// or not the writer wrote a row for it.
///
/// # Errors
///
/// A TURN that is not stored or whose stored row is shorter than its header,
/// a declaration that binds no id, and the writer's errors.
pub fn mint_named_person(
    vault: &Vault,
    attempt: AttemptId,
    parent: Option<AttemptId>,
    turn: EntityId,
    name: &str,
) -> Result<EntityId> {
    crate::dreamer_consolidation::mint_named_person_for_test(vault, attempt, parent, turn, name)
}
