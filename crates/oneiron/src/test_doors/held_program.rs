//! A held turn-program attempt for release tests: plant a Diverged hold as
//! the admission and the program runtime leave it, without the run or
//! checkpoint a resume would read; or one whose stamp binds no admission.

use crate::dreamer_runner::turn_program_test_hooks::{
    HeldProgramAdmission, plant_held_program_attempt,
};
use crate::error::Result;
use crate::{EdgeActorClass, EntityId, Vault};

/// Plants a Diverged-held turn-program attempt stamped as `actor`'s program
/// try (class `actor_class`), with the admission that queued it as its
/// program's root try, sealed for `actor`. Answers the attempt's hex, the
/// hold's exact reason and its park time, as a release request names them.
///
/// # Errors
///
/// A store failure.
pub fn plant_held_turn_program_for_test(
    vault: &Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> Result<(String, String, u64)> {
    plant_held_program_attempt(vault, actor, actor_class, HeldProgramAdmission::Bound)
}

/// Plants the same held attempt with a stamp that names `actor` but an
/// admission no row holds: no program read finds a program there. Answers
/// as [`plant_held_turn_program_for_test`].
///
/// # Errors
///
/// A store failure.
pub fn plant_unbound_held_turn_program_for_test(
    vault: &Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> Result<(String, String, u64)> {
    plant_held_program_attempt(vault, actor, actor_class, HeldProgramAdmission::Absent)
}
