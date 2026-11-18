//! A held turn-program attempt for release tests: plant a Diverged hold as
//! the admission and the program runtime leave it, without the admission row,
//! run or checkpoint a resume would read.

use crate::error::Result;
use crate::{EdgeActorClass, EntityId, Vault};

/// Plants a Diverged-held turn-program attempt stamped as `actor`'s program
/// try (class `actor_class`). Answers the attempt's hex, the hold's exact
/// reason and its park time, as a release request names them.
///
/// # Errors
///
/// A store failure.
pub fn plant_held_turn_program_for_test(
    vault: &Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> Result<(String, String, u64)> {
    crate::dreamer_runner::turn_program_test_hooks::plant_held_program_attempt(
        vault,
        actor,
        actor_class,
    )
}
