//! The answer the owner's confirm carries for a held machine answer, on a
//! fold, for the integration tests of the owner-proof rule (row
//! CARRIER-OWNER-PROOF, the confirm door): the confirm builds it from the
//! fold alone, and no door of this crate writes a held answer that names
//! other keys than its machine stands under, so only a hand-signed log
//! reaches that case.

use crate::EntityId;
use crate::authority::{AuthorityEntryHash, AuthorityFold, MachineProfile};
use crate::error::Result;

/// The profile [`crate::Vault::confirm_held_machine_answers`] appends for
/// the held answer `entry` as `owner`'s own answer on `fold`.
///
/// # Errors
/// As the confirm door: an entry that no longer asks, and a held answer the
/// confirm never carries.
pub fn confirming_answer(
    fold: &AuthorityFold,
    owner: EntityId,
    entry: &AuthorityEntryHash,
) -> Result<MachineProfile> {
    fold.confirming_answer(owner, entry)
}
