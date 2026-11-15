//! A person's conversation-training opt-out in a fold, for the integration
//! tests of the owner-proof rule (row CARRIER-OWNER-PROOF, rulings
//! CARRIER-PERSON-OPT-OUT and CARRIER-PERSON-OPT-BACK-IN): the fold's
//! training choices are crate-private.

use crate::EntityId;
use crate::authority::AuthorityFold;

/// Whether `person`'s own opt-out is in force in the fold.
pub fn leaves_out(fold: &AuthorityFold, person: EntityId) -> bool {
    fold.conversation_training.leaves_out(person)
}

/// `person`'s choice revision in the fold: what their next choice names as
/// `seen`, zero while they have no live choice.
pub fn training_revision(fold: &AuthorityFold, person: EntityId) -> [u8; 32] {
    fold.conversation_training.revision(person).0
}
