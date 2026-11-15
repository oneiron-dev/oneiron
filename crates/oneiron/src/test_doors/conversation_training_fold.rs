//! A person's conversation-training opt-out in a fold, for the integration
//! tests of the owner-proof rule (row CARRIER-OWNER-PROOF, ruling
//! CARRIER-PERSON-OPT-OUT): the fold's training choices are crate-private.

use crate::EntityId;
use crate::authority::AuthorityFold;

/// Whether `person`'s own opt-out is in force in the fold.
pub fn leaves_out(fold: &AuthorityFold, person: EntityId) -> bool {
    fold.conversation_training.leaves_out(person)
}
