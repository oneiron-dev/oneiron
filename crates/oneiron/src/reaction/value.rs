//! Reaction claim values and structural codecs are defined in the claims layer.

pub use crate::claim::reaction_record::{
    PREDICATE_CONVERSATION_REACTION, PREDICATE_CONVERSATION_REACTION_ECHO, ReactionExternalId,
    ReactionValue,
};
pub(crate) use crate::claim::reaction_record::{
    decode_echo, decode_reaction, is_reaction_claim_predicate, machine_written,
    validate_reaction_claim_structure,
};
