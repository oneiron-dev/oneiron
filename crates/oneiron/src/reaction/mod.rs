//! Message reactions as `conversation.reaction` claims (OF-372).
//!
//! A reaction is a CLAIM, not an entity kind: packs add predicates, not entity
//! types (ARCH-0003), as `annotation.comment` and `calendar.attendee` do. One
//! claim says that a PERSON reacted with a glyph to a conversation record:
//!
//! * subject: the MESSAGE (or DAG TURN) reacted to;
//! * value: `{glyph, occurredAt, by, externalId?}`, where `by` is the reacting
//!   person and `externalId` the connector's provider generation;
//! * author: the reacting person on a first-party write; a mirrored write is
//!   attested by the engine's conversation-mirror MACHINE and signed.
//!
//! One live reaction per (message, person, glyph). A repeat put is idempotent,
//! a remove retracts the live claim, a re-add is a new claim in the same
//! chain, and the whole toggle history stays readable in order. Claims give
//! author, scope, lifecycle, sync and erase; this module adds only the chain
//! rule, the connector doors, the grouped reads and the agent signal feed.
//!
//! Audience is the reacted record's room audience: a reaction claim resolves
//! its room through its subject, so threads inherit their room, and the
//! audience rule also requires the reacted record itself to be readable.
mod chain;
mod erase;
mod mirror;
mod outbound;
mod read;
mod signal;
mod value;
mod write;

pub(crate) use erase::{
    erase_reaction_claims, person_reaction_claims_in, record_reaction_claims_in,
};
pub(crate) use mirror::ensure_conversation_mirror_actor;
pub use mirror::{ReactionIngress, conversation_mirror_actor_id};
pub use outbound::{
    REACTION_OUTBOUND_ATTEMPT_KIND, ReactionOutboundAttempt, connector_declares_reaction_target,
};
pub(crate) use read::grouped_lines_in;
pub use read::{REACTIONS_FIELD, ReactionHistoryEntry, ReactionPill, reaction_line};
pub use signal::{
    MAX_REACTION_SIGNAL_PAGE, ReactionSignal, ReactionSignalPage, page_reaction_signals,
};
pub use value::{
    PREDICATE_CONVERSATION_REACTION, PREDICATE_CONVERSATION_REACTION_ECHO, ReactionExternalId,
    ReactionValue,
};
pub(crate) use value::{is_reaction_claim_predicate, validate_reaction_claim_structure};
pub(crate) use write::REACTION_STANDALONE_WEIGHT;
pub use write::{ReactionChange, ReactionInput, ReactionState};

#[cfg(test)]
mod tests;
