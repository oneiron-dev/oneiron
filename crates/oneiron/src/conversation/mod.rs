//! Conversation rooms, witnessed messages, and CONV-09 reactions (OF-372, ONE-1991).
//!
//! The reaction record IS the event: a REACTION (kind 107, prefix `rx`) body
//! `{v:1, msg, by, glyph, at, ext?}` with `About(10)` to the MESSAGE and
//! `AuthoredBy(0)` to the PERSON. Toggle is append-fresh or tombstone-toggle;
//! inbox and pills are derived reads over the same edges. No new edge kinds,
//! no sidecar primary state.

pub mod reaction;
pub(crate) mod visibility;

pub use self::reaction::{
    GROUPED_PILLS_MAX_MESSAGES, GROUPED_PILLS_MAX_REACTIONS, LiveReaction, REACTION_BODY_KEYS,
    REACTION_BODY_VERSION, REACTION_EXTERNAL_CONNECTOR_MAX_BYTES, REACTION_EXTERNAL_ID_MAX_BYTES,
    REACTION_GLYPH_MAX_SCALARS, REACTION_INBOX_KEY_PREFIX, ReactionBody, ReactionExternalId,
    ReactionGrouping, ReactionPill, ReactionState, decode_reaction_body, encode_reaction_body,
    validate_reaction_glyph,
};
