//! Outbound intent wire vocabulary.
//! Entry: `OutboundIntent`.
//! Defines its own items.

pub use crate::dreamer_runner::maintenance::identity::MentionProvenance;

/// Version for the intent field contract consumed by the later dispatcher.
pub const OUTBOUND_INTENT_SCHEMA_VERSION: &str = "outbound.intent.v1";

#[doc(hidden)]
pub use oneiron_records::outbound::intent::{
    OutboundIntent, OutboundIntentDraft, OutboundRecipient, OutboundRecipientRole,
};

pub use crate::store::outbound_trigger::{OutboundIntentSource, OutboundIntentTrigger};
