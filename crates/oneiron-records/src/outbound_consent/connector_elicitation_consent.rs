//! Moved from `crates/oneiron/src/outbound_consent/connector_elicitation_consent.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The action class a stop-asking press remembers (FIX 8808).
pub const CONNECTOR_ELICITATION_ANSWER_ACTION: &str = "outbound.connector_elicitation_answer";

/// The derivation domain of the once digest an owner's press binds.
pub const CONNECTOR_ELICITATION_CONSENT_DOMAIN: &[u8] =
    b"oneiron:connector-elicitation-owner-consent:v1";
