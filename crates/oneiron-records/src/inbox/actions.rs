//! Moved from `crates/oneiron/src/inbox/actions.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One tap a notification offers: the registered verb it calls and that
/// verb's own input, so a client renders the button the engine describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAction {
    /// The registered verb the tap calls.
    pub verb: String,
    /// The verb's input, as its own fields name it.
    pub args: serde_json::Value,
}

impl NotificationAction {
    fn new(verb: &str, args: serde_json::Value) -> Self {
        Self {
            verb: verb.to_owned(),
            args,
        }
    }
}
