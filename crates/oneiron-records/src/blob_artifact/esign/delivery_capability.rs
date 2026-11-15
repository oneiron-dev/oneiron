//! Moved from `crates/oneiron/src/blob_artifact/esign/delivery_capability.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::notice_dispatch::EsignNotice;
pub use oneiron_verb_wire::blob_artifact::esign::delivery_capability::EsignDeliveryWait;

impl EsignNotice {
    /// Whether this notice's delivery carries a signing link: an invitation
    /// or a reminder. Every other notice goes out without one.
    #[must_use]
    pub fn carries_signing_link(&self) -> bool {
        matches!(self.transition.as_str(), "invite" | "reminder")
    }
}
