//! Moved from `crates/oneiron/src/counterparty_contact/trusted_contact_notice.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::counterparty_contact::trusted_contact_notice::TrustedContactNoticeAuthorization;
use serde::Deserialize;
use serde::Serialize;

/// Everything the host needs to send one notice, and what authorized it,
/// and nothing from the turn or the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactNotice {
    /// The send's own ref: one per fire, so a later crisis is a new send and
    /// never the replay of an old one.
    pub fire: String,
    pub person: String,
    pub contact: String,
    pub version: u64,
    pub sender: String,
    pub channel: String,
    pub verb: String,
    pub target: String,
    pub authorization: TrustedContactNoticeAuthorization,
}
