//! Moved from `crates/oneiron/src/mail_pack/importer.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How much one step reads from the provider. The host sets its cadence;
/// these bound one step so many sources share a host fairly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSyncBudget {
    /// Change feed pages.
    pub history_pages: u32,
    /// Newest-first listing pages.
    pub list_pages: u32,
    /// Bodies filled in.
    pub bodies: u32,
    /// Opened attachments fetched.
    pub attachments: u32,
}

impl Default for MailSyncBudget {
    fn default() -> Self {
        Self {
            history_pages: 10,
            list_pages: 2,
            bodies: 50,
            attachments: 10,
        }
    }
}
