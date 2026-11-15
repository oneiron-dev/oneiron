//! Moved from `crates/oneiron/src/channel_identity_provider/mail_placement.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// Where a message lives in its granted mailbox. Junk takes precedence over
/// inbox when a provider supplies conflicting labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailPlacement {
    Inbox,
    Archive,
    Spam,
    Trash,
}

/// Which mailbox placements the owner has allowed this read to visit.
/// The default is inbox-only; widening archive or junk is explicit.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementPolicy {
    #[default]
    InboxOnly,
    InboxAndArchive,
    EntireMailbox,
}

impl PlacementPolicy {
    /// Whether a classified message belongs to the requested read.
    #[must_use]
    pub const fn includes(self, placement: MailPlacement) -> bool {
        match self {
            Self::InboxOnly => matches!(placement, MailPlacement::Inbox),
            Self::InboxAndArchive => {
                matches!(placement, MailPlacement::Inbox | MailPlacement::Archive)
            }
            Self::EntireMailbox => true,
        }
    }

    /// Refuse a wire response that escaped the granted placement boundary.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] if `placement` is not in this policy.
    pub fn require(self, placement: MailPlacement) -> Result<()> {
        if self.includes(placement) {
            Ok(())
        } else {
            Err(Error::InvalidConfig(format!(
                "mail wire returned {placement:?} outside {self:?} placement policy"
            )))
        }
    }
}
