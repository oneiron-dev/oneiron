//! Provider-neutral mailbox placement and read policy.
//!
//! A host maps provider labels to these facts before returning a page. The
//! engine never receives Gmail API flags or trusts a wire response whose
//! placement is outside the policy that was requested.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

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
                "gmail wire returned {placement:?} outside {self:?} placement policy"
            )))
        }
    }
}
