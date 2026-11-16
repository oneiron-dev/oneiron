//! Moved from `crates/oneiron/src/channel_identity_provider/line_adapter.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// LINE Messaging API plan tier used for quota-aware runtime manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineOfficialAccountPlanTier {
    Free,
    Paid,
    Enterprise,
}

impl LineOfficialAccountPlanTier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Paid => "paid",
            Self::Enterprise => "enterprise",
        }
    }
}
