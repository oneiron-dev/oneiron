//! Fan-out approval policy dial and its stable wire spelling.

use serde::{Deserialize, Serialize};

/// The r5v2 approval ladder, spelled with the existing wire tokens (`auto`,
/// `full-access`, `manual`) but kept as a fan-out-specific enum so a ladder
/// move on one axis cannot silently move the other.
///
/// `Default` is derived rather than hand-written only because a hand-written
/// impl is a denied clippy lint here; the default is `auto` either way.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanoutApprovalMode {
    #[default]
    Auto,
    FullAccess,
    Manual,
}

impl FanoutApprovalMode {
    /// The canonical wire token. It is also the token hashed into the plan
    /// digest, so the mode cannot change under an approval.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::FullAccess => "full-access",
            Self::Manual => "manual",
        }
    }
}
