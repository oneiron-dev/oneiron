//! Reasons a tested revision lacks reviewed promotion.

use oneiron_base::error::Error;

/// Why a tested queue revision cannot be promoted yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueuePromotionGap {
    /// The chain's root holds untouched bytes no reviewed import admitted.
    UntouchedBytes(String),
    /// A changed path has no admitted reviewed operation covering it.
    Unreviewed(String),
}

impl QueuePromotionGap {
    pub fn error(&self) -> Error {
        Error::InvalidClaimBody(match self {
            Self::UntouchedBytes(_) => {
                "untouched imported bytes have no reviewed import admission (G4)"
            }
            Self::Unreviewed(_) => "a tested queue revision change lacks its reviewed operation",
        })
    }
}
