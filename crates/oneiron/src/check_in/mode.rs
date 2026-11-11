//! The three check-in modes and their stable wire tokens.

use serde::{Deserialize, Serialize};

/// The three check-in modes (ARCH-0082 #modes). "Never allow" is not a mode
/// (it is a power switched off), and "propose" is not one either (an actor
/// without the power opens a proposal).
///
/// The wire tokens are the fan-out's existing ones (`manual`, `auto`,
/// `full-access`). They are stored in policy-manifest rows and hashed into
/// frozen fan-out plan digests, so they do not move with the Rust names.
///
/// `Default` is derived rather than hand-written only because a hand-written
/// impl is a denied clippy lint here; the default is `AskWhenUnsure`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum CheckInMode {
    /// The act waits for a proof from the ladder. Wire token `manual`.
    #[serde(rename = "manual")]
    AlwaysAsk,
    /// The decision-model check runs. Sure: go. Unsure, refusal or error:
    /// ask. Wire token `auto`.
    #[default]
    #[serde(rename = "auto")]
    AskWhenUnsure,
    /// The act goes, with a receipt and an undo where one exists. Wire token
    /// `full-access`.
    #[serde(rename = "full-access")]
    NeverAsk,
}

impl CheckInMode {
    /// Every mode, strictest first.
    pub const ALL: [Self; 3] = [Self::AlwaysAsk, Self::AskWhenUnsure, Self::NeverAsk];

    /// The wire token. It is also the token hashed into a fan-out plan
    /// digest, so the mode cannot change under an approval.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AlwaysAsk => "manual",
            Self::AskWhenUnsure => "auto",
            Self::NeverAsk => "full-access",
        }
    }

    /// The meet: the stricter of two modes. `AlwaysAsk` beats
    /// `AskWhenUnsure`, which beats `NeverAsk`.
    #[must_use]
    pub const fn stricter(self, other: Self) -> Self {
        match (self, other) {
            (Self::AlwaysAsk, _) | (_, Self::AlwaysAsk) => Self::AlwaysAsk,
            (Self::AskWhenUnsure, _) | (_, Self::AskWhenUnsure) => Self::AskWhenUnsure,
            (Self::NeverAsk, Self::NeverAsk) => Self::NeverAsk,
        }
    }
}
