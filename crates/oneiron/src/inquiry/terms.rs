//! The inquiry edge's terms (federation.md #inquiry-first-build, "Grant
//! row"; Engine ruling INQUIRE-SHAPE Q1 = A): the WORLD the member opened to
//! one company, the tier ceiling recall reads at, the check-in mode the
//! member's ladder runs in, and the keep the member allows without being
//! asked. They ride the Connect guest grant that carries the verb class
//! `inquire`, as its `inquiry_terms` body key, and nowhere else.
//!
//! Member defaults (federation.md #inquiry-first-build): tier ceiling
//! `unstamped`, mode `ask_when_unsure`, keep `task` allowed.

use super::record::InquiryKeep;
use crate::entity_id::EntityId;

/// The disclosure tier an inquiry's recall reads at (federation.md
/// #inquiry). `unstamped` is the one tier the canon names: claims that carry
/// no sensitivity stamp. A wider tier needs its own ruling, so a body naming
/// any other token refuses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum InquiryTierCeiling {
    /// Claims with no sensitivity stamp; the member default.
    #[default]
    Unstamped,
}

impl InquiryTierCeiling {
    /// The wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unstamped => "unstamped",
        }
    }

    /// The tier a wire token names.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "unstamped" => Some(Self::Unstamped),
            _ => None,
        }
    }
}

/// The check-in mode the member's ladder runs an inquiry in (ARCH-0082 #the
/// three modes). The wire tokens are the check-in modes' own (`manual`,
/// `auto`, `full-access`), so the stored terms read the same once the
/// check-in ladder's mode type is on main.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum InquiryCheckInMode {
    /// Every inquiry waits for the member. Wire token `manual`.
    AlwaysAsk,
    /// The companion's check runs: sure, it answers; unsure, the member is
    /// asked. The member default. Wire token `auto`.
    #[default]
    AskWhenUnsure,
    /// The vault answers from the opened scope without asking. Wire token
    /// `full-access`.
    NeverAsk,
}

impl InquiryCheckInMode {
    /// The wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AlwaysAsk => "manual",
            Self::AskWhenUnsure => "auto",
            Self::NeverAsk => "full-access",
        }
    }

    /// The mode a wire token names.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "manual" => Some(Self::AlwaysAsk),
            "auto" => Some(Self::AskWhenUnsure),
            "full-access" => Some(Self::NeverAsk),
            _ => None,
        }
    }
}

/// The terms one inquiry edge carries on its grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct InquiryTerms {
    /// The WORLD "What <company> can ask about": the opened scope, and the
    /// grant's only world.
    pub opened_world: EntityId,
    /// The tier recall reads the opened scope at.
    pub tier_ceiling: InquiryTierCeiling,
    /// The mode the member's check-in ladder runs an inquiry in.
    pub check_in_mode: InquiryCheckInMode,
    /// The keep the member allows without being asked: an inquiry that
    /// asks to keep more goes to the member.
    pub keep_allowed: InquiryKeep,
}

impl InquiryTerms {
    /// The member defaults over `opened_world`: tier `unstamped`, mode
    /// `ask_when_unsure`, keep `task`.
    #[must_use]
    pub fn member_defaults(opened_world: EntityId) -> Self {
        Self {
            opened_world,
            tier_ceiling: InquiryTierCeiling::default(),
            check_in_mode: InquiryCheckInMode::default(),
            keep_allowed: InquiryKeep::default(),
        }
    }
}
