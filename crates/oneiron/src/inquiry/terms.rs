//! The inquiry edge's terms (federation.md #inquiry-first-build, "Grant
//! row"; Engine ruling INQUIRE-SHAPE Q1 = A): the WORLD the member opened to
//! one company, the tier ceiling recall reads at, the check-in mode the
//! member's ladder runs an inquiry in for each keep, and the keep the member
//! allows without being asked. They ride the Connect guest grant that
//! carries the verb class `inquire`, as its `inquiry_terms` body key, and
//! nowhere else.
//!
//! The modes per keep are the member's saved decisions for this asker
//! (federation.md #inquiry-checkin: "answer from the scope without asking
//! me, never answer, or always ask me"; "A row is keyed by the keep terms";
//! Engine ruling INQUIRE-STANDING = A, FIX INQUIRY-STANDING-PER-KEEP).
//!
//! Member defaults (federation.md #inquiry-first-build, #inquiry-copy): tier
//! ceiling `unstamped`; mode `auto` for a `task` inquiry and `manual` for a
//! `copy` inquiry, which the member answers until they save a mode for it;
//! keep `task` allowed.

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
/// three modes), or the member's saved "never answer". The ladder's three
/// wire tokens are the check-in modes' own (`manual`, `auto`,
/// `full-access`); `never` is the inquiry's fourth.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum InquiryCheckInMode {
    /// Never answer: the inquiry settles `no_answer` at once, with neither
    /// the companion nor the member reached, and the edge stays. Wire token
    /// `never`.
    NeverAnswer,
    /// Every inquiry waits for the member. Wire token `manual`.
    AlwaysAsk,
    /// The companion's check runs: sure, it answers; unsure, the member is
    /// asked. Wire token `auto`.
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
            Self::NeverAnswer => "never",
            Self::AlwaysAsk => "manual",
            Self::AskWhenUnsure => "auto",
            Self::NeverAsk => "full-access",
        }
    }

    /// The mode a wire token names.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "never" => Some(Self::NeverAnswer),
            "manual" => Some(Self::AlwaysAsk),
            "auto" => Some(Self::AskWhenUnsure),
            "full-access" => Some(Self::NeverAsk),
            _ => None,
        }
    }

    /// How far the vault answers without the member: `never` least, then
    /// `manual`, `auto` and `full-access`.
    const fn reach(self) -> u8 {
        match self {
            Self::NeverAnswer => 0,
            Self::AlwaysAsk => 1,
            Self::AskWhenUnsure => 2,
            Self::NeverAsk => 3,
        }
    }

    /// Whether this mode answers without the member no further than
    /// `other` does.
    #[must_use]
    pub const fn is_within(self, other: Self) -> bool {
        self.reach() <= other.reach()
    }
}

/// The check-in mode for each keep an inquiry may ask for: the member's
/// saved decision for this asker, keyed by the keep terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct InquiryKeepModes {
    /// The mode of an inquiry with keep `task`.
    pub task: InquiryCheckInMode,
    /// The mode of an inquiry with keep `copy`.
    pub copy: InquiryCheckInMode,
}

impl Default for InquiryKeepModes {
    /// The member defaults: `auto` for `task`, `manual` for `copy`.
    fn default() -> Self {
        Self {
            task: InquiryCheckInMode::AskWhenUnsure,
            copy: InquiryCheckInMode::AlwaysAsk,
        }
    }
}

impl InquiryKeepModes {
    /// `mode` for every keep.
    #[must_use]
    pub const fn uniform(mode: InquiryCheckInMode) -> Self {
        Self {
            task: mode,
            copy: mode,
        }
    }

    /// The mode saved for `keep`.
    #[must_use]
    pub const fn mode_for(self, keep: InquiryKeep) -> InquiryCheckInMode {
        match keep {
            InquiryKeep::Task => self.task,
            InquiryKeep::Copy => self.copy,
        }
    }

    /// Whether every keep's mode is within `other`'s.
    #[must_use]
    pub const fn is_within(self, other: Self) -> bool {
        self.task.is_within(other.task) && self.copy.is_within(other.copy)
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
    /// The mode the member's check-in ladder runs an inquiry in, for each
    /// keep.
    pub check_in_modes: InquiryKeepModes,
    /// The keep the member allows without being asked: the outer bound of
    /// the modes. An inquiry that asks to keep more goes to the member,
    /// unless its keep's mode is `never`.
    pub keep_allowed: InquiryKeep,
}

impl InquiryTerms {
    /// The member defaults over `opened_world`: tier `unstamped`, modes
    /// `auto` for `task` and `manual` for `copy`, keep `task`.
    #[must_use]
    pub fn member_defaults(opened_world: EntityId) -> Self {
        Self {
            opened_world,
            tier_ceiling: InquiryTierCeiling::default(),
            check_in_modes: InquiryKeepModes::default(),
            keep_allowed: InquiryKeep::default(),
        }
    }

    /// The mode the ladder runs an inquiry that asks for `keep` in: the
    /// mode saved for that keep, at most `manual` when `keep` asks for more
    /// than `keep_allowed`.
    #[must_use]
    pub fn mode_for(&self, keep: InquiryKeep) -> InquiryCheckInMode {
        let mode = self.check_in_modes.mode_for(keep);
        if keep_exceeds(keep, self.keep_allowed) && !mode.is_within(InquiryCheckInMode::AlwaysAsk) {
            return InquiryCheckInMode::AlwaysAsk;
        }
        mode
    }

    /// Whether these terms answer without the member no further than
    /// `other` do, over the same opened WORLD and tier: every keep's mode
    /// within `other`'s, and no wider keep allowed.
    #[must_use]
    pub fn is_narrowing_of(&self, other: &Self) -> bool {
        self.opened_world == other.opened_world
            && self.tier_ceiling == other.tier_ceiling
            && self.check_in_modes.is_within(other.check_in_modes)
            && !keep_exceeds(self.keep_allowed, other.keep_allowed)
    }
}

/// Whether `keep` asks for more than `allowed`: a copy where only the task
/// is allowed.
const fn keep_exceeds(keep: InquiryKeep, allowed: InquiryKeep) -> bool {
    matches!((keep, allowed), (InquiryKeep::Copy, InquiryKeep::Task))
}
