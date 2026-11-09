//! Moved from `crates/oneiron/src/dreamer_wake/sieve/rules.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Which rule flagged a span. Each class has its own confidence on the sieve
/// policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleClass {
    /// A calendar date with its numbers: `2026-10-12`, `Oct 12`, `10月12日`.
    AbsoluteDate,
    /// A time relative to the turn that the parser resolves: `last week`,
    /// `3 days ago`, `明日`.
    RelativeDate,
    /// A time the rules cannot pin: `last several weeks`, a bare weekday, a
    /// slash pair such as `3/4`.
    VagueDate,
    /// A run of capitalized words inside a sentence, or of two or more words.
    Name,
    /// One capitalized word opening a sentence: as often a plain word.
    InitialName,
    /// A katakana run: a foreign name or a loanword.
    KatakanaName,
}

impl RuleClass {
    pub const fn is_date(self) -> bool {
        matches!(
            self,
            Self::AbsoluteDate | Self::RelativeDate | Self::VagueDate
        )
    }
}
