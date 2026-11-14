//! Moved from `crates/oneiron/src/learning_setting_choice.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The four spawn fields an owner row may steer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpawnChoice {
    Model,
    Width,
    Pattern,
    Budget,
}

impl SpawnChoice {
    pub const ALL: [Self; 4] = [Self::Model, Self::Width, Self::Pattern, Self::Budget];

    /// The row key: canon's choice name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Width => "width",
            Self::Pattern => "pattern",
            Self::Budget => "budget",
        }
    }

    /// The choice a row key names, if it names one.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|choice| choice.as_str() == key)
    }
}

pub const ROW_VERSION: u8 = 1;

pub const ROW_LABEL: &str = "learning choice row";
