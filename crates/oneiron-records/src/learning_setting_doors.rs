//! Moved from `crates/oneiron/src/learning_setting_doors.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::learning_setting::SettingMode;
pub use oneiron_verb_wire::learning_setting_doors::LearningSettingClear;
pub use oneiron_verb_wire::learning_setting_doors::LearningSettingMode;
pub use oneiron_verb_wire::learning_setting_doors::LearningSettingScope;
pub use oneiron_verb_wire::learning_setting_doors::LearningSettingSpecView;
pub use oneiron_verb_wire::learning_setting_doors::LearningSettingsRequest;
use serde::Deserialize;
use serde::Serialize;

impl From<LearningSettingMode> for SettingMode {
    fn from(mode: LearningSettingMode) -> Self {
        match mode {
            LearningSettingMode::Seed => Self::Seed,
            LearningSettingMode::Pin => Self::Pin,
        }
    }
}
