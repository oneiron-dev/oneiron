//! Moved from `crates/oneiron/src/vault_shape/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::vault_shape::apply::ShapeItemState;
pub use crate::vault_shape::approval::ShapeApprovalDependencies;
pub use crate::vault_shape::card::ShapeCard;
pub use crate::vault_shape::grant::ShapeGrantBound;
pub use crate::vault_shape::member::ShapePreset;
pub use crate::vault_shape::plan::ShapeChange;
pub use crate::vault_shape::plan::ShapeItemClass;
pub use crate::vault_shape::reach::REACH_LINE_MAX_CHANGES;
pub use crate::vault_shape::reach::REACH_LINE_NO_CHANGE;
pub use crate::vault_shape::reach::REACH_LINE_NONE;
pub use crate::vault_shape::reach::ShapePlanReach;
pub use crate::vault_shape::reach::ShapeReach;
pub use crate::vault_shape::reach::ShapeReachFact;
pub use crate::vault_shape::reach::ShapeReachVerdict;
pub use crate::vault_shape::run::ShapeApplyRun;
pub use crate::vault_shape::shared_setup::ShapeLearningOutcome;
pub use crate::vault_shape::shared_setup::ShapeLearningSetting;
pub use crate::vault_shape::skill::ShapeSkillSource;
use oneiron_base::error::Error;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// Longest name, id or reference a row may carry, in bytes.
pub const SHAPE_NAME_MAX_BYTES: usize = 256;

pub fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}
pub mod apply;
pub mod approval;
pub mod card;
pub mod grant;
pub mod member;
pub mod plan;
pub mod reach;
pub mod run;
pub mod seed;
pub mod shared_setup;
pub mod skill;
