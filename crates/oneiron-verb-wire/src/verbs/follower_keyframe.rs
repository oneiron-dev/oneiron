//! Moved from `crates/oneiron/src/verbs/follower_keyframe.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The sessions marked to fold retained frames after their prepared suffix drains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerFollowerKeyframeResult {
    /// Sessions marked, not folds already completed.
    pub sessions_marked: usize,
}
