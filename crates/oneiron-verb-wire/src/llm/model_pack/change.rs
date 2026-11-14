//! Moved from `crates/oneiron/src/llm/model_pack/change.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The owner's revert: the change its notice names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelPackRevertRequest {
    pub change_ref: String,
}

/// Why a revert cannot run now. Nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelPackRevertBlock {
    /// A later pack change replaced this one; its own notice reverts it.
    Superseded,
    /// The change had no pack before it: the vault's first pack.
    NoPreviousPack,
    /// The pack before the change is neither installed nor kept as the
    /// version a same-name update replaced at the bytes the change recorded,
    /// or its kept bytes no longer pass an install's checks.
    NotInstalled,
    /// The pack before the change has retired: it is no longer served.
    Retired,
    /// The hub ref the pack before the change came from is frozen to other
    /// bytes, the newer version's, so its drift check refuses the version
    /// the change recorded. The owner lifts the freeze, then reverts: the
    /// newer version stays in effect while the freeze is lifted, so the
    /// change still stands. Moving the freeze to the older bytes instead
    /// ends the newer version first, a change of its own that supersedes
    /// this one (review #6755).
    FrozenRefPinsNewer,
}
