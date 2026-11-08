//! The explicit owner request to keyframe follower sessions (FIX 8532).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;

use super::EmptyRequest;

/// The sessions marked to fold retained frames after their prepared suffix drains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerFollowerKeyframeResult {
    /// Sessions marked, not folds already completed.
    pub sessions_marked: usize,
}

/// Marks the existing follower sessions under the owner's proof.
///
/// # Errors
/// An owner proof that no longer stands, or a storage error.
pub fn dreamer_follower_keyframe_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: EmptyRequest,
) -> MemoryResult<DreamerFollowerKeyframeResult> {
    Ok(DreamerFollowerKeyframeResult {
        sessions_marked: vault.dreamer_follower_keyframe(owner)?,
    })
}
