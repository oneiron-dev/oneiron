//! The explicit owner request to keyframe follower sessions (FIX 8532).

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;

use super::EmptyRequest;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::follower_keyframe::DreamerFollowerKeyframeResult;

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
