//! The goal-limit bundle's frontier bytes; split from its parent hash worker.

use sha2::Sha256;

use super::{PolicyManifestResolution, hash_bytes, hash_str, hash_u64};

/// The bundle's precedence and vault limits, then, only when it has any,
/// each project- or thread-scoped row's canonical bytes, so a bundle with
/// no scoped row keeps its frontier.
pub(super) fn hash_goal_limits(hasher: &mut Sha256, resolution: &PolicyManifestResolution) {
    if let Some(limits) = &resolution.goal_limits {
        hash_str(hasher, "goal_limits");
        hash_str(hasher, limits.precedence.as_str());
        for field in limits.fields() {
            hash_u64(hasher, field);
        }
        if !limits.scoped.is_empty() {
            hash_str(hasher, "goal_limits_scoped");
        }
        for row in &limits.scoped {
            hash_bytes(hasher, &row.canonical_bytes());
        }
    }
}
