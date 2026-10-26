//! The goal-limit bundle's frontier bytes; split from its parent hash worker.

use sha2::Sha256;

use super::{PolicyManifestResolution, hash_str, hash_u64};

pub(super) fn hash_goal_limits(hasher: &mut Sha256, resolution: &PolicyManifestResolution) {
    if let Some(limits) = resolution.goal_limits {
        hash_str(hasher, "goal_limits");
        hash_str(hasher, limits.precedence.as_str());
        for field in limits.fields() {
            hash_u64(hasher, field);
        }
    }
}
