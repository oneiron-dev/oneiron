//! Cross-cutting types shared by every `serialize` submodule.

use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::registry::{
    ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_PLACE, ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_SKILL, ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_TURN,
};

pub(super) const GROUP_ORDER: &[u8] = &[
    ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_TURN,
    ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_EVENT,
    ENTITY_TYPE_PERSON,
    ENTITY_TYPE_COMPANION_REGISTER,
    ENTITY_TYPE_PSYCH_PROFILE,
    ENTITY_TYPE_SKILL,
    ENTITY_TYPE_ASSET_TEXT,
    ENTITY_TYPE_PLACE,
];
/// Grouping key for one serialized section.
///
/// Deliberately NOT a `u8`. The catch-all bucket used to be the sentinel
/// `OTHER_ENTITY_TYPE = u8::MAX`, which made byte 255 read as a static kind
/// allocation — byte-space v3 forbids exactly that (255 is the reserved
/// sentinel, and the conformance oracle scans for static constants in
/// 128–255). The bucket is now a variant, so it cannot collide with any byte.
/// Derived `Ord` puts `Kind(_)` before `Other`, preserving the old sort where
/// the 255 sentinel trailed every real kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum GroupKey {
    /// A kind that has its own labelled section.
    Kind(u8),
    /// Every kind without a labelled section, merged into one bucket.
    Other,
}
// Bound native TOON recursion for user/vault-provided JSON field values.
pub(super) const TOON_MAX_DEPTH: usize = 128;
pub(super) type ValueDepthLimit = Option<usize>;
