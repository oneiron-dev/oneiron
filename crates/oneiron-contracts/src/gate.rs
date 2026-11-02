//! The caller-supplied retrieval filter. `oneiron`'s gate projects and narrows it against
//! vault authority; the value itself is shared vocabulary.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Caller-supplied retrieval constraints. Unset fields inherit vault authority;
/// valid over-asks are clamped, not rejected. Numeric minima must be finite in
/// `[0, 1]`, and sensitivity must be in `0..=3`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RetrievalFilter {
    /// Admitted entity types; absent means every registered type. On the
    /// wire each is its registry kind (`CLAIM`, `MESSAGE`, ...), the same
    /// spelling a read receipt's scope uses, so a receipt's applied scope
    /// reads back as a filter (FIX 11745).
    #[serde(default, with = "crate::serialize::type_kinds")]
    pub entity_types: Option<BTreeSet<u8>>,
    #[serde(default)]
    pub max_sensitivity_band: Option<u8>,
    #[serde(default)]
    pub include_stale: Option<bool>,
    #[serde(default)]
    pub min_confidence: Option<f32>,
    #[serde(default)]
    pub min_salience: Option<f32>,
}
