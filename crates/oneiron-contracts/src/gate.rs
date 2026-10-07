//! The caller-supplied retrieval filter. `oneiron`'s gate projects and narrows it against
//! vault authority; the value itself is shared vocabulary.

use std::collections::BTreeSet;

/// Caller-supplied retrieval constraints. Unset fields inherit vault authority;
/// valid over-asks are clamped, not rejected. Numeric minima must be finite in
/// `[0, 1]`, and sensitivity must be in `0..=3`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RetrievalFilter {
    pub entity_types: Option<BTreeSet<u8>>,
    pub max_sensitivity_band: Option<u8>,
    pub include_stale: Option<bool>,
    pub min_confidence: Option<f32>,
    pub min_salience: Option<f32>,
}
