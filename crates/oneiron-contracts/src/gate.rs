//! The caller-supplied retrieval filter. `oneiron`'s gate projects and narrows it against
//! vault authority; the value itself is shared vocabulary.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// The highest sensitivity band a filter names: bands run `0..=3`.
pub const MAX_SENSITIVITY_BAND: u8 = 3;

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

impl RetrievalFilter {
    /// This request and `other` asked together, as one request (FIX 3977):
    /// the types both admit, the lower band, stale rows only when neither
    /// excludes them, the higher minima. An unset field is the meet
    /// identity, so it never widens the other side. A value out of its
    /// range is kept, never met away, so the narrowing door still refuses
    /// it.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            entity_types: match (&self.entity_types, &other.entity_types) {
                (Some(left), Some(right)) => Some(left.intersection(right).copied().collect()),
                (Some(types), None) | (None, Some(types)) => Some(types.clone()),
                (None, None) => None,
            },
            max_sensitivity_band: meet_field(
                self.max_sensitivity_band,
                other.max_sensitivity_band,
                |band| band <= MAX_SENSITIVITY_BAND,
                std::cmp::min,
            ),
            include_stale: match (self.include_stale, other.include_stale) {
                (Some(left), Some(right)) => Some(left && right),
                (Some(value), None) | (None, Some(value)) => Some(value),
                (None, None) => None,
            },
            min_confidence: meet_field(
                self.min_confidence,
                other.min_confidence,
                valid_minimum,
                f32::max,
            ),
            min_salience: meet_field(
                self.min_salience,
                other.min_salience,
                valid_minimum,
                f32::max,
            ),
        }
    }

    /// `left` met with `right`, either absent: `None` only when both are.
    #[must_use]
    pub fn meet_requests(left: Option<&Self>, right: Option<&Self>) -> Option<Self> {
        match (left, right) {
            (Some(left), Some(right)) => Some(left.meet(right)),
            (Some(request), None) | (None, Some(request)) => Some(request.clone()),
            (None, None) => None,
        }
    }
}

/// One field of [`RetrievalFilter::meet`]: the narrower of two set values,
/// an invalid one kept whole so validation refuses it.
fn meet_field<T: Copy>(
    left: Option<T>,
    right: Option<T>,
    valid: impl Fn(T) -> bool,
    narrower: impl Fn(T, T) -> T,
) -> Option<T> {
    match (left, right) {
        (Some(left), Some(_)) if !valid(left) => Some(left),
        (Some(_), Some(right)) if !valid(right) => Some(right),
        (Some(left), Some(right)) => Some(narrower(left, right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn valid_minimum(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

/// A caller's retrieval filter as every read door takes it (RETRIEVAL-04,
/// `#t-filter`): the wire form of [`RetrievalFilter`]. Each field only
/// narrows vault policy; a valid over-ask clamps to the floor and an unset
/// field leaves the floor in force. Relationship, world and facet selectors
/// stay outside it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadFilterInput {
    /// Restrict to these entity types, each its numeric registry type byte.
    #[serde(default)]
    pub entity_types: Option<BTreeSet<u8>>,
    /// Sensitivity ceiling, in 0..=3.
    #[serde(default)]
    pub max_sensitivity_band: Option<u8>,
    /// Ask for stale claims; the ceiling still decides.
    #[serde(default)]
    pub include_stale: Option<bool>,
    /// Drop claims below this confidence, in [0, 1].
    #[serde(default)]
    pub min_confidence: Option<f32>,
    /// Drop claims below this salience, in [0, 1].
    #[serde(default)]
    pub min_salience: Option<f32>,
}

impl ReadFilterInput {
    /// This input as the request the gate narrows a floor by: the one
    /// conversion every door uses.
    #[must_use]
    pub fn to_filter(&self) -> RetrievalFilter {
        RetrievalFilter {
            entity_types: self.entity_types.clone(),
            max_sensitivity_band: self.max_sensitivity_band,
            include_stale: self.include_stale,
            min_confidence: self.min_confidence,
            min_salience: self.min_salience,
        }
    }

    /// This input and `other` asked together, as [`RetrievalFilter::meet`]
    /// joins them: the result only narrows either.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        let met = self.to_filter().meet(&other.to_filter());
        Self {
            entity_types: met.entity_types,
            max_sensitivity_band: met.max_sensitivity_band,
            include_stale: met.include_stale,
            min_confidence: met.min_confidence,
            min_salience: met.min_salience,
        }
    }
}
