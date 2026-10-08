//! Mandatory read receipts: the requested / actor-ceiling / applied scope triple and the
//! axes a read narrowed. `oneiron::claim` re-exports both types; the scoped-read lane that
//! fills them stays in `oneiron`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::gate::RetrievalFilter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadScope {
    pub entity_types: Option<BTreeSet<u8>>,
    pub max_sensitivity_band: u8,
    pub include_stale: bool,
    pub min_confidence: f32,
    pub min_salience: f32,
    pub deny_all: bool,
}

/// Scalars compare by bit pattern, so a receipt is `Eq` and carriers that
/// derive `Eq` can hold one. Every scope float is a finite floor from policy.
impl PartialEq for ReadScope {
    fn eq(&self, other: &Self) -> bool {
        self.entity_types == other.entity_types
            && self.max_sensitivity_band == other.max_sensitivity_band
            && self.include_stale == other.include_stale
            && self.min_confidence.to_bits() == other.min_confidence.to_bits()
            && self.min_salience.to_bits() == other.min_salience.to_bits()
            && self.deny_all == other.deny_all
    }
}
impl Eq for ReadScope {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedReadReceipt {
    pub requested: ReadScope,
    pub actor_ceiling: ReadScope,
    pub applied: ReadScope,
    pub narrowed_axes: Vec<String>,
    pub suppressed_count: usize,
    /// Machine-readable re-plan hint: names axes, not prose to parse.
    pub replan_hint: Vec<String>,
}

impl ReadScope {
    /// Reuse the already-applied scalar/type intersection for a later read.
    #[must_use]
    pub fn as_filter(&self) -> RetrievalFilter {
        RetrievalFilter {
            entity_types: if self.deny_all {
                Some(BTreeSet::new())
            } else {
                self.entity_types.clone()
            },
            max_sensitivity_band: Some(self.max_sensitivity_band),
            include_stale: Some(self.include_stale),
            min_confidence: Some(self.min_confidence),
            min_salience: Some(self.min_salience),
        }
    }

    fn restrict(&mut self, other: &Self) {
        self.entity_types = match (&self.entity_types, &other.entity_types) {
            (Some(left), Some(right)) => Some(left.intersection(right).copied().collect()),
            (left, right) => left.clone().or_else(|| right.clone()),
        };
        self.max_sensitivity_band = self.max_sensitivity_band.min(other.max_sensitivity_band);
        self.include_stale &= other.include_stale;
        self.min_confidence = self.min_confidence.max(other.min_confidence);
        self.min_salience = self.min_salience.max(other.min_salience);
        self.deny_all |=
            other.deny_all || self.entity_types.as_ref().is_some_and(BTreeSet::is_empty);
    }
}

impl ScopedReadReceipt {
    /// Add existing rows withheld by a consumer projection, not missing refs or page limits.
    /// The row-authority axis and re-plan hint stay consistent with the new count.
    pub fn add_suppressed(&mut self, count: usize) {
        self.suppressed_count = self.suppressed_count.saturating_add(count);
        self.record_axes();
    }

    /// Combine sequential filters. The original request is retained; neither
    /// the reported ceiling nor the applied scope can grow between snapshots.
    /// Counts are evaluated row exclusions, not missing refs or page truncation.
    pub fn restrict_with(&mut self, later: &Self) {
        self.actor_ceiling.restrict(&later.actor_ceiling);
        self.applied.restrict(&later.applied);
        self.suppressed_count = self.suppressed_count.saturating_add(later.suppressed_count);
        for axis in &later.narrowed_axes {
            if !self.narrowed_axes.contains(axis) {
                self.narrowed_axes.push(axis.clone());
            }
        }
        self.record_axes();
    }

    /// Recomputes `narrowed_axes` and `replan_hint` from the three scopes and the
    /// suppressed count. Engine seam: `oneiron`'s scoped-read receipt builder calls it
    /// after assembling the scopes. It only derives the axis lists from fields that are
    /// already public, so it cannot widen a receipt.
    pub fn record_axes(&mut self) {
        let differences = [
            (
                "entity_types",
                self.requested.entity_types != self.applied.entity_types,
            ),
            (
                "max_sensitivity_band",
                self.requested.max_sensitivity_band != self.applied.max_sensitivity_band,
            ),
            (
                "include_stale",
                self.requested.include_stale != self.applied.include_stale,
            ),
            (
                "min_confidence",
                self.requested.min_confidence != self.applied.min_confidence,
            ),
            (
                "min_salience",
                self.requested.min_salience != self.applied.min_salience,
            ),
            ("deny_all", self.applied.deny_all),
            ("row_authority", self.suppressed_count > 0),
        ];
        for (axis, changed) in differences {
            if changed && !self.narrowed_axes.iter().any(|existing| existing == axis) {
                self.narrowed_axes.push(axis.to_owned());
            }
        }
        self.replan_hint.clone_from(&self.narrowed_axes);
    }
}
