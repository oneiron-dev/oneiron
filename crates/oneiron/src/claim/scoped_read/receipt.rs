//! Mandatory read receipts. Responses carry the requested/ceiling/intersection tuple.
use super::ScopedRead;
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter, RetrievalFilter};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadScope {
    pub entity_types: Option<BTreeSet<u8>>,
    pub max_sensitivity_band: u8,
    pub include_stale: bool,
    pub min_confidence: f32,
    pub min_salience: f32,
    pub deny_all: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopedReadReceipt {
    pub requested: ReadScope,
    pub actor_ceiling: ReadScope,
    pub applied: ReadScope,
    pub narrowed_axes: Vec<String>,
    pub suppressed_count: usize,
    /// Machine-readable re-plan hint: names axes, not prose to parse.
    pub replan_hint: Vec<String>,
}

#[must_use = "scoped results include a mandatory narrowing receipt"]
#[derive(Debug, Clone, PartialEq)]
pub struct ScopedReadResult<T> {
    pub value: T,
    pub receipt: ScopedReadReceipt,
}
impl<T> std::ops::Deref for ScopedReadResult<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> IntoIterator for ScopedReadResult<Vec<T>> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.value.into_iter()
    }
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

    fn resolved(filter: &ResolvedRetrievalFilter) -> Self {
        Self {
            entity_types: filter.entity_types.clone(),
            max_sensitivity_band: filter.max_sensitivity_band,
            include_stale: filter.include_stale,
            min_confidence: filter.min_confidence,
            min_salience: filter.min_salience,
            deny_all: filter.deny_all,
        }
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

    fn record_axes(&mut self) {
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

impl ScopedRead<'_> {
    pub(super) fn receipt_for(
        &self,
        requested: Option<&RetrievalFilter>,
        policy: &PolicyManifestResolution,
        applied: &ResolvedRetrievalFilter,
        suppressed_count: usize,
    ) -> ScopedReadReceipt {
        let floor = policy.retrieval_floor_for_actor(Some(&self.actor_key));
        let actor_ceiling = ReadScope {
            entity_types: floor.allowed_entity_types,
            max_sensitivity_band: floor.max_sensitivity_band,
            include_stale: floor.include_stale,
            min_confidence: floor.min_confidence,
            min_salience: floor.min_salience,
            deny_all: floor.deny_all,
        };
        let applied = ReadScope::resolved(applied);
        let requested = requested.map_or_else(
            || actor_ceiling.clone(),
            |req| ReadScope {
                entity_types: req
                    .entity_types
                    .clone()
                    .or_else(|| actor_ceiling.entity_types.clone()),
                max_sensitivity_band: req
                    .max_sensitivity_band
                    .unwrap_or(actor_ceiling.max_sensitivity_band),
                include_stale: req.include_stale.unwrap_or(actor_ceiling.include_stale),
                min_confidence: req.min_confidence.unwrap_or(actor_ceiling.min_confidence),
                min_salience: req.min_salience.unwrap_or(actor_ceiling.min_salience),
                deny_all: req.entity_types.as_ref().is_some_and(BTreeSet::is_empty),
            },
        );
        let mut receipt = ScopedReadReceipt {
            requested,
            actor_ceiling,
            applied,
            replan_hint: Vec::new(),
            narrowed_axes: Vec::new(),
            suppressed_count,
        };
        receipt.record_axes();
        receipt
    }

    /// Returns the same mandatory receipt even when no row was withheld.
    pub fn read_receipt(
        &self,
        requested: Option<&RetrievalFilter>,
        suppressed: usize,
    ) -> crate::Result<ScopedReadReceipt> {
        let (applied, policy) = self.resolve_retrieval_filter(requested)?;
        Ok(self.receipt_for(requested, &policy, &applied, suppressed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_read_door_reports_intersection_even_without_narrowing() -> crate::Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let read = vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").unwrap());
        let plain = read.search_text("absent", 1, None)?;
        assert_eq!(plain.receipt.requested, plain.receipt.applied);
        assert_eq!(plain.receipt.suppressed_count, 0);
        let filtered = read.filter_scored_entities(vec![])?;
        assert_eq!(filtered.receipt.requested, filtered.receipt.applied);
        assert!(read.hydrate_short_id("cl999999", 0)?.value.is_none());
        for band in 0..=3 {
            for confidence in [0.0, 0.25, 0.5, 1.0] {
                let requested = RetrievalFilter {
                    max_sensitivity_band: Some(band),
                    min_confidence: Some(confidence),
                    include_stale: Some(true),
                    ..Default::default()
                };
                let receipt = read.read_receipt(Some(&requested), 0)?;
                assert!(receipt.applied.max_sensitivity_band <= band);
                assert!(receipt.applied.min_confidence >= confidence);
                assert!(!receipt.applied.include_stale || receipt.actor_ceiling.include_stale);
                assert_eq!(receipt.replan_hint, receipt.narrowed_axes);
            }
        }
        Ok(())
    }
}
