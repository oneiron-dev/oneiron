//! Mandatory read receipts. Responses carry the requested/ceiling/intersection tuple.
use super::ScopedRead;
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter, RetrievalFilter};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub use oneiron_contracts::claim::{ReadScope, ScopedReadReceipt};

/// Values and the narrowing receipt from one scoped read.
///
/// Borrowing the value leaves the receipt available. Consuming the wrapper as
/// bare rows is not supported: projections must explicitly preserve the receipt.
///
/// ```compile_fail
/// use oneiron::claim::ScopedReadResult;
/// fn bare_rows(result: ScopedReadResult<Vec<u8>>) {
///     for row in result {
///         let _ = row;
///     }
/// }
/// ```
///
/// ```compile_fail
/// use oneiron::claim::ScopedReadResult;
/// fn bare_rows(result: ScopedReadResult<Vec<u8>>) -> Vec<u8> {
///     result.into_iter().collect()
/// }
/// ```
///
/// On the wire the pair is `{"value": .., "narrowing": ..}`: `narrowing` is the
/// one name every read result gives its receipt.
#[must_use = "scoped results include a mandatory narrowing receipt"]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedReadResult<T> {
    pub value: T,
    #[serde(rename = "narrowing")]
    pub receipt: ScopedReadReceipt,
}

impl<T> ScopedReadResult<T> {
    /// Project the value; the receipt travels with the projection.
    pub fn map<U>(self, project: impl FnOnce(T) -> U) -> ScopedReadResult<U> {
        ScopedReadResult {
            value: project(self.value),
            receipt: self.receipt,
        }
    }
}

impl<T> ScopedReadResult<Vec<Option<T>>> {
    /// The first slot of a one-read slice, under the slice's receipt.
    pub fn single(self) -> ScopedReadResult<Option<T>> {
        self.map(|slots| slots.into_iter().next().flatten())
    }
}
impl<T> std::ops::Deref for ScopedReadResult<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

/// The applied scope a resolved policy filter produced.
fn read_scope_from_resolved(filter: &ResolvedRetrievalFilter) -> ReadScope {
    ReadScope {
        entity_types: filter.entity_types.clone(),
        max_sensitivity_band: filter.max_sensitivity_band,
        include_stale: filter.include_stale,
        min_confidence: filter.min_confidence,
        min_salience: filter.min_salience,
        deny_all: filter.deny_all,
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
        let applied = read_scope_from_resolved(applied);
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

    /// The receipt for a scan that already holds its transaction: the
    /// authority is resolved in that snapshot, never a newer one.
    pub(crate) fn read_receipt_in(
        &self,
        txn: &heed::RoTxn<'_>,
        requested: Option<&RetrievalFilter>,
        suppressed: usize,
    ) -> crate::Result<ScopedReadReceipt> {
        let (applied, policy) = self.resolve_retrieval_filter_in(txn, requested)?;
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
        assert!(
            read.read(&[super::super::PointRead::short("cl999999", 0)], None)?
                .single()
                .value
                .is_none()
        );
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
