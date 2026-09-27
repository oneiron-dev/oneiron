//! One-snapshot scoped row projection: value and receipt contribution together.
use super::ScopedRead;
use crate::{EntityId, Result};
use std::collections::HashSet;

/// An unforgeable, run-local candidate view. Only a verified `ScopedRead`
/// builds it under the pipeline's current read transaction. It is never a
/// persisted grant or a caller-supplied list of bare IDs.
pub(crate) struct ScopedDiaryCandidates(HashSet<EntityId>);
impl ScopedDiaryCandidates {
    pub(super) fn from_admission(ids: HashSet<EntityId>) -> Self {
        Self(ids)
    }
    pub(crate) fn contains(&self, id: &EntityId) -> bool {
        self.0.contains(id)
    }
}

/// A private denial and a missing row share the same observable outcome.
/// Only ordinary policy-denied rows may contribute a receipt count/hint.
pub(super) enum ReadAdmission<T> {
    Visible(T),
    Suppressed,
    OpaqueAbsent,
}
impl<T> ReadAdmission<T> {
    pub(super) fn into_option(self) -> Option<T> {
        match self {
            Self::Visible(value) => Some(value),
            Self::Suppressed | Self::OpaqueAbsent => None,
        }
    }
    pub(super) fn suppression(&self) -> usize {
        usize::from(matches!(self, Self::Suppressed))
    }
    pub(super) fn visible(&self) -> bool {
        matches!(self, Self::Visible(_))
    }
}

impl ScopedRead<'_> {
    /// Resolve value and denial metadata in the SAME transaction. A caller
    /// never tests stored existence separately after this projection.
    pub(super) fn admit_in<T>(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        read: impl FnOnce() -> Result<Option<T>>,
    ) -> Result<ReadAdmission<T>> {
        if let Some(value) = read()? {
            return Ok(ReadAdmission::Visible(value));
        }
        let Some(row) = self.entity_record_in(txn, id)? else {
            return Ok(ReadAdmission::OpaqueAbsent);
        };
        if crate::note::countable_read_suppression(row.entity_type, &row.body) {
            Ok(ReadAdmission::Suppressed)
        } else {
            Ok(ReadAdmission::OpaqueAbsent)
        }
    }

    pub(super) fn admit_entity_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &crate::gate::PolicyManifestResolution,
        filter: &crate::gate::ResolvedRetrievalFilter,
        id: &EntityId,
    ) -> Result<ReadAdmission<()>> {
        self.admit_in(txn, id, || {
            self.is_entity_retrievable_with_policy_in(txn, policy, filter, id)
                .map(|allowed| allowed.then_some(()))
        })
    }
}
