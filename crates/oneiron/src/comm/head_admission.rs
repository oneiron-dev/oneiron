//! Transaction-local admission around actual projector head mutations.

use super::claims::{CommError, CommResult};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The batch's existing actor or reader checks, not authority for source records.
pub(crate) trait ProjectedHeadAdmission {
    fn before(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        ids: &[EntityId],
        local_puts: &[EntityId],
    ) -> Result<()>;
    fn after(&mut self, vault: &Vault, txn: &mut heed::RwTxn<'_>, ids: &[EntityId]) -> Result<()>;
    fn projected(&mut self, ids: &[EntityId]);
}

#[derive(Default)]
pub(super) struct HeadAdmission<'a> {
    bound: Option<&'a mut dyn ProjectedHeadAdmission>,
    failed: bool,
}

impl<'a> HeadAdmission<'a> {
    pub(super) fn bound(bound: &'a mut dyn ProjectedHeadAdmission) -> Self {
        Self {
            bound: Some(bound),
            failed: false,
        }
    }

    pub(super) fn failed(&self) -> bool {
        self.failed
    }

    pub(super) fn projected(&mut self, ids: &[EntityId]) {
        if let Some(bound) = self.bound.as_deref_mut() {
            bound.projected(ids);
        }
    }

    pub(super) fn write<T>(
        &mut self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        ids: &[EntityId],
        local_puts: &[EntityId],
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> CommResult<T>,
    ) -> CommResult<T> {
        if let Some(bound) = self.bound.as_deref_mut() {
            if let Err(error) = bound.before(vault, txn, ids, local_puts) {
                self.failed = true;
                return Err(CommError::Engine(error));
            }
        }
        let result = write(txn)?;
        if let Some(bound) = self.bound.as_deref_mut() {
            if let Err(error) = bound.after(vault, txn, ids) {
                self.failed = true;
                return Err(CommError::Engine(error));
            }
        }
        Ok(result)
    }
}
