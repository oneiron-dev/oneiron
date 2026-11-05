//! Exact provenance of a selected, admitted room row at an explicit save.
use super::{BIRTH_BY_TRIGGER, ROW_BIRTH, RowBirth};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::SessionStoreView;
use crate::{EntityId, Error, Result, Vault};

pub(crate) struct SavedRoomBirth {
    row: EntityId,
    birth: Option<RowBirth>,
}

impl SavedRoomBirth {
    pub(crate) fn prepare(
        view: &SessionStoreView<'_>,
        txn: &heed::RoTxn<'_>,
        row: EntityId,
    ) -> Result<Self> {
        let birth = ROW_BIRTH.get(view, txn, &row)?;
        if let Some(birth) = &birth {
            birth.check_shape()?;
        }
        Ok(Self { row, birth })
    }

    pub(crate) fn land(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        grant: &crate::off_record::PromoteReplayGrant,
    ) -> Result<()> {
        if !grant.exempts(&self.row) || grant.selected_saver().is_none() {
            return Err(Error::InvariantViolation(
                "room birth is outside the selected save",
            ));
        }
        let Some(birth) = &self.birth else {
            return Ok(());
        };
        if vault.store.port_deletion_marked(
            txn,
            DeletionMarker::HardDelete,
            &birth.made_by.process.actor,
        )? {
            return Err(Error::EntityNotFound);
        }
        match ROW_BIRTH.get(&vault.store, txn, &self.row)? {
            Some(stored) if stored == *birth => return Ok(()),
            Some(stored) if stored.is_document_birth() => {
                if let Some(trigger) = &stored.made_by.trigger {
                    BIRTH_BY_TRIGGER.delete(&vault.store, txn, &(trigger.row(), self.row))?;
                }
            }
            Some(_) => {
                return Err(Error::InvariantViolation(
                    "a row's birth envelope is immutable",
                ));
            }
            None => {}
        }
        // No base_form conversion: supplied room evidence remains evidence as
        // supplied, not an upgraded source claim or a new birth by the saver.
        ROW_BIRTH.put(&vault.store, txn, &self.row, birth)?;
        if let Some(trigger) = &birth.made_by.trigger {
            BIRTH_BY_TRIGGER.put(&vault.store, txn, &(trigger.row(), self.row), &())?;
        }
        Ok(())
    }
}
