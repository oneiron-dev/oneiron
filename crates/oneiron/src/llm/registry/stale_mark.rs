//! The host's or owner's own stale marks on registry rows (FIX 4546, FIX
//! 4547). A pack refresh marks the models it no longer ships and clears the
//! mark of those it ships again; a mark set through
//! [`Vault::mark_model_row_stale`] is the owner's, so an ordinary re-put and
//! a pack that ships the model again keep it, and only another such call
//! clears it. A model the installed pack serves with no stored row is stored
//! when it is marked, so the mark holds. A withdrawn mesh offer is kept as a
//! stale row, never deleted.
use heed::{RoTxn, RwTxn};

use super::{CatalogSeed, ModelRegistryRow, REGISTRY_ROW};
use crate::llm::ModelId;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::{Result, Vault};

/// When the owner marked a model's row stale. Key: string (model id).
const STALE_MARK: SideTable<String, u64, Named> =
    SideTable::new(&side_table::LLM_REGISTRY_STALE_MARK);

/// The owner's mark on the row stored under `key`, when it has one.
pub(super) fn owner_mark(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    key: &str,
) -> Result<Option<u64>> {
    STALE_MARK.get(dbs, txn, &key.to_owned())
}

impl Vault {
    /// Marks `model`'s row retired by its provider since `at`, for a host
    /// or owner that learns of a retirement outside a pack refresh; `None`
    /// clears the mark, and any stale reading the row holds. The row stays:
    /// one only the installed pack serves is stored with the mark (FIX
    /// 4547), and an ordinary re-put or a pack that ships the model again
    /// keeps it (FIX 4546). A seat already admitted on the model keeps
    /// working; only new seats pass it over. `Ok(false)` when no row serves
    /// the model, or it already reads so.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn mark_model_row_stale(&self, model: &ModelId, at: Option<u64>) -> Result<bool> {
        let key = model.as_str().to_owned();
        let mut txn = self.store.env.write_txn()?;
        let row = match REGISTRY_ROW.get(&self.store, &txn, &key)? {
            Some(row) => Some(row),
            None => self.pack_row_in(&txn, model)?,
        };
        let Some(mut row) = row else {
            return Ok(false);
        };
        let marked = owner_mark(&self.store, &txn, &key)?;
        if row.stale_since == at && marked == at {
            return Ok(false);
        }
        match at {
            Some(at) => STALE_MARK.put(&self.store, &mut txn, &key, &at)?,
            None => {
                STALE_MARK.delete(&self.store, &mut txn, &key)?;
            }
        }
        row.stale_since = at;
        REGISTRY_ROW.put(self, &mut txn, &key, &row)?;
        txn.commit()?;
        Ok(true)
    }

    /// Keeps the stored row for `row`'s model, while it still holds `row`,
    /// as a stale row from now on: the source that wrote it withdrew it (a
    /// mesh node that stopped offering the model). Its record stays; no new
    /// seat or route takes it, and the source's next offer of the model
    /// writes it live again. `Ok(false)` when the stored row is gone,
    /// changed since, or already stale.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn withdraw_model_registry_row(&self, row: &ModelRegistryRow) -> Result<bool> {
        let key = row.catalog.model.as_str().to_owned();
        let mut txn = self.store.env.write_txn()?;
        let stored = REGISTRY_ROW.get(&self.store, &txn, &key)?;
        if stored.as_ref() != Some(row) || row.is_stale() {
            return Ok(false);
        }
        let mut withdrawn = row.clone();
        withdrawn.stale_since = Some(crate::ports::recorded_at_in_txn(&self.store, &mut txn)?);
        REGISTRY_ROW.put(self, &mut txn, &key, &withdrawn)?;
        txn.commit()?;
        Ok(true)
    }

    /// The installed model pack's row for `model`, when the pack serves it.
    fn pack_row_in(&self, txn: &RwTxn<'_>, model: &ModelId) -> Result<Option<ModelRegistryRow>> {
        if self
            .installed_pack_in_txn(txn, crate::skill_hub::MODEL_PACK_NAME)?
            .is_none()
        {
            return Ok(None);
        }
        Ok(CatalogSeed::from_installed_pack_in_txn(self, txn)?
            .rows
            .into_iter()
            .find(|row| &row.catalog.model == model))
    }
}
