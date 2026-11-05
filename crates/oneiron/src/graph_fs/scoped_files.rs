//! Core half of `graph_fs::scoped_files`: its store-layer items live in `oneiron_store::graph_fs::scoped_files` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::graph_fs::scoped_files::*;

use super::model::GraphFsResolver;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::repo_secret_reads::repo_asset_body_in_txn;
use crate::ports::ScopedReadResult;
use crate::ports::{PointRead, ReadRow};
use oneiron_contracts::gate::RetrievalFilter;

impl GraphFsResolver<'_, '_> {
    pub(super) fn file_rows(
        &self,
        reads: &[PointRead<'_>],
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<Option<ReadRow>>>> {
        self.scoped_read
            .read_projected(reads, requested, |txn, rows| {
                rows.into_iter()
                    .map(|row| {
                        let Some(mut row) = row else { return Ok(None) };
                        // A repo ASSET reads as its projection on a mount
                        // whose handle reads repo bytes masked, the owner's
                        // key included (FIX 8964), before the owner's
                        // exact return.
                        if self.repo_masked()
                            && let Some(body) = row.body.as_mut()
                            && let Some(projected) = repo_asset_body_in_txn(
                                self.scoped_read.vault(),
                                txn,
                                &row.id,
                                row.entity_type,
                                body,
                            )?
                        {
                            *body = projected;
                        }
                        if self.scoped_read.actor_key().reads_as_vault_owner() {
                            return Ok(Some(row));
                        }
                        let Some(body) = row.body.as_mut() else {
                            return Ok(Some(row));
                        };
                        if row.entity_type == crate::registry::ENTITY_TYPE_ASSET {
                            *body = crate::store::file_key_masks::sighted_bytes_in_txn(
                                &self.scoped_read.vault().store,
                                txn,
                                body.clone(),
                                None,
                                crate::file_secret_marks::SecretSight::Masked,
                            )?;
                        } else {
                            let mut cursor = std::io::Cursor::new(body.as_slice());
                            let value = rmpv::decode::read_value(&mut cursor)
                                .ok()
                                .filter(|_| cursor.position() == body.len() as u64);
                            if let Some(mut value) = value {
                                let mut texts = Vec::new();
                                strings(&value, &mut texts);
                                let keys = crate::batch::secret_scan::LiftedKeys::of_in_txn(
                                    &self.scoped_read.vault().store,
                                    txn,
                                    texts,
                                )?;
                                if mask(&mut value, &keys) {
                                    let mut bytes = Vec::new();
                                    rmpv::encode::write_value(&mut bytes, &value).map_err(
                                        |_| {
                                            Error::InvariantViolation(
                                                "masked graph-fs body did not encode",
                                            )
                                        },
                                    )?;
                                    *body = bytes;
                                }
                            } else if let Ok(text) = std::str::from_utf8(body) {
                                let keys = crate::batch::secret_scan::LiftedKeys::of_in_txn(
                                    &self.scoped_read.vault().store,
                                    txn,
                                    [text],
                                )?;
                                if let Some(masked) = keys.masked(text) {
                                    *body = masked.into_bytes();
                                }
                            }
                        }
                        Ok(Some(row))
                    })
                    .collect::<Result<Vec<_>>>()
            })
    }

    pub(super) fn file_row(&self, id: EntityId) -> Result<ScopedReadResult<Option<ReadRow>>> {
        Ok(self.file_rows(&[PointRead::id(id)], None)?.single())
    }
}

fn mask(value: &mut rmpv::Value, keys: &crate::batch::secret_scan::LiftedKeys) -> bool {
    match value {
        rmpv::Value::String(text) => {
            let Some(masked) = text.as_str().and_then(|text| keys.masked(text)) else {
                return false;
            };
            *text = masked.into();
            true
        }
        rmpv::Value::Array(items) => items
            .iter_mut()
            .fold(false, |changed, item| mask(item, keys) | changed),
        rmpv::Value::Map(items) => items.iter_mut().fold(false, |changed, (key, value)| {
            mask(key, keys) | mask(value, keys) | changed
        }),
        _ => false,
    }
}
