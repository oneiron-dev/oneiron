//! The same credential-gated file projection for point reads and indexed
//! hydration. A non-owner never receives a lifted value through raw bytes.
use super::model::GraphFsResolver;
use crate::claim::{PointRead, ReadRow, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::RetrievalFilter;

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
                        if self.scoped_read.actor_key().reads_as_vault_owner() {
                            return Ok(Some(row));
                        }
                        let Some(body) = row.body.as_mut() else {
                            return Ok(Some(row));
                        };
                        if row.entity_type == crate::registry::ENTITY_TYPE_ASSET {
                            *body = crate::secret_custody::sighted_bytes_in_txn(
                                &self.scoped_read.vault().store,
                                txn,
                                body.clone(),
                                crate::secret_custody::SecretSight::Masked,
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

fn strings<'a>(value: &'a rmpv::Value, out: &mut Vec<&'a str>) {
    match value {
        rmpv::Value::String(text) => {
            if let Some(text) = text.as_str() {
                out.push(text);
            }
        }
        rmpv::Value::Array(items) => {
            for item in items {
                strings(item, out);
            }
        }
        rmpv::Value::Map(items) => {
            for (key, value) in items {
                strings(key, out);
                strings(value, out);
            }
        }
        _ => {}
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
