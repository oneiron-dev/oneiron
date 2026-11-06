//! The same credential-gated file projection for point reads and indexed
//! hydration. A non-owner never receives a lifted value through raw bytes.
use super::coreutils_text::{checkpoint, copy_text_parts};
use super::model::{GRAPH_FS_PROJECTION_VERSION, GraphFsFile, GraphFsResolver};
use crate::batch::secret_scan::ContainerReader;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::repo_secret_reads::repo_asset_body_in_txn_with_reader;
use crate::ports::ScopedReadResult;
use crate::ports::{PointRead, ReadRow};
use crate::registry::ENTITY_TYPE_CLAIM;
use oneiron_contracts::gate::RetrievalFilter;
use std::io::{self, Read, Write};

impl GraphFsResolver<'_, '_> {
    pub(super) fn file_rows(
        &self,
        reads: &[PointRead<'_>],
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<Option<ReadRow>>>> {
        self.file_rows_with_reader(reads, requested, &ContainerReader::default())
    }

    pub(super) fn file_rows_with_reader(
        &self,
        reads: &[PointRead<'_>],
        requested: Option<&RetrievalFilter>,
        reader: &ContainerReader,
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
                            && let Some(projected) = repo_asset_body_in_txn_with_reader(
                                self.scoped_read.vault(),
                                txn,
                                &row.id,
                                row.entity_type,
                                body,
                                reader,
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
                            *body = crate::store::file_key_masks::sighted_bytes_in_txn_with_reader(
                                &self.scoped_read.vault().store,
                                txn,
                                std::mem::take(body),
                                None,
                                crate::file_secret_marks::SecretSight::Masked,
                                reader,
                            )?;
                        } else {
                            let mut input = PacedBodyIo::new(
                                std::io::Cursor::new(body.as_slice()),
                                reader,
                                self.options.page_byte_cap,
                            );
                            let value = rmpv::decode::read_value(&mut input);
                            let cursor = input.finish()?;
                            let value = value
                                .ok()
                                .filter(|_| cursor.position() == body.len() as u64);
                            if let Some(mut value) = value {
                                let mut texts = Vec::new();
                                strings(&value, &mut texts, reader)?;
                                let keys =
                                    crate::batch::secret_scan::LiftedKeys::of_in_txn_with_reader(
                                        &self.scoped_read.vault().store,
                                        txn,
                                        texts,
                                        reader,
                                        self.options.page_byte_cap,
                                    )?;
                                if mask(&mut value, &keys, reader)? {
                                    let mut output = PacedBodyIo::new(
                                        Vec::new(),
                                        reader,
                                        self.options.page_byte_cap,
                                    );
                                    let encoded = rmpv::encode::write_value(&mut output, &value);
                                    let bytes = output.finish()?;
                                    encoded.map_err(|_| {
                                        Error::InvariantViolation(
                                            "masked graph-fs body did not encode",
                                        )
                                    })?;
                                    *body = bytes;
                                }
                            } else if let Ok(text) = std::str::from_utf8(body) {
                                let keys =
                                    crate::batch::secret_scan::LiftedKeys::of_in_txn_with_reader(
                                        &self.scoped_read.vault().store,
                                        txn,
                                        [text],
                                        reader,
                                        self.options.page_byte_cap,
                                    )?;
                                if let Some(masked) = keys.masked_with_reader(text, reader)? {
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

    pub(super) fn file_row_with_reader(
        &self,
        id: EntityId,
        reader: &ContainerReader,
    ) -> Result<ScopedReadResult<Option<ReadRow>>> {
        Ok(self
            .file_rows_with_reader(&[PointRead::id(id)], None, reader)?
            .single())
    }

    pub(super) fn read_claim_file(
        &self,
        path: &str,
        claim_id: &EntityId,
        reader: &ContainerReader,
    ) -> Result<ScopedReadResult<Option<GraphFsFile>>> {
        let ScopedReadResult { value, receipt } = self.file_row_with_reader(*claim_id, reader)?;
        let Some(ReadRow {
            entity_type: ENTITY_TYPE_CLAIM,
            learned_at,
            body: Some(body),
            ..
        }) = value
        else {
            return Ok(ScopedReadResult {
                value: None,
                receipt,
            });
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(GRAPH_FS_PROJECTION_VERSION.as_bytes());
        bytes.extend_from_slice(b"\nkind\tclaim\nmount\t");
        bytes.extend_from_slice(self.options.mount.stable_label().as_bytes());
        bytes.extend_from_slice(b"\nid\t");
        bytes.extend_from_slice(claim_id.to_hex().as_bytes());
        bytes.extend_from_slice(b"\nlearned_at\t");
        bytes.extend_from_slice(learned_at.to_string().as_bytes());
        bytes.extend_from_slice(b"\nbody_msgpack_hex\t");
        for chunk in body.chunks(self.options.page_byte_cap.max(1)) {
            checkpoint(reader)?;
            bytes.extend_from_slice(bytes_to_hex_lower(chunk).as_bytes());
        }
        bytes.push(b'\n');
        Ok(ScopedReadResult {
            value: Some(GraphFsFile {
                path: copy_text_parts(&[path], reader, self.options.page_byte_cap)?,
                mount: self.options.mount,
                bytes,
            }),
            receipt,
        })
    }
}

struct PacedBodyIo<'a, T> {
    inner: T,
    reader: &'a ContainerReader,
    scan_bytes: usize,
    cancelled: Option<Error>,
}

impl<'a, T> PacedBodyIo<'a, T> {
    fn new(inner: T, reader: &'a ContainerReader, scan_bytes: usize) -> Self {
        Self {
            inner,
            reader,
            scan_bytes: scan_bytes.max(1),
            cancelled: None,
        }
    }

    fn checkpoint(&mut self) -> io::Result<()> {
        if let Err(error) = checkpoint(self.reader) {
            self.cancelled = Some(error);
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }

    fn finish(self) -> Result<T> {
        if let Some(error) = self.cancelled {
            return Err(error);
        }
        Ok(self.inner)
    }
}

impl<T: Read> Read for PacedBodyIo<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.checkpoint()?;
        let len = buf.len().min(self.scan_bytes);
        self.inner.read(&mut buf[..len])
    }
}

impl<T: Write> Write for PacedBodyIo<'_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.checkpoint()?;
        let len = buf.len().min(self.scan_bytes);
        self.inner.write(&buf[..len])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn strings<'a>(
    value: &'a rmpv::Value,
    out: &mut Vec<&'a str>,
    reader: &ContainerReader,
) -> Result<()> {
    checkpoint(reader)?;
    match value {
        rmpv::Value::String(text) => {
            if let Some(text) = text.as_str() {
                out.push(text);
            }
        }
        rmpv::Value::Array(items) => {
            for item in items {
                strings(item, out, reader)?;
            }
        }
        rmpv::Value::Map(items) => {
            for (key, value) in items {
                strings(key, out, reader)?;
                strings(value, out, reader)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn mask(
    value: &mut rmpv::Value,
    keys: &crate::batch::secret_scan::LiftedKeys,
    reader: &ContainerReader,
) -> Result<bool> {
    checkpoint(reader)?;
    match value {
        rmpv::Value::String(text) => {
            let Some(value) = text.as_str() else {
                return Ok(false);
            };
            let Some(masked) = keys.masked_with_reader(value, reader)? else {
                return Ok(false);
            };
            *text = masked.into();
            Ok(true)
        }
        rmpv::Value::Array(items) => items.iter_mut().try_fold(false, |changed, item| {
            Ok(mask(item, keys, reader)? | changed)
        }),
        rmpv::Value::Map(items) => items.iter_mut().try_fold(false, |changed, (key, value)| {
            Ok(mask(key, keys, reader)? | mask(value, keys, reader)? | changed)
        }),
        _ => Ok(false),
    }
}
