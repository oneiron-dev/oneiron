//! An ASSET body kept in its file, read as a serving door's reader reads it
//! (FIX 5507).
//!
//! A file-plane body keeps its bytes as written, a file the secret mask
//! marked included, and the mark on the file's digest says where its keys
//! sit ([`super::masked_files`]). A serving door reads such a body through
//! the checked, pinned reader every body file read takes, which verifies
//! the stored bytes' length and BLAKE3 as they pass. The owner and a granted
//! agent read the stored bytes. Any other reader reads each marked span
//! overwritten as the bytes pass, never the stored bytes held whole beside
//! the copy, and the release scan reads that copy before any of it is
//! handed on, as it reads every masked copy. A mark that places keys inside
//! members, and an unmarked body, are judged as the whole-body door judges
//! them. The stored bytes never change.

use std::io::Read;

use heed::RoTxn;

use super::masked_files::{FILLER, SecretSight, masked_file_in_txn, sighted_bytes_in_txn};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead as _;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::vault::Vault;

/// `inner`'s bytes with each byte inside `spans` overwritten by the mask's
/// filler as it passes. `spans` are offsets in the stored bytes, in byte
/// order, none overlapping the next.
struct Filled<'r> {
    inner: &'r mut dyn Read,
    at: u64,
    spans: &'r [(u64, u64)],
}

impl Read for Filled<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        let start = self.at;
        let end = start.saturating_add(read as u64);
        let passed = self.spans.iter().take_while(|(_, to)| *to <= start).count();
        self.spans = &self.spans[passed..];
        for &(from, to) in self.spans {
            if from >= end {
                break;
            }
            let lo = usize::try_from(from.max(start) - start).unwrap_or(read);
            let hi = usize::try_from(to.min(end) - start).unwrap_or(read);
            if let Some(span) = buf.get_mut(lo..hi) {
                span.fill(FILLER);
            }
        }
        self.at = end;
        Ok(read)
    }
}

impl Vault {
    /// The body of ASSET `id` held in its file, as `sight` reads it, the
    /// file read once through the checked reader: `None` when `id` holds no
    /// readable body file. `expected` is the digest the door names the body
    /// by; a file of other bytes is corruption.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a file the door does not name or a span
    /// past its end; a masked copy the release scan still reads as secret,
    /// and [`sighted_bytes_in_txn`]'s refusals; the checked reader's errors.
    pub(crate) fn sighted_body_file_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        expected: &[u8; 32],
        sight: SecretSight,
    ) -> Result<Option<Vec<u8>>> {
        let Some(row) = self.store.port_entity_record(txn, id)? else {
            return Ok(None);
        };
        if row.entity_type != ENTITY_TYPE_ASSET {
            return Ok(None);
        }
        let Some(manifest) = crate::store::asset_file_in_txn(&self.store, txn, id, &row.body)?
        else {
            return Ok(None);
        };
        if manifest.facts.blake3 != *expected {
            return Err(Error::CorruptedIndex("blob content hash"));
        }
        // Only a mark on the file's own bytes is filled as they pass; one
        // inside a member is rebuilt from the whole body below.
        let spans = match sight {
            SecretSight::Masked => masked_file_in_txn(&self.store, txn, expected)?
                .filter(|mark| mark.members.is_empty())
                .map(|mark| {
                    mark.keys
                        .iter()
                        .map(|key| (key.start, key.end))
                        .collect::<Vec<_>>()
                }),
            SecretSight::Owner | SecretSight::Granted => None,
        };
        if spans.as_ref().is_some_and(|spans| {
            spans
                .iter()
                .any(|&(start, end)| start > end || end > manifest.facts.len)
        }) {
            return Err(Error::CorruptedIndex("masked file key span"));
        }
        let copy = self.with_asset_body_reader_in_txn(txn, id, |body| {
            let mut copy = Vec::with_capacity(usize::try_from(manifest.facts.len).unwrap_or(0));
            match &spans {
                Some(spans) => Filled {
                    inner: body,
                    at: 0,
                    spans,
                }
                .read_to_end(&mut copy)?,
                None => body.read_to_end(&mut copy)?,
            };
            Ok(copy)
        })?;
        let Some(copy) = copy else {
            return Ok(None);
        };
        if spans.is_some() {
            if crate::batch::secret_scan::scan_file_content("", &copy).is_some() {
                return Err(Error::InvariantViolation(
                    "a masked file still reads as secret",
                ));
            }
            return Ok(Some(copy));
        }
        if sight == SecretSight::Masked {
            return sighted_bytes_in_txn(&self.store, txn, copy, sight).map(Some);
        }
        Ok(Some(copy))
    }

    /// Whether ASSET `id` holds a readable body file named `expected`, its
    /// stored bytes read once through the checked reader, which verifies
    /// their length and BLAKE3, and dropped as they pass (FIX 6507): a door
    /// that must judge a file before its receipt is written checks it this
    /// way, never holding it whole. `false` when `id` holds no readable body
    /// file.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a file the door does not name; the
    /// checked reader's errors.
    pub(crate) fn check_body_file_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        expected: &[u8; 32],
    ) -> Result<bool> {
        let Some(row) = self.store.port_entity_record(txn, id)? else {
            return Ok(false);
        };
        if row.entity_type != ENTITY_TYPE_ASSET {
            return Ok(false);
        }
        let Some(manifest) = crate::store::asset_file_in_txn(&self.store, txn, id, &row.body)?
        else {
            return Ok(false);
        };
        if manifest.facts.blake3 != *expected {
            return Err(Error::CorruptedIndex("blob content hash"));
        }
        // The checked reader reads whatever the callback leaves, so the
        // whole file is verified.
        Ok(self
            .with_asset_body_reader_in_txn(txn, id, |_| Ok(()))?
            .is_some())
    }
}
