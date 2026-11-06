//! Kept removal archives across a restore over the live vault (FIX 3679).
//!
//! An archive's row is Live: the live vault's row wins, and one it no
//! longer keeps stays absent. Its bytes are a body file owned by its removal
//! receipt, and that file's descriptor, digest holder and instance row are
//! content, restored from the image. Here they follow the row: each live
//! archive keeps its exact descriptor and holder as the live vault holds
//! them; the restore lands its file from the live vault when the image
//! carries none of its digest, under the instance the live rows bind it to,
//! which joins the image's rows so the restore's custody plan requires it;
//! and a receipt descriptor no live archive names goes, an image row's and
//! an opened payload's alike. An archive whose file cannot come with it
//! goes with a warning, rather than stand over a file the copy lacks. A
//! restore beside the vault, or one with no live vault, keeps the image's
//! archives and the image's files, and runs none of this.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use heed::RwTxn;

use super::write_budget::RestoreRoom;
use super::{CheckpointImage, codec_error};
use crate::provenance::body::{BodyState, owned_bodies_in_txn};
use crate::store::owned_body::{BODY, BODY_DIGEST};
use crate::store::result_body_pins::ResultBodyPin;
use crate::store::{
    BODY_KEYS, BodyDir, BodyFile, CustodyBinding, SealingStream, Store, body_key_in,
};
use crate::{EntityId, Result, Vault};

/// One live archive file the image does not carry.
struct LiveFile {
    /// The archive row it backs.
    row: Vec<u8>,
    /// The descriptor and digest-holder rows that name it, by key.
    names: [Vec<u8>; 2],
    digest: [u8; 32],
    len: u64,
    /// The instance the live rows bind it under: `None` for a plain file no
    /// checkpoint bound yet.
    instance: Option<[u8; 16]>,
    /// Whether it rests as an envelope, in a sealed directory.
    sealed: bool,
    file: BodyFile,
}

/// What a restore over the live vault carries of its kept removal archives
/// ([`carry_live`]), until the restored rows commit.
pub(super) struct LiveArchives {
    /// Every receipt the image or the live vault keeps an archive under:
    /// the owners whose descriptors this restore settles.
    receipts: BTreeSet<EntityId>,
    /// Each kept archive's descriptor and digest-holder rows, raw, as the
    /// live vault holds them, by key.
    wanted: BTreeMap<Vec<u8>, Vec<u8>>,
    files: Vec<LiveFile>,
    /// Keeps the live files from the live vault's collector until they land.
    _pin: ResultBodyPin,
}

/// The value of the row of `rows` under `key`; `rows` are sorted by key.
fn row_at<'r>(rows: &'r [(Vec<u8>, Vec<u8>)], key: &[u8]) -> Option<&'r [u8]> {
    rows.binary_search_by(|(at, _)| at.as_slice().cmp(key))
        .ok()
        .map(|at| rows[at].1.as_slice())
}

/// Reads from `current`, for each archive row the authority carry kept in
/// `image`, its exact descriptor and digest holder, and opens its file when
/// the image carries none of its digest; the instance row the file is bound
/// under joins the image's rows. A row whose descriptor `current` no longer
/// holds as named, or whose digest the image binds under another instance,
/// goes. `image_receipts` are the receipts the image kept archives under
/// before the carry replaced its archive rows.
///
/// # Errors
///
/// Storage, custody and filesystem errors of `current`.
pub(super) fn carry_live(
    image: &mut CheckpointImage,
    current: &Vault,
    image_receipts: BTreeSet<EntityId>,
) -> Result<LiveArchives> {
    let rows = image
        .databases
        .get_mut("vault_meta")
        .ok_or_else(codec_error)?;
    let carried = crate::federation::removal_archive_bindings_in_rows(rows);
    let mut receipts = image_receipts;
    receipts.extend(carried.iter().map(|(_, binding)| binding.receipt));
    // Pinned and guarded before the read that finds the files, held until
    // they land.
    let pin = current.pin_all_result_bodies();
    let _custody = current.store.gate_custody_read_guard()?;
    let txn = current.store.env.read_txn()?;
    let dir = current.store.body_dir()?;
    let mut wanted = BTreeMap::new();
    let mut files = Vec::new();
    let mut gone = BTreeSet::new();
    let mut key_rows = Vec::new();
    for (row, binding) in carried {
        let descriptor = BODY.key_bytes(&(binding.receipt, binding.occurrence));
        let holder = BODY_DIGEST.key_bytes(&(binding.body.blake3, binding.occurrence));
        let complete = BodyState::Complete {
            body: binding.body.clone(),
        };
        let named = current
            .store
            .vault_meta
            .get(&txn, &descriptor)?
            .filter(|raw| {
                BODY.decode_value(raw)
                    .is_ok_and(|body| body.state == complete)
            })
            .map(|raw| raw.to_vec());
        let held = current
            .store
            .vault_meta
            .get(&txn, &holder)?
            .map(|raw| raw.to_vec());
        let (Some(named), Some(held)) = (named, held) else {
            tracing::warn!(
                receipt = %binding.receipt.to_hex(),
                "a kept removal archive changed after the restore read it; its row goes (FIX 3679)"
            );
            gone.insert(row);
            continue;
        };
        let digest = binding.body.blake3;
        let key_at = BODY_KEYS.key_bytes(&digest);
        let live_key = crate::store::body_key_row_in_txn(&current.store, &txn, &digest)?;
        let image_key = row_at(rows, &key_at)
            .map(|raw| BODY_KEYS.decode_value(raw))
            .transpose()?;
        let file = match (&image_key, &live_key) {
            // The image lands this file under the instance the live rows name.
            (Some(image_key), Some(live_key)) if image_key == live_key => None,
            (Some(_), _) => {
                tracing::warn!(
                    receipt = %binding.receipt.to_hex(),
                    "the image binds a kept removal archive's bytes under another instance; its \
                     row goes (FIX 3679)"
                );
                gone.insert(row);
                continue;
            }
            (None, _) => {
                let Some(file) = dir.open_reader(&digest, binding.body.bytes, live_key.as_ref())?
                else {
                    tracing::warn!(
                        receipt = %binding.receipt.to_hex(),
                        "a kept removal archive's file is gone from the live vault; its row goes \
                         (FIX 3679)"
                    );
                    gone.insert(row);
                    continue;
                };
                Some(file)
            }
        };
        if let Some(file) = file {
            if let Some(live_key) = &live_key {
                key_rows.push((key_at, BODY_KEYS.encode_value(live_key)?));
            }
            files.push(LiveFile {
                row,
                names: [descriptor.clone(), holder.clone()],
                digest,
                len: binding.body.bytes,
                instance: live_key.as_ref().map(|row| row.instance),
                sealed: dir.sealed.is_some(),
                file,
            });
        }
        wanted.insert(descriptor, named);
        wanted.insert(holder, held);
    }
    let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = std::mem::take(rows)
        .into_iter()
        .filter(|(key, _)| !gone.contains(key))
        .collect();
    merged.extend(key_rows);
    *rows = merged.into_iter().collect();
    Ok(LiveArchives {
        receipts,
        wanted,
        files,
        _pin: pin,
    })
}

impl LiveArchives {
    /// The on-disk lengths of the files this restore lands from the live
    /// vault, for its room.
    pub(super) fn landing_lens(&self) -> impl Iterator<Item = u64> + '_ {
        self.files.iter().map(|live| live.len)
    }

    /// Lands each live file into `target`, the copy's `bodies/`, before any
    /// row naming it does: a sealed copy takes the envelope under the
    /// instance the live rows bind, its key read from `custody`, the custody
    /// the restored rows bind; a plain one takes the body opened. Each claims
    /// its room on `room` first. A file a sealed copy cannot take, one no
    /// instance binds yet, goes with its archive row from `image`.
    ///
    /// # Errors
    ///
    /// Custody, sealing and filesystem errors; a claim the disk's floor
    /// refuses.
    pub(super) fn land(
        &mut self,
        target: &BodyDir,
        custody: Option<&CustodyBinding>,
        room: &mut RestoreRoom<'_>,
        image: &mut CheckpointImage,
    ) -> Result<()> {
        let mut gone = BTreeSet::new();
        for live in std::mem::take(&mut self.files) {
            room.landing_body(live.len)?;
            let LiveFile {
                row,
                names,
                digest,
                len,
                instance,
                sealed,
                mut file,
            } = live;
            if target.sealed.is_none() {
                target.import_asset_body(&digest, len, &mut file)?;
                continue;
            }
            let (Some(instance), Some(custody)) = (instance, custody) else {
                tracing::warn!(
                    "a kept removal archive's plain file has no instance a sealed copy can take; \
                     its row goes (FIX 3679)"
                );
                for name in &names {
                    self.wanted.remove(name);
                }
                gone.insert(row);
                continue;
            };
            let key = body_key_in(custody, &instance)?;
            if sealed {
                target.import_sealed(&digest, len, file.into_stored(), key, false)?;
            } else {
                let stored = SealingStream::new(file, Arc::clone(&key), len, Some(digest))?;
                target.import_sealed(&digest, len, stored, key, false)?;
            }
        }
        if !gone.is_empty() {
            let rows = image
                .databases
                .get_mut("vault_meta")
                .ok_or_else(codec_error)?;
            rows.retain(|(key, _)| !gone.contains(key));
        }
        Ok(())
    }

    /// Settles the archive descriptors in `txn`, the restore's writer, once
    /// its rows and opened payload have landed: each kept archive's
    /// descriptor and holder stand as the live vault holds them, and every
    /// other descriptor of a receipt this restore settles is released, its
    /// file queued for the collector when nothing else holds its digest.
    /// What an erase owed or retired is the Live state's, carried already.
    ///
    /// # Errors
    ///
    /// Storage errors, and a descriptor that does not decode.
    pub(super) fn settle_in_txn(&self, store: &Store, txn: &mut RwTxn<'_>) -> Result<()> {
        for (key, value) in &self.wanted {
            store.vault_meta.put(txn, key, value)?;
        }
        for receipt in &self.receipts {
            for body in owned_bodies_in_txn(store, txn, receipt)? {
                if !self
                    .wanted
                    .contains_key(&BODY.key_bytes(&(body.owner, body.occurrence)))
                {
                    crate::provenance::body::release_body_in_txn(
                        store,
                        txn,
                        &body.owner,
                        &body.occurrence,
                    )?;
                }
            }
        }
        Ok(())
    }
}
