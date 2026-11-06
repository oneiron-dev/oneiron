//! A saved period rewritten by erasure needs a new lens over its current
//! report. Store-only erasure records an empty intent row; the existing
//! home digest pass moves that intent to the native Dreamer queue.
use super::{
    DIGEST_PREFIX, SCHEDULE_PREFIX, WeaveDigestReader, WireDigest, digest_row_in, invalid,
};
use crate::Vault;
use crate::error::Result;
use crate::store::Store;

const PREFIX: &[u8] = b"weave:digest_rerender:v1:";

fn key(digest_key: &[u8]) -> Vec<u8> {
    [PREFIX, digest_key].concat()
}

pub(super) fn mark_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    digest_key: &[u8],
) -> Result<()> {
    store.vault_meta.put(txn, &key(digest_key), &[])?;
    Ok(())
}

pub(super) fn clear_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    digest_key: &[u8],
) -> Result<()> {
    store.vault_meta.delete(txn, &key(digest_key))?;
    Ok(())
}

pub(super) fn pending_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(store
        .vault_meta
        .prefix_iter(txn, PREFIX)?
        .next()
        .transpose()?
        .is_some())
}

/// A marker names the original saved period, never an Admin proof.
fn period(marker: &[u8]) -> Option<(WeaveDigestReader, u64, &[u8])> {
    let digest_key = marker.strip_prefix(PREFIX)?;
    let suffix = digest_key.strip_prefix(DIGEST_PREFIX)?;
    if suffix.len() != 1 + 16 + 8 {
        return None;
    }
    let (stem, at) = suffix.split_at(1 + 16);
    let reader = WeaveDigestReader::from_schedule_key(&[SCHEDULE_PREFIX, stem].concat())?;
    let scheduled_for = u64::from_be_bytes(at.try_into().ok()?);
    Some((reader, scheduled_for, digest_key))
}

impl Vault {
    /// Called only after the ordinary digest pass has proved this is home.
    /// Current reader authority, Owner schedule basis and model funding are
    /// still checked by the unchanged native lens execution path.
    pub(super) fn enqueue_weave_rerenders(&self, now: u64) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let markers = self
                .store
                .vault_meta
                .prefix_iter(&*txn, PREFIX)?
                .map(|row| row.map(|(key, _)| key.to_vec()))
                .collect::<Result<Vec<_>>>()?;
            for marker in markers {
                if let Some((reader, scheduled_for, digest_key)) = period(&marker)
                    && let Some(raw) = digest_row_in(&self.store, txn, digest_key)?
                {
                    let wire: WireDigest = serde_json::from_slice(&raw).map_err(|_| invalid())?;
                    if wire.lens.is_none()
                        && wire.lens_refused.is_none()
                        && wire
                            .sections
                            .iter()
                            .any(|section| !section.items.is_empty())
                    {
                        crate::dreamer_runner::DreamerRunnerStore::new(self)
                            .enqueue_weave_lens_in_txn(
                                txn,
                                reader,
                                scheduled_for,
                                wire.rendered_at,
                                wire.report_revision,
                                now,
                            )?;
                    }
                }
                // Enqueue and marker retirement share one commit. A missing
                // period, empty report or unrenderable namespace owes no job.
                self.store.vault_meta.delete(txn, &marker)?;
            }
            Ok(())
        })
    }
}
