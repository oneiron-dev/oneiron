//! The record a copy edit held on its ruled cause leaves (FIX 10598, FIX
//! 10735): one typed row per held edit in the sync doctor's `x:` family,
//! hash and metadata only, never a byte of the edit. A window edit's row
//! names its window; a document copy lineage's names `e:` and its copy id.
//!
//! A held edit lands nowhere and is never applied: the visible diff found an
//! edit of the sealed-file placeholder (`sealed_file_edited`) or no unique
//! mapping onto the stored bytes (`projection_edit_conflict`). Its row names
//! the window, the hash of the source's key, the ruled cause and the hash of
//! what the peer wrote (its row, or its document update), so the owner's
//! `sync_doctor` lists it while the edit itself stays with the device that
//! wrote it. The same edit
//! sent again (a queued resend, or a later exchange that carries it) is
//! recorded once.

use super::rows::HeldEdit;
use crate::Vault;
use crate::error::Result;
use crate::origin::RepoProjectionHoldCause;
use crate::origin::secret_projection::edit::RepoProjectionDiffResult;
use crate::sync::quarantine::{
    QuarantineContainer, QuarantineRecord, crdt_key_metadata, quarantined_records, record_in_txn,
};

/// Records each of `held`, the edits one blob held on their ruled cause at
/// `place` (a window key, or `e:` and a copy id), that no row records yet, in
/// one writer.
///
/// # Errors
/// A store failure reading or writing the rows: the caller keeps nothing of
/// the blob, so the peer sends it again.
pub(super) fn record_held_edits(vault: &Vault, place: &str, held: &[HeldEdit]) -> Result<()> {
    let recorded = quarantined_records(vault)?;
    let at = vault.store.clock.now_recorded_at();
    let mut fresh: Vec<QuarantineRecord> = Vec::new();
    for edit in held {
        let (crdt_key_hash, crdt_key_len) = crdt_key_metadata(&edit.source.to_hex());
        let record = QuarantineRecord {
            window_key: place.to_owned(),
            container: QuarantineContainer::Entities,
            crdt_key_hash,
            crdt_key_len,
            reason_code: cause_code(&edit.cause).to_owned(),
            payload_hash: edit.edit,
            quarantined_at: at,
        };
        let known = |other: &QuarantineRecord| same_hold(other, &record);
        if recorded.iter().any(|(_, other)| known(other)) || fresh.iter().any(known) {
            continue;
        }
        fresh.push(record);
    }
    if fresh.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for record in &fresh {
            record_in_txn(vault, wtxn, record)?;
        }
        Ok(())
    })
}

/// Whether `a` and `b` record one hold: the same window, key, cause and
/// edit, whenever each was recorded.
fn same_hold(a: &QuarantineRecord, b: &QuarantineRecord) -> bool {
    a.window_key == b.window_key
        && a.container == b.container
        && a.crdt_key_hash == b.crdt_key_hash
        && a.crdt_key_len == b.crdt_key_len
        && a.reason_code == b.reason_code
        && a.payload_hash == b.payload_hash
}

/// The ruled reason code of a held edit's cause.
fn cause_code(cause: &RepoProjectionDiffResult) -> &'static str {
    match cause {
        RepoProjectionDiffResult::SealedFileEdited => {
            RepoProjectionHoldCause::SealedFileEdited.as_str()
        }
        _ => RepoProjectionHoldCause::ProjectionEditConflict.as_str(),
    }
}
