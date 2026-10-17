//! LFS objects the historical lift sweep reads again (OF-067, Engine ruling
//! D = a). A new object whose bytes hold a hit the write door's reading
//! finds is refused before it is published. One stored before keeps its
//! bytes under its oid, which names them: the sweep reads it again as an
//! upload's install does, in the order its chunks make it, and a hit marks
//! the object. A marked object is withheld from every reader off this device
//! (`sync::chunks::lfs_object_withheld`), and the owner gets the proposal.
//! A key inside one chunk is marked with that chunk's ASSET by the records
//! walk; a key split over two chunks only the object's mark covers.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::LfsOid;
use super::chunks::{LfsManifest, asset_body_in_txn, read_chunk_in_txn};
use super::lifecycle::DELETED;
use super::scanner::CredentialStream;
use super::store::OBJECTS;
use super::upload::LFS_WHOLE_SCAN_MAX;
use crate::Vault;
use crate::batch::secret_scan::write_payload_hit;
use crate::error::{Error, GateError, Result};
use crate::secret_custody::{CarrierMark, carrier_mark_in_txn, put_carrier_mark_in_txn};
use crate::side_table;

impl Vault {
    /// The hit the write door's reading finds in the stored object `oid`,
    /// when the sweep has not marked it.
    pub(crate) fn lfs_object_lift_hit_in_txn(
        &self,
        txn: &RoTxn<'_>,
        oid: LfsOid,
    ) -> Result<Option<&'static str>> {
        if lifted_mark_in_txn(self, txn, oid)? {
            return Ok(None);
        }
        lfs_object_hit_in_txn(self, txn, oid)
    }

    /// Marks the stored object `oid` when its bytes hold a hit, in the
    /// caller's transaction. Its bytes, chunks and manifest stay as they
    /// are. The hit's reason, or `None` when nothing is left to mark.
    pub(crate) fn lift_lfs_object_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        oid: LfsOid,
    ) -> Result<Option<&'static str>> {
        let Some(reason) = self.lfs_object_lift_hit_in_txn(txn, oid)? else {
            return Ok(None);
        };
        let marked_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        put_carrier_mark_in_txn(
            &self.store,
            txn,
            &side_table::ORIGIN_LFS_OBJECT,
            oid.as_bytes(),
            &CarrierMark {
                version: *oid.as_bytes(),
                reason: reason.to_owned(),
                withheld: Vec::new(),
                marked_at,
            },
        )?;
        Ok(Some(reason))
    }

    /// Whether the lift sweep marked the object `oid`: its bytes hold a hit
    /// a new upload is refused for, so no reader off this device gets them.
    pub fn lfs_object_secret_withheld(&self, oid: LfsOid) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        lifted_mark_in_txn(self, &txn, oid)
    }
}

fn lifted_mark_in_txn(vault: &Vault, txn: &RoTxn<'_>, oid: LfsOid) -> Result<bool> {
    Ok(carrier_mark_in_txn(
        &vault.store,
        txn,
        &side_table::ORIGIN_LFS_OBJECT,
        oid.as_bytes(),
        oid.as_bytes(),
    )?
    .is_some())
}

/// The install's reading of a stored object, with the owner's switch on:
/// each distinct chunk by the batch door, the stream rules across each chunk
/// edge, and, within the whole-scan bound, the object read whole.
fn lfs_object_hit_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    oid: LfsOid,
) -> Result<Option<&'static str>> {
    if DELETED.contains(&vault.store, txn, &oid)? {
        return Ok(None);
    }
    let Some(object) = OBJECTS
        .get(&vault.store, txn, &oid)?
        .map(|record| record.with_oid(oid))
    else {
        return Ok(None);
    };
    let manifest = LfsManifest::decode(&asset_body_in_txn(vault, txn, &object.asset_id)?)
        .map_err(|_| Error::CorruptedIndex("lfs manifest"))?;
    if manifest.asset_id()? != object.asset_id || manifest.size_bytes != object.size_bytes {
        return Err(Error::CorruptedIndex("lfs manifest digest"));
    }
    let bounded = manifest.size_bytes <= LFS_WHOLE_SCAN_MAX;
    let mut stream = CredentialStream::with_write_seam(!bounded);
    let mut whole = Vec::new();
    let mut seen = BTreeSet::new();
    for chunk in &manifest.chunks {
        let bytes = read_chunk_in_txn(vault, txn, chunk)?;
        if let Some(reason) = refusal(stream.feed(&bytes)) {
            return Ok(Some(reason));
        }
        if seen.insert(chunk.hash)
            && let Some(reason) = write_payload_hit(&bytes)
        {
            return Ok(Some(reason));
        }
        if bounded {
            whole.extend_from_slice(&bytes);
        }
    }
    if let Some(reason) = refusal(stream.finish()) {
        return Ok(Some(reason));
    }
    Ok(if bounded {
        write_payload_hit(&whole)
    } else {
        None
    })
}

/// The reason a scan that refuses gives, for a reader that marks instead.
fn refusal(scanned: Result<()>) -> Option<&'static str> {
    match scanned {
        Ok(()) => None,
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => Some(
            reason_codes
                .last()
                .copied()
                .unwrap_or("gate.secret_scan.detected"),
        ),
        Err(_) => Some("gate.secret_scan.detected"),
    }
}
