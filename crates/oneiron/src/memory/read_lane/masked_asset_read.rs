//! `vault.assets.masked_read`'s lane read: one admitted ASSET's bytes, always masked.

use super::*;

/// The verb a Grant lists to name a masked asset read: the row's own name. This
/// method exists only for that row, so the check names it directly.
const MASKED_ASSET_READ_VERB: &str = "vault.assets.masked_read";

impl Memory<'_> {
    /// Reads `entity_ref` as its ASSET bytes, always masked, in the lane's
    /// snapshot: the caller's live owner Grant naming the verb is checked in
    /// the same snapshot, and without one the read is refused. Readability is
    /// judged before the type: a ref that resolves to nothing, a row the lane
    /// withholds, a deleted shell, and a row that is no ASSET answer `None`,
    /// exactly like a missing target; the receipt counts only rows the key
    /// could read. An admitted ASSET answers its bytes as a masked reader
    /// reads them in that same snapshot
    /// ([`repo_asset_body_in_txn`](crate::memory::repo_secret_reads::repo_asset_body_in_txn)):
    /// a repo file a mark covers, or a value custody knows reads in, answers
    /// its projection; a file stored with keys in it answers its copy with
    /// each key overwritten
    /// ([`sighted_bytes_in_txn`](crate::store::file_key_masks::sighted_bytes_in_txn));
    /// a file no masked copy is served of, and bytes in which the release
    /// scan still reads a credential, answer `None`, as a withheld row does;
    /// every other ASSET answers its stored bytes unchanged. The snapshot is
    /// the known-value pass's own ([`with_known_snapshot`](crate::Vault::with_known_snapshot), FIX 8966),
    /// so the bytes and the values matched against them are one state and the
    /// thread holds one read transaction (LMDB's one reader slot per thread).
    /// There is no cap and no pin: the row is read live. Record verbs serve
    /// every claim status, so the lane is `Recorded` as `vault.get` opens it.
    pub(crate) fn masked_asset_read(
        &self,
        entity_ref: &str,
    ) -> MemoryResult<ScopedReadResult<Option<(EntityId, Vec<u8>)>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let target = self.read_target(entity_ref, ReadMode::Live)?;
        let _bodies = lane.prepare_point_read::<MemoryError>()?;
        let vault = self.vault();
        vault.with_known_snapshot(|known, txn| {
            Ok(
                lane.read_projected_in_txn(txn, &point_reads(&[target]), None, |txn, rows| {
                    let standing = crate::authority::principal_standing_in_txn(
                        vault,
                        txn,
                        self.actor(),
                        self.actor_class(),
                        MASKED_ASSET_READ_VERB,
                    )?;
                    if standing.is_none() {
                        return Err(masked_asset_read_refused());
                    }
                    let Some(row) = rows.into_iter().next().flatten() else {
                        return Ok::<_, MemoryError>(None);
                    };
                    if row.entity_type != crate::registry::ENTITY_TYPE_ASSET {
                        return Ok(None);
                    }
                    let candidate = self.read_world_candidate(&lane, txn, &row);
                    let Some(body) = row.body else {
                        return Ok(None);
                    };
                    let id = row.id;
                    let served = crate::memory::repo_secret_reads::repo_asset_body_in_txn(
                        vault,
                        txn,
                        &id,
                        row.entity_type,
                        &body,
                        known,
                    )?
                    .unwrap_or(body);
                    // A file stored with keys in it reads as its copy with each
                    // key overwritten; a file no masked copy is served of
                    // (sealed, or one whose copy still holds a key) answers
                    // `None`, as a withheld row does (#7149 review round 1).
                    let served = match crate::store::file_key_masks::sighted_bytes_in_txn(
                        &vault.store,
                        txn,
                        served,
                        None,
                        crate::secret_custody::SecretSight::Masked,
                    ) {
                        Ok(served) => served,
                        Err(crate::error::Error::Secret(
                            crate::error::SecretError::MaskedCopyWithheld { .. }
                            | crate::error::SecretError::SealedFileWithheld,
                        )) => return Ok(None),
                        Err(error) => return Err(MemoryError::from(error)),
                    };
                    // Bytes the release scan still reads a credential in, such
                    // as a body stored while the write door's scan was off with
                    // no mark to mask by, answer `None` too: serve still redacts.
                    if crate::batch::secret_scan::scan_file_content("", &served).is_some() {
                        return Ok(None);
                    }
                    if let Some(candidate) = candidate {
                        candidate.served();
                    }
                    self.produced_from([id]);
                    Ok(Some((id, served)))
                }),
            )
        })?
    }
}

/// The read's refusal of a caller with no live Grant naming the verb.
fn masked_asset_read_refused() -> MemoryError {
    MemoryError::new(
        crate::memory::MEMORY_CODE_FORBIDDEN,
        format!(
            "{MASKED_ASSET_READ_VERB} takes a live Grant naming the verb: no live Grant from a live owner names this caller and lists the verb"
        ),
        &["Have the owner grant this caller the verb by name."],
    )
}
