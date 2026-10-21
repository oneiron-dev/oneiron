//! Cleanup marks keyed by id16: a run's archive mark on a completed attempt,
//! and the owner's kept mark on an entry he brought back.
//!
//! One row per id, and its length says what it is:
//!
//! * 48 bytes, `[revision 32][run 16]`: cleanup run `run` archived the
//!   attempt while its queue row hashed to `revision`. The mark holds only
//!   while the row's bytes do, and it names the run, so restoring and
//!   re-archiving identical bytes never lets an older run undo a newer
//!   archive.
//! * 32 bytes, `[revision]`: the owner kept the record or attempt at
//!   `revision`, by reverting its run or restoring it himself. No arm takes
//!   that revision again; an edit moves the revision and re-arms the arms.
//!
//! Any other length marks nothing.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// The mark table. Key: id16, an attempt's id or a kept record's entity id.
const MARK: SideTable<[u8; 16], Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_ATTEMPT_ARCHIVE);

const REVISION_LEN: usize = 32;
const RUN_MARK_LEN: usize = REVISION_LEN + 16;

/// A BLAKE3 revision of the bytes a mark binds.
pub(super) type Revision = [u8; REVISION_LEN];

/// One decoded mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CleanupMark {
    /// Cleanup run `run` archived the attempt at `revision`.
    Archived { revision: Revision, run: AttemptId },
    /// The owner kept the entry at `revision`.
    Kept { revision: Revision },
}

impl CleanupMark {
    pub(super) fn decode(raw: &[u8]) -> Option<Self> {
        match raw.len() {
            RUN_MARK_LEN => {
                let (revision, run) = raw.split_at(REVISION_LEN);
                Some(Self::Archived {
                    revision: revision.try_into().ok()?,
                    run: AttemptId::from_bytes(run).ok()?,
                })
            }
            REVISION_LEN => Some(Self::Kept {
                revision: raw.try_into().ok()?,
            }),
            _ => None,
        }
    }

    pub(super) fn encode(self) -> Vec<u8> {
        match self {
            Self::Archived { revision, run } => [revision.as_slice(), run.as_bytes()].concat(),
            Self::Kept { revision } => revision.to_vec(),
        }
    }

    /// This mark moved to `revision` when it binds `bound`, the bytes a row
    /// held before an in-place rewrite; none when it binds other bytes.
    pub(super) fn moved(self, bound: &Revision, revision: &Revision) -> Option<Self> {
        match self {
            Self::Archived {
                revision: held,
                run,
            } if held == *bound => Some(Self::Archived {
                revision: *revision,
                run,
            }),
            Self::Kept { revision: held } if held == *bound => Some(Self::Kept {
                revision: *revision,
            }),
            _ => None,
        }
    }
}

/// The BLAKE3 revision of `bytes`.
pub(super) fn revision_of(bytes: &[u8]) -> Revision {
    *blake3::hash(bytes).as_bytes()
}

/// The mark row for `id` as stored, whatever it reads as.
pub(super) fn raw_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 16],
) -> Result<Option<Vec<u8>>> {
    MARK.get(store, txn, id)
}

/// The decoded mark for `id`; a row that reads as neither mark is none.
pub(super) fn mark_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 16],
) -> Result<Option<CleanupMark>> {
    Ok(raw_in_txn(store, txn, id)?.and_then(|raw| CleanupMark::decode(&raw)))
}

pub(super) fn put_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &[u8; 16],
    mark: CleanupMark,
) -> Result<()> {
    MARK.put(store, txn, id, &mark.encode())
}

pub(super) fn delete_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &[u8; 16]) -> Result<()> {
    MARK.delete(store, txn, id)?;
    Ok(())
}

/// Every mark row, in id order.
pub(super) fn scan_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<([u8; 16], Vec<u8>)>> {
    MARK.scan(store, txn)
}

/// Whether the owner kept `id` at exactly the revision of `bytes`. The bytes
/// are hashed only when a kept mark is there to compare.
pub(super) fn kept_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 16],
    bytes: &[u8],
) -> Result<bool> {
    Ok(matches!(
        mark_in_txn(store, txn, id)?,
        Some(CleanupMark::Kept { revision }) if revision == revision_of(bytes)
    ))
}

/// The revision of `entity`'s stored record: the hash of its encoded record,
/// the same bytes the PERSON mint evidence binds. None when no record is
/// stored.
pub(super) fn record_revision_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<Revision>> {
    Ok(vault
        .store
        .port_entity_record(txn, entity)?
        .map(|row| revision_of(&row.encode())))
}

/// Keeps `entity` at its current record revision: the owner brought it back,
/// so no arm archives that revision again. A record with nothing stored is
/// left unmarked.
pub(super) fn keep_record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    if let Some(revision) = record_revision_in_txn(vault, txn, entity)? {
        put_in_txn(
            &vault.store,
            txn,
            entity.as_bytes(),
            CleanupMark::Kept { revision },
        )?;
    }
    Ok(())
}
