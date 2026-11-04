//! An attempt's cleanup mark (`VAULT_CLEANUP_ATTEMPT_ARCHIVE`), keyed by
//! id16: a cleanup run's archive mark on a completed attempt, or the
//! owner's kept mark on an entry he brought back, each bound to a BLAKE3
//! revision of the bytes it marks; and the refresh that moves an attempt's
//! mark when its row is rewritten in place. Vault cleanup
//! (`vault_cleanup::{marks, attempt_retention}`) decides, writes, scans and
//! lifts the marks; the store's attempt payload retirement refreshes them.
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::attempt_id::AttemptId;

/// The mark table. Key: id16, an attempt's id or a kept record's entity id.
pub(crate) const MARK: SideTable<[u8; 16], Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_ATTEMPT_ARCHIVE);

pub(crate) const REVISION_LEN: usize = 32;

pub(crate) const RUN_MARK_LEN: usize = REVISION_LEN + 16;

/// A BLAKE3 revision of the bytes a mark binds.
pub(crate) type Revision = [u8; REVISION_LEN];

/// One decoded mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupMark {
    /// Cleanup run `run` archived the attempt at `revision`.
    Archived { revision: Revision, run: AttemptId },
    /// The owner kept the entry at `revision`.
    Kept { revision: Revision },
}

impl CleanupMark {
    pub(crate) fn decode(raw: &[u8]) -> Option<Self> {
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

    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Self::Archived { revision, run } => [revision.as_slice(), run.as_bytes()].concat(),
            Self::Kept { revision } => revision.to_vec(),
        }
    }

    /// This mark moved to `revision` when it binds `bound`, the bytes a row
    /// held before an in-place rewrite; none when it binds other bytes.
    pub(crate) fn moved(self, bound: &Revision, revision: &Revision) -> Option<Self> {
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
pub(crate) fn revision_of(bytes: &[u8]) -> Revision {
    *blake3::hash(bytes).as_bytes()
}

/// The mark row for `id` as stored, whatever it reads as.
pub(crate) fn raw_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 16],
) -> Result<Option<Vec<u8>>> {
    MARK.get(store, txn, id)
}

pub(crate) fn put_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &[u8; 16],
    mark: CleanupMark,
) -> Result<()> {
    MARK.put(store, txn, id, &mark.encode())
}

pub(crate) fn delete_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &[u8; 16]) -> Result<()> {
    MARK.delete(store, txn, id)?;
    Ok(())
}

/// Moves an attempt's cleanup mark to the bytes its row was rewritten to in
/// this transaction, when the mark bound the row as it stood (`before`): an
/// erase that rewrites a row in place leaves it archived by the same run
/// (FIX 7076), or kept by the owner. A stale or unreadable mark bound bytes
/// the row no longer holds, so it is removed, never rebound: no hash of
/// those bytes outlives the erase (FIX 7615). An absent mark stays absent.
pub(crate) fn refresh_archived_attempt_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    before: &[u8],
    after: &[u8],
) -> Result<()> {
    let bound = revision_of(before);
    let revision = revision_of(after);
    let Some(raw) = raw_in_txn(store, txn, id.as_bytes())? else {
        return Ok(());
    };
    match CleanupMark::decode(&raw).and_then(|mark| mark.moved(&bound, &revision)) {
        Some(moved) => put_in_txn(store, txn, id.as_bytes(), moved),
        None => delete_in_txn(store, txn, id.as_bytes()),
    }
}
