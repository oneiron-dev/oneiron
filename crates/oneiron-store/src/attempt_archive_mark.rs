//! An attempt's cleanup mark (`VAULT_CLEANUP_ATTEMPT_ARCHIVE`), keyed by
//! id16: a cleanup run's archive mark on a completed attempt, or the
//! owner's kept mark on an entry he brought back, each bound to a BLAKE3
//! revision of the bytes it marks; and the refresh that moves an attempt's
//! mark when its row is rewritten in place. Vault cleanup
//! (`vault_cleanup::{marks, attempt_retention}`) decides, writes, scans and
//! lifts the marks; the store's attempt payload retirement refreshes them.
use crate::attempt_id::AttemptId;
use oneiron_base::error::Result;

pub const REVISION_LEN: usize = 32;

pub const RUN_MARK_LEN: usize = REVISION_LEN + 16;

/// A BLAKE3 revision of the bytes a mark binds.
pub type Revision = [u8; REVISION_LEN];

/// One decoded mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupMark {
    /// Cleanup run `run` archived the attempt at `revision`.
    Archived { revision: Revision, run: AttemptId },
    /// The owner kept the entry at `revision`.
    Kept { revision: Revision },
}

impl CleanupMark {
    pub fn decode(raw: &[u8]) -> Option<Self> {
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

    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::Archived { revision, run } => [revision.as_slice(), run.as_bytes()].concat(),
            Self::Kept { revision } => revision.to_vec(),
        }
    }

    /// This mark moved to `revision` when it binds `bound`, the bytes a row
    /// held before an in-place rewrite; none when it binds other bytes.
    pub fn moved(self, bound: &Revision, revision: &Revision) -> Option<Self> {
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
pub fn revision_of(bytes: &[u8]) -> Revision {
    *blake3::hash(bytes).as_bytes()
}
