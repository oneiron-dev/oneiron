//! The optional identity-hint readers a queued turn actually carried.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::ScopedRead;
use crate::memory::{MemoryResult, OnDeviceIdentityHintReader};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum QueuedHintRead {
    Internal,
    Caller {
        readers: Vec<OnDeviceIdentityHintReader>,
        unknown: bool,
    },
}

impl QueuedHintRead {
    pub(super) fn caller(read: Option<OnDeviceIdentityHintReader>) -> Self {
        Self::Caller {
            unknown: read.is_none(),
            readers: read.into_iter().collect(),
        }
    }

    /// Internal bookkeeping does not clear a caller's constraint. Distinct
    /// captured positions remain distinct even when no hint can pick for all.
    pub(super) fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Internal, read) | (read, Self::Internal) => read.clone(),
            (
                Self::Caller {
                    readers: left,
                    unknown: left_unknown,
                },
                Self::Caller {
                    readers: right,
                    unknown: right_unknown,
                },
            ) => {
                let mut readers = left.clone();
                for read in right {
                    if !readers.contains(read) {
                        readers.push(read.clone());
                    }
                }
                Self::Caller {
                    readers,
                    unknown: *left_unknown || *right_unknown,
                }
            }
        }
    }

    pub(super) fn valid(&self) -> bool {
        match self {
            Self::Internal => true,
            Self::Caller { readers, unknown } => {
                (*unknown || !readers.is_empty()) && readers.iter().all(|read| read.valid())
            }
        }
    }

    pub(super) fn open<'v>(&self, vault: &'v Vault) -> MemoryResult<Option<ScopedRead<'v>>> {
        match self {
            Self::Caller {
                readers,
                unknown: false,
            } if readers.len() == 1 => readers[0].open(vault),
            _ => Ok(None),
        }
    }
}
