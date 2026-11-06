//! The optional identity-hint readers a queued turn actually carried.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::ScopedRead;
use crate::memory::{MemoryResult, QueuedIdentityHintReader};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum QueuedHintRead {
    Internal,
    Caller {
        readers: Vec<QueuedIdentityHintReader>,
        unknown: bool,
    },
}

impl QueuedHintRead {
    pub(super) fn caller(read: Option<QueuedIdentityHintReader>) -> Self {
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

    pub(super) fn hold_room_turns(&self, vault: &Vault) -> Vec<crate::claim::TurnTerms> {
        match self {
            Self::Caller {
                readers,
                unknown: false,
            } => readers
                .iter()
                .filter_map(|reader| reader.hold_room_turn(vault))
                .collect(),
            _ => Vec::new(),
        }
    }

    pub(super) fn open<'v>(&self, vault: &'v Vault) -> MemoryResult<Option<Vec<ScopedRead<'v>>>> {
        match self {
            Self::Caller {
                readers,
                unknown: false,
            } if !readers.is_empty() => {
                let mut opened = Vec::with_capacity(readers.len());
                for reader in readers {
                    let Some(read) = reader.open(vault)? else {
                        return Ok(None);
                    };
                    opened.push(read);
                }
                Ok(Some(opened))
            }
            _ => Ok(None),
        }
    }
}
