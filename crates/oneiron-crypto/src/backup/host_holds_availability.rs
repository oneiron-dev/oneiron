//! Content-free host-holds availability signed beside a backup (FIX 11545).
//!
//! The member stays encrypted. These facts name what the backup producer
//! sealed, or why it sealed none; they do not open or independently inspect it.

use serde::{Deserialize, Serialize};

use crate::codec::Reader;
use crate::error::{Error, Result};

/// Why a hosted vault's checkpoint carries no host-order family. Content
/// free.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostHoldsUnavailable {
    /// The host gave no usable recipient.
    RecipientMissing,
    /// The family did not read in the snapshot's transaction.
    ExportFailed,
    /// The family did not serialize or seal.
    SealFailed,
}

/// What a checkpoint carries of its vault's host-order family, for its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostHoldsAvailability {
    /// No host carries the vault: none is sealed, and none is owed.
    NotHosted,
    /// The complete family, sealed to this recipient at this epoch; its
    /// member's BLAKE3, which a restore's tag names.
    Sealed {
        recipient_id: [u8; 32],
        recipient_epoch: u64,
        member_blake3: [u8; 32],
    },
    /// None is sealed, and why.
    Unavailable(HostHoldsUnavailable),
}

/// One tag, a recipient id, its epoch and the sealed member's digest.
pub(super) const HOST_HOLDS_AVAILABILITY_LEN: usize = 1 + 32 + 8 + 32;

impl HostHoldsAvailability {
    /// The fixed, canonical availability field of a checkpoint fact.
    pub(super) fn encode_into(self, out: &mut Vec<u8>) {
        let (tag, recipient, epoch, member) = match self {
            Self::NotHosted => (0, [0; 32], 0, [0; 32]),
            Self::Sealed {
                recipient_id,
                recipient_epoch,
                member_blake3,
            } => (1, recipient_id, recipient_epoch, member_blake3),
            Self::Unavailable(HostHoldsUnavailable::RecipientMissing) => (2, [0; 32], 0, [0; 32]),
            Self::Unavailable(HostHoldsUnavailable::ExportFailed) => (3, [0; 32], 0, [0; 32]),
            Self::Unavailable(HostHoldsUnavailable::SealFailed) => (4, [0; 32], 0, [0; 32]),
        };
        out.push(tag);
        out.extend_from_slice(&recipient);
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(&member);
    }

    /// Reads exactly that field, rejecting unknown tags and nonzero padding.
    pub(super) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let tag = reader.take(1, "checkpoint fact host-holds tag")?[0];
        let recipient_id = reader.array("checkpoint fact host-holds recipient")?;
        let recipient_epoch = reader.u64("checkpoint fact host-holds epoch")?;
        let member_blake3 = reader.array("checkpoint fact host-holds member digest")?;
        let availability = match tag {
            0 => Self::NotHosted,
            1 => {
                return Ok(Self::Sealed {
                    recipient_id,
                    recipient_epoch,
                    member_blake3,
                });
            }
            2 => Self::Unavailable(HostHoldsUnavailable::RecipientMissing),
            3 => Self::Unavailable(HostHoldsUnavailable::ExportFailed),
            4 => Self::Unavailable(HostHoldsUnavailable::SealFailed),
            _ => return Err(Error::BackupMalformed("checkpoint fact host-holds tag")),
        };
        if recipient_id != [0; 32] || recipient_epoch != 0 || member_blake3 != [0; 32] {
            return Err(Error::BackupMalformed("checkpoint fact host-holds padding"));
        }
        Ok(availability)
    }
}
