//! The authenticated NOTE state envelope (FIX 2401; OF-073): every NOTE
//! text-plane frame names its head, its head sequence and the seal its
//! authority holds, before the document bytes. A seal never moves once
//! written, so each frame carries the one seal or none, and a replica
//! installs it with the state it froze. Window carriers never carry a seal.

use crate::error::Result;
use crate::note::NoteSeal;
use crate::note::documents::invalid;
use crate::{EntityId, Vault};

/// Bytes of the head sequence field.
const SEQ_LEN: usize = 8;

/// Bytes of the seal length field. A zero length carries no seal.
const SEAL_LEN: usize = 4;

/// One NOTE frame's payload, read back.
pub(crate) struct NoteStateEnvelope<'a> {
    pub(crate) head: EntityId,
    pub(crate) seq: u64,
    pub(crate) seal: Option<NoteSeal>,
    pub(crate) document: &'a [u8],
}

/// The payload of `note`'s frame at `head` (its head document and head
/// sequence) over `document`, with the seal read in the export's own `txn`.
/// Its sealer reads as no one where this vault erased it.
pub(super) fn payload(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    (head, seq): (EntityId, u64),
    document: &[u8],
) -> Result<Vec<u8>> {
    let seal = match crate::note::note_seal_in_txn(&vault.store, txn, note)? {
        Some(mut seal) => {
            seal.sealed_by = seal.sealed_by.erased_here(vault, txn)?;
            rmp_serde::to_vec_named(&seal).map_err(|_| invalid("NOTE seal encode"))?
        }
        None => Vec::new(),
    };
    let len = u32::try_from(seal.len()).map_err(|_| invalid("NOTE seal encode"))?;
    Ok([
        head.as_bytes().as_slice(),
        &seq.to_be_bytes(),
        &len.to_be_bytes(),
        &seal,
        document,
    ]
    .concat())
}

impl<'a> NoteStateEnvelope<'a> {
    /// `payload`, a frame of `note`, read back. A seal must name `note`,
    /// decode to its one canonical spelling and hold a frontier.
    pub(crate) fn decode(note: EntityId, payload: &'a [u8]) -> Result<Self> {
        let malformed = || invalid("NOTE frame head");
        let (head, rest) = payload
            .split_at_checked(crate::entity_id::ENTITY_ID_LEN)
            .ok_or_else(malformed)?;
        let (seq, rest) = rest.split_at_checked(SEQ_LEN).ok_or_else(malformed)?;
        let (len, rest) = rest.split_at_checked(SEAL_LEN).ok_or_else(malformed)?;
        let head = EntityId::from_bytes(head.try_into().map_err(|_| malformed())?)
            .map_err(|_| malformed())?;
        let seq = u64::from_be_bytes(seq.try_into().map_err(|_| malformed())?);
        let len = u32::from_be_bytes(len.try_into().map_err(|_| malformed())?);
        let len = usize::try_from(len).map_err(|_| malformed())?;
        let (seal, document) = rest.split_at_checked(len).ok_or_else(malformed)?;
        let seal = if seal.is_empty() {
            None
        } else {
            let row: NoteSeal =
                rmp_serde::from_slice(seal).map_err(|_| invalid("NOTE frame seal"))?;
            let canonical =
                rmp_serde::to_vec_named(&row).map_err(|_| invalid("NOTE frame seal"))?;
            if canonical != seal
                || row.note != note
                || loro::Frontiers::decode(&row.frontier).is_err()
            {
                return Err(invalid("NOTE frame seal"));
            }
            Some(row)
        };
        Ok(Self {
            head,
            seq,
            seal,
            document,
        })
    }
}
