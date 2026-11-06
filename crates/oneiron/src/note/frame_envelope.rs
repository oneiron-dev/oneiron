//! The authenticated NOTE state envelope and its strict payload decoder.

use crate::EntityId;
use crate::error::Result;
use crate::note::NoteSeal;
use crate::note::documents::invalid;

/// Bytes of the head sequence field.
const SEQ_LEN: usize = 8;

/// Bytes of the seal length field. A zero length carries no seal.
const SEAL_LEN: usize = 4;

/// Bytes of the overrides length field. A zero length carries none.
const OVERRIDES_LEN: usize = 4;

/// The largest overrides section a frame carries: four small policy
/// members encode far below this; anything larger is not our frame.
const MAX_OVERRIDES_LEN: usize = 1024;

/// One NOTE frame's payload, read back.
pub(crate) struct NoteStateEnvelope<'a> {
    pub(crate) head: EntityId,
    pub(crate) seq: u64,
    pub(crate) seal: Option<NoteSeal>,
    pub(crate) overrides: &'a [u8],
    pub(crate) document: &'a [u8],
}

impl<'a> NoteStateEnvelope<'a> {
    /// `payload`, a frame of `note`, read back. A seal must name `note`,
    /// decode to its one canonical spelling and hold a frontier. The
    /// overrides section is length-checked here and decoded where it
    /// installs; an empty set carries none.
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
        let (seal, rest) = rest.split_at_checked(len).ok_or_else(malformed)?;
        let (overrides_len, rest) = rest.split_at_checked(OVERRIDES_LEN).ok_or_else(malformed)?;
        let overrides_len = u32::from_be_bytes(overrides_len.try_into().map_err(|_| malformed())?);
        let overrides_len = usize::try_from(overrides_len).map_err(|_| malformed())?;
        if overrides_len > MAX_OVERRIDES_LEN {
            return Err(malformed());
        }
        let (overrides, document) = rest.split_at_checked(overrides_len).ok_or_else(malformed)?;
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
            overrides,
            document,
        })
    }
}
