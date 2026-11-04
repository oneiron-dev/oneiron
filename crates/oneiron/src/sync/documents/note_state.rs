//! The authenticated NOTE state envelope (FIX 2401; OF-073): every NOTE
//! text-plane frame names its head, its head sequence, the seal its
//! authority holds and the NOTE's own overrides, before the document bytes.
//! A seal never moves once written, so each frame carries the one seal or
//! none, and a replica installs it with the state it froze; the overrides
//! land in the same write (FIX 3819). Window carriers never carry a seal.

use crate::error::Result;
use crate::note::documents::invalid;
use crate::{EntityId, Vault};

pub(crate) use crate::note::frame_envelope::NoteStateEnvelope;

/// The payload of `note`'s frame at `head` (its head document and head
/// sequence) over `document`, with the seal and the NOTE's own overrides
/// read in the export's own `txn`. Its sealer reads as no one where this
/// vault erased it; a NOTE with no overrides carries an empty set.
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
    let overrides = crate::note::encode_frame_overrides_in_txn(vault, txn, &note)?;
    let overrides_len =
        u32::try_from(overrides.len()).map_err(|_| invalid("NOTE overrides encode"))?;
    Ok([
        head.as_bytes().as_slice(),
        &seq.to_be_bytes(),
        &len.to_be_bytes(),
        &seal,
        &overrides_len.to_be_bytes(),
        &overrides,
        document,
    ]
    .concat())
}
