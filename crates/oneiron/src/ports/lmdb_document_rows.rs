//! LMDB/session adapter of the document-row port, over the declared `sync_state` families.
use super::{
    DocumentRow, DocumentRowStore, DocumentSlot, DocumentUpdateKey, PendingUpdate, UpdateSeq,
};
use crate::error::Result;
use crate::side_table::{self, FixedSideKey, Raw, SideKey, SideTable};
use crate::store::ManifestDbs;
use heed::{RoTxn, RwTxn};

const SNAPSHOT: SideTable<DocumentSlot, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_SNAPSHOT);
const STATE_VECTOR: SideTable<DocumentSlot, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_STATE_VECTOR);
const SHALLOW_SINCE: SideTable<DocumentSlot, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_SHALLOW_SINCE);
/// The `m:u_seq:e:` counter: the last appended sequence, four big-endian bytes.
const UPDATE_SEQUENCE: SideTable<DocumentSlot, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_M_U_SEQ_E);
const UPDATES: SideTable<DocumentUpdateKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_UPDATE);

fn table(row: DocumentRow) -> SideTable<DocumentSlot, Vec<u8>, Raw> {
    match row {
        DocumentRow::Snapshot => SNAPSHOT,
        DocumentRow::StateVector => STATE_VECTOR,
        DocumentRow::ShallowSince => SHALLOW_SINCE,
        DocumentRow::UpdateSequence => UPDATE_SEQUENCE,
    }
}

/// The key bytes of every update of one slot: `{slot}:`.
fn slot_updates(slot: DocumentSlot) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(DocumentSlot::WIDTH + 1);
    slot.encode_into(&mut prefix);
    prefix.push(b':');
    prefix
}

impl SideKey for DocumentSlot {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_hex().as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Self::parse(std::str::from_utf8(bytes).ok()?)
    }
}

impl FixedSideKey for DocumentSlot {
    const WIDTH: usize = 32;
}

impl SideKey for UpdateSeq {
    fn encode_into(&self, out: &mut Vec<u8>) {
        let spelled = match self {
            Self::Sequence(seq) => format!("{seq:08x}"),
            Self::Generation(generation) => format!("{generation:020}"),
        };
        out.extend_from_slice(spelled.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        match bytes.len() {
            8 if bytes
                .iter()
                .all(|&b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                u32::from_str_radix(text, 16).ok().map(Self::Sequence)
            }
            20 if bytes.iter().all(u8::is_ascii_digit) => text.parse().ok().map(Self::Generation),
            _ => None,
        }
    }
}

impl SideKey for DocumentUpdateKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.slot.encode_into(out);
        out.push(b':');
        self.seq.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (slot, rest) = bytes.split_at_checked(DocumentSlot::WIDTH)?;
        Some(Self {
            slot: DocumentSlot::decode_key(slot)?,
            seq: UpdateSeq::decode_key(rest.strip_prefix(b":")?)?,
        })
    }
}

/// A stored counter that is not four bytes, refused as the sync plane has always refused it.
#[cfg(feature = "sync")]
fn malformed_update_sequence() -> crate::Error {
    crate::Error::sync_protocol(crate::error::SyncProtocolValidation::InvalidDocumentKey)
}

/// A stored counter that is not four bytes; the sync plane's refusal needs the sync build.
#[cfg(all(not(feature = "sync"), test))]
fn malformed_update_sequence() -> crate::Error {
    crate::Error::CorruptedIndex("entity document update sequence")
}

impl<T: ManifestDbs> DocumentRowStore for T {
    #[cfg(any(feature = "sync", test))]
    fn port_document_update_append(
        &self,
        txn: &mut RwTxn<'_>,
        slot: DocumentSlot,
        update: &[u8],
    ) -> Result<u32> {
        let seq = match UPDATE_SEQUENCE.get(self, txn, &slot)? {
            Some(bytes) => u32::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| malformed_update_sequence())?,
            ),
            None => 0,
        }
        .checked_add(1)
        .ok_or(crate::Error::InvariantViolation(
            "document sequence exhausted",
        ))?;
        let key = DocumentUpdateKey {
            slot,
            seq: UpdateSeq::Sequence(seq),
        };
        UPDATES.put(self, txn, &key, &update.to_vec())?;
        UPDATE_SEQUENCE.put(self, txn, &slot, &seq.to_be_bytes().to_vec())?;
        self.port_document_state_vector_mark_stale(txn, slot)?;
        Ok(seq)
    }

    #[cfg(feature = "sync")]
    fn port_document_update_put(
        &self,
        txn: &mut RwTxn<'_>,
        slot: DocumentSlot,
        seq: UpdateSeq,
        update: &[u8],
    ) -> Result<()> {
        UPDATES.put(
            self,
            txn,
            &DocumentUpdateKey { slot, seq },
            &update.to_vec(),
        )
    }

    fn port_document_snapshot_put(
        &self,
        txn: &mut RwTxn<'_>,
        slot: DocumentSlot,
        snapshot: &[u8],
    ) -> Result<()> {
        SNAPSHOT.put(self, txn, &slot, &snapshot.to_vec())
    }

    fn port_document_state_vector_put(
        &self,
        txn: &mut RwTxn<'_>,
        slot: DocumentSlot,
        state_vector: &[u8],
    ) -> Result<()> {
        STATE_VECTOR.put(self, txn, &slot, &state_vector.to_vec())
    }

    #[cfg(any(feature = "sync", test))]
    fn port_document_state_vector_mark_stale(
        &self,
        txn: &mut RwTxn<'_>,
        slot: DocumentSlot,
    ) -> Result<()> {
        STATE_VECTOR.delete(self, txn, &slot)?;
        Ok(())
    }

    fn port_document_shallow_since_put(
        &self,
        txn: &mut RwTxn<'_>,
        slot: DocumentSlot,
        shallow_since: &[u8],
    ) -> Result<()> {
        SHALLOW_SINCE.put(self, txn, &slot, &shallow_since.to_vec())
    }

    fn port_document_rows_delete(
        &self,
        txn: &mut RwTxn<'_>,
        slot: DocumentSlot,
        rows: &[DocumentRow],
    ) -> Result<()> {
        for row in rows {
            table(*row).delete(self, txn, &slot)?;
        }
        Ok(())
    }

    fn port_document_updates_delete(&self, txn: &mut RwTxn<'_>, slot: DocumentSlot) -> Result<()> {
        UPDATES.delete_from(self, txn, &slot_updates(slot))?;
        Ok(())
    }

    fn port_document_row(
        &self,
        txn: &RoTxn<'_>,
        slot: DocumentSlot,
        row: DocumentRow,
    ) -> Result<Option<Vec<u8>>> {
        table(row).get_bytes(self, txn, &slot)
    }

    fn port_document_updates(
        &self,
        txn: &RoTxn<'_>,
        slot: DocumentSlot,
    ) -> Result<Vec<PendingUpdate>> {
        UPDATES
            .iter_raw_from(self, txn, &slot_updates(slot))?
            .map(|row| {
                let (key, bytes) = row?;
                let seq = DocumentUpdateKey::decode_key(&key).map(|key| key.seq);
                Ok(PendingUpdate { seq, bytes })
            })
            .collect()
    }

    fn port_document_snapshot_slots(&self, txn: &RoTxn<'_>) -> Result<Vec<Option<DocumentSlot>>> {
        SNAPSHOT
            .iter_raw_from(self, txn, &[])?
            .map(|row| row.map(|(key, _)| DocumentSlot::decode_key(&key)))
            .collect()
    }

    fn port_document_update_keys(&self, txn: &RoTxn<'_>) -> Result<Vec<Option<DocumentUpdateKey>>> {
        UPDATES
            .iter_raw_from(self, txn, &[])?
            .map(|row| row.map(|(key, _)| DocumentUpdateKey::decode_key(&key)))
            .collect()
    }
}
