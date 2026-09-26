//! The document-row port: the ARCH-0023b entity-document families of one document slot.
//!
//! A slot owns a snapshot (`d:e:`), a cached state vector (`sv:e:`), a shallow-since version
//! vector (`ssv:e:`), pending updates (`u:e:`) and the counter that numbers appended updates
//! (`m:u_seq:e:`). Row bytes are opaque here: the CRDT codecs belong to the callers. An absent
//! state vector means a stale one (ARCH-0023b:81), so an append removes it and recovery never
//! trusts it.
use super::Transactions;
use crate::EntityId;
use crate::error::Result;

/// The document a set of rows belongs to, spelled as 32 lower-case hex characters in every key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DocumentSlot(EntityId);

impl DocumentSlot {
    pub(crate) fn of(id: EntityId) -> Self {
        Self(id)
    }

    /// A slot named by its key spelling. Only the canonical lower-case spelling names a slot, so
    /// a key read back re-encodes to the same bytes.
    #[cfg(feature = "sync")]
    pub(crate) fn from_hex(hex: &str) -> Result<Self> {
        Self::parse(hex).ok_or(crate::Error::CorruptedIndex("entity document slot"))
    }

    pub(super) fn parse(hex: &str) -> Option<Self> {
        let id = EntityId::from_hex(hex).ok()?;
        (id.to_hex() == hex).then_some(Self(id))
    }

    pub(crate) fn to_hex(self) -> String {
        self.0.to_hex()
    }
}

/// Where a pending update sits in its slot's replay order. Two writers number updates, and each
/// keeps its own key spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateSeq {
    /// An appended update, numbered by the slot's `m:u_seq:e:` counter: `{seq:08x}`.
    Sequence(u32),
    /// An entity-document commit, numbered by its head's generation: `{generation:020}`.
    Generation(u64),
}

/// One `u:e:` row key: its slot and its place in that slot's replay order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DocumentUpdateKey {
    pub(crate) slot: DocumentSlot,
    pub(crate) seq: UpdateSeq,
}

/// The single-row families of a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DocumentRow {
    Snapshot,
    StateVector,
    ShallowSince,
    UpdateSequence,
}

impl DocumentRow {
    pub(crate) const ALL: [Self; 4] = [
        Self::Snapshot,
        Self::StateVector,
        Self::ShallowSince,
        Self::UpdateSequence,
    ];
}

/// One pending update as stored, with its parsed place: `None` when the key after the slot
/// spells neither sequence form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingUpdate {
    pub(crate) seq: Option<UpdateSeq>,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) trait DocumentRowStore: Transactions {
    /// Appends one update at the slot's next sequence, advances the counter and marks the state
    /// vector stale. Returns the sequence the update took.
    #[cfg(any(feature = "sync", test))]
    fn port_document_update_append(
        &self,
        txn: &mut Self::Write<'_>,
        slot: DocumentSlot,
        update: &[u8],
    ) -> Result<u32>;
    /// Writes one update at a place its caller numbers; the counter does not move.
    #[cfg(feature = "sync")]
    fn port_document_update_put(
        &self,
        txn: &mut Self::Write<'_>,
        slot: DocumentSlot,
        seq: UpdateSeq,
        update: &[u8],
    ) -> Result<()>;
    fn port_document_snapshot_put(
        &self,
        txn: &mut Self::Write<'_>,
        slot: DocumentSlot,
        snapshot: &[u8],
    ) -> Result<()>;
    fn port_document_state_vector_put(
        &self,
        txn: &mut Self::Write<'_>,
        slot: DocumentSlot,
        state_vector: &[u8],
    ) -> Result<()>;
    #[cfg(any(feature = "sync", test))]
    fn port_document_state_vector_mark_stale(
        &self,
        txn: &mut Self::Write<'_>,
        slot: DocumentSlot,
    ) -> Result<()>;
    fn port_document_shallow_since_put(
        &self,
        txn: &mut Self::Write<'_>,
        slot: DocumentSlot,
        shallow_since: &[u8],
    ) -> Result<()>;
    /// Deletes the named single rows of a slot; an absent row is not an error.
    fn port_document_rows_delete(
        &self,
        txn: &mut Self::Write<'_>,
        slot: DocumentSlot,
        rows: &[DocumentRow],
    ) -> Result<()>;
    /// Deletes every pending update of a slot.
    fn port_document_updates_delete(
        &self,
        txn: &mut Self::Write<'_>,
        slot: DocumentSlot,
    ) -> Result<()>;

    /// The stored bytes of one single row.
    fn port_document_row(
        &self,
        txn: &Self::Read<'_>,
        slot: DocumentSlot,
        row: DocumentRow,
    ) -> Result<Option<Vec<u8>>>;
    fn port_document_updates(
        &self,
        txn: &Self::Read<'_>,
        slot: DocumentSlot,
    ) -> Result<Vec<PendingUpdate>>;
    /// The slot of every stored snapshot, `None` for a key that names no slot.
    fn port_document_snapshot_slots(
        &self,
        txn: &Self::Read<'_>,
    ) -> Result<Vec<Option<DocumentSlot>>>;
    /// The key of every stored update, `None` for a key that spells no slot and place.
    fn port_document_update_keys(
        &self,
        txn: &Self::Read<'_>,
    ) -> Result<Vec<Option<DocumentUpdateKey>>>;
}
