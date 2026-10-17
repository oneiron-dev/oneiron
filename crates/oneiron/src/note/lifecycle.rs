//! The one NOTE seal (ARCH-0032: `Active → Sealed → Archived → Tombstoned`).
//! Sealing freezes the note's document at its head and frontier. A later edit
//! opens a fork and leaves the seal intact: no frame, merge or head switch
//! moves a sealed head. The scratchpad's run-end seal is this seal too, so
//! every NOTE answers "sealed?" from one row.

use super::documents::{invalid, live_doc};
use super::sync_rows::SYNC_DS_E;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_NOTE;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::Store;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// One seal per NOTE. Key: id16(note).
pub(super) const NOTE_SEAL: SideTable<EntityId, NoteSeal, Named> =
    SideTable::new(&side_table::NOTE_SEAL);

/// What a seal froze: the NOTE's head document and that document's frontier,
/// and who sealed it when. A seal never moves once written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteSeal {
    #[serde(with = "crate::entity_id::serde_hex")]
    pub note: EntityId,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub document: EntityId,
    /// The head document's encoded oplog frontier at the seal.
    pub frontier: Vec<u8>,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub sealed_by: EntityId,
    pub sealed_at: u64,
}

/// Whether a NOTE is reachable, orthogonal to its mutability (ARCH-0032).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteLifecycleStatus {
    Active,
    Sealed,
    Archived,
    Tombstoned,
}

/// `vault.notes.seal` and `vault.notes.lifecycle`: the NOTE named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteRefRequest {
    pub note_ref: String,
}

/// `vault.notes.lifecycle`: where one NOTE stands, and its seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteLifecycleView {
    pub status: NoteLifecycleStatus,
    pub seal: Option<NoteSeal>,
}

/// `note`'s seal inside the caller's read, if it is sealed.
pub(crate) fn note_seal_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> Result<Option<NoteSeal>> {
    NOTE_SEAL.get(store, txn, &note)
}

/// Whether `note` is sealed: the gate every in-place NOTE write and every
/// after-seal extraction reads.
pub(crate) fn note_sealed_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> Result<bool> {
    NOTE_SEAL.contains(store, txn, &note)
}

/// Refuses an in-place write to a sealed `note`: a frame, a merge into its
/// head or a head switch.
pub(crate) fn refuse_sealed_note_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> MemoryResult<()> {
    if note_sealed_in_txn(store, txn, note)? {
        return Err(sealed_note());
    }
    Ok(())
}

pub(crate) fn sealed_note() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "this NOTE is sealed",
        &["A sealed NOTE's document is frozen; an edit opens a fork and the seal stays."],
    )
}

/// Seals `note` at its current head and frontier, by `by`, in the caller's
/// write. Sealing a sealed NOTE returns its seal unchanged. Callers check the
/// sealer's authority first.
pub(crate) fn seal_note_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    by: EntityId,
) -> Result<NoteSeal> {
    if let Some(seal) = NOTE_SEAL.get(&vault.store, txn, &note)? {
        return Ok(seal);
    }
    let doc = live_doc(vault, txn, note)?;
    let seal = NoteSeal {
        note,
        document: doc.head,
        frontier: doc.doc.oplog_frontiers().encode(),
        sealed_by: by,
        sealed_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
    };
    NOTE_SEAL.put(&vault.store, txn, &note, &seal)?;
    Ok(seal)
}

impl Vault {
    /// `note`'s seal, if it is sealed.
    pub fn note_seal(&self, note: EntityId) -> Result<Option<NoteSeal>> {
        let txn = self.store.env.read_txn()?;
        note_seal_in_txn(&self.store, &txn, note)
    }

    /// Where `note` stands: archived and tombstoned read the deletion
    /// markers, sealed reads the seal, and anything else is active.
    pub fn note_lifecycle(&self, note: EntityId) -> Result<NoteLifecycleStatus> {
        let txn = self.store.env.read_txn()?;
        if self.archive_tombstone_in_txn(&txn, &note)?.is_some() {
            return Ok(NoteLifecycleStatus::Archived);
        }
        if crate::ports::TombstoneStore::port_tombstone_is_deleted(self, &txn, &note)? {
            return Ok(NoteLifecycleStatus::Tombstoned);
        }
        if self.get_entity_type_in_txn(&txn, &note)? != Some(ENTITY_TYPE_NOTE) {
            return Err(invalid("entity is not a NOTE"));
        }
        Ok(if note_sealed_in_txn(&self.store, &txn, note)? {
            NoteLifecycleStatus::Sealed
        } else {
            NoteLifecycleStatus::Active
        })
    }

    /// Seals `note` by its author or the owner (OF-073; CALLS "OF-073 NOTE
    /// seal trigger"). A replica NOTE's seal needs the authority its edits
    /// need, so it is refused here.
    pub fn seal_note(&self, note: EntityId, actor: WriteActor) -> MemoryResult<NoteSeal> {
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_actor_content_write_txn_as(actor, |content| {
                content.update_note(note, |txn| {
                    let (_, core) = super::verbs::note_core(self, txn, note)?;
                    if SYNC_DS_E.contains(&self.store, txn, &HexId(note))? {
                        return Err(
                            invalid("replica NOTE seals require authenticated authority").into(),
                        );
                    }
                    self.authorize_shared_note_write_in_txn(txn, note, &actor)?;
                    let owner = actor.actor_class() == EdgeActorClass::Human
                        && crate::memory::verify_owner_actor_binding_in_txn(
                            self,
                            txn,
                            actor.entity_ref(),
                        )
                        .is_ok();
                    if !owner && core.author_ref != actor.entity_ref() {
                        return Err(invalid("NOTE seal requires its author or the owner").into());
                    }
                    Ok(seal_note_in_txn(self, txn, note, actor.entity_ref())?)
                })
            })
    }
}

impl Memory<'_> {
    /// `vault.notes.seal`: seals one NOTE as this actor.
    pub fn seal_note(&self, input: &NoteRefRequest) -> MemoryResult<NoteSeal> {
        let note = crate::memory::resolve_entity_ref(self.vault(), &input.note_ref)?;
        self.vault()
            .seal_note(note, WriteActor::new(self.actor(), self.actor_class()))
    }

    /// `vault.notes.lifecycle`: where one NOTE stands, and its seal.
    pub fn note_lifecycle(&self, input: &NoteRefRequest) -> MemoryResult<NoteLifecycleView> {
        let note = crate::memory::resolve_entity_ref(self.vault(), &input.note_ref)?;
        Ok(NoteLifecycleView {
            status: self.vault().note_lifecycle(note)?,
            seal: self.vault().note_seal(note)?,
        })
    }
}
