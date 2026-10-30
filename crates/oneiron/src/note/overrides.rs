//! A NOTE's own extraction, context and retention defaults (ARCH-0032: each
//! kind "carries its own extraction, context and retention defaults, and a
//! note may override them"). The kind stays the seed; the note's row names
//! only the members it overrides. Every gate that read the kind's descriptor
//! reads the note's defaults instead, with one get in the caller's read.
//!
//! An override is a NOTE policy, not an authority: a wider context lifts only
//! the NOTE floor, never a scope or grant check (OF-490), and a longer
//! retention delays cleanup's archive and the tombstone review but is not a
//! legal hold against an authorized delete or erase.

use super::documents::invalid;
use super::kinds::{self, ContextDefault, ExtractionDefault, NoteKindDescriptor, RetentionDefault};
use super::lifecycle::NoteRefRequest;
use super::sync_rows::SYNC_DS_E;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::{Memory, MemoryResult};
use crate::side_table::{self, HexId, Named, SideTable};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// One NOTE's overrides; absent when it overrides nothing. Key: id16(note).
pub(super) const NOTE_OVERRIDE: SideTable<EntityId, NoteOverrides, Named> =
    SideTable::new(&side_table::NOTE_OVERRIDE);

/// The members a NOTE overrides; an absent member inherits its kind's.
/// `archive_after_days` goes with `retention: archive_after_days` only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extraction: Option<ExtractionDefault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ContextDefault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionDefault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_after_days: Option<u32>,
}

impl NoteOverrides {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The registry's own rule for a descriptor: a finite retention names a
    /// positive day count, and no other retention names one.
    fn validate(&self) -> Result<()> {
        match (self.retention, self.archive_after_days) {
            (Some(RetentionDefault::ArchiveAfterDays), Some(1..))
            | (Some(RetentionDefault::Durable | RetentionDefault::SessionSealed), None)
            | (None, None) => Ok(()),
            _ => Err(invalid(
                "only an archive_after_days retention override names its days, and they are positive",
            )),
        }
    }

    fn apply(&self, defaults: &mut NoteKindDescriptor) {
        if let Some(extraction) = self.extraction {
            defaults.extraction = extraction;
        }
        if let Some(context) = self.context {
            defaults.context = context;
        }
        if let Some(retention) = self.retention {
            defaults.retention = retention;
            defaults.archive_after_days = self.archive_after_days;
        }
    }
}

/// `vault.notes.set_overrides`: the NOTE named and the overrides it now
/// carries, replacing any it had. Empty overrides clear them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetNoteOverridesRequest {
    pub note_ref: String,
    #[serde(default)]
    pub overrides: NoteOverrides,
}

/// A NOTE's overrides, and the defaults its gates read after them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteDefaultsView {
    pub overrides: NoteOverrides,
    pub defaults: NoteKindDescriptor,
}

/// `note`'s overrides inside the caller's read, if it has any.
pub(crate) fn note_overrides_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    note: &EntityId,
) -> Result<Option<NoteOverrides>> {
    NOTE_OVERRIDE.get(store, txn, note)
}

/// `note`'s context default: its own override, else its kind's. The kind is
/// checked against the registry either way.
pub(crate) fn note_context_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    note: &EntityId,
    kind: &str,
) -> Result<ContextDefault> {
    let context = kinds::context_in_txn(store, txn, kind)?;
    Ok(note_overrides_in_txn(store, txn, note)?
        .and_then(|overrides| overrides.context)
        .unwrap_or(context))
}

/// `note`'s defaults: its kind's descriptor with the note's overrides over
/// it. A plugin kind with no blessed descriptor seeds as every gate already
/// read it: relationship-scoped, never extracted, durable.
pub(crate) fn note_defaults_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    note: &EntityId,
    kind: &str,
) -> Result<NoteKindDescriptor> {
    let context = kinds::context_in_txn(store, txn, kind)?;
    let mut defaults = match kinds::descriptor_in_txn(store, txn, kind)? {
        Some(descriptor) => NoteKindDescriptor {
            context,
            ..descriptor
        },
        None => NoteKindDescriptor {
            pack: "plugin".into(),
            kind: kind.into(),
            extraction: ExtractionDefault::Disabled,
            context,
            retention: RetentionDefault::Durable,
            archive_after_days: None,
        },
    };
    if let Some(overrides) = note_overrides_in_txn(store, txn, note)? {
        overrides.apply(&mut defaults);
    }
    Ok(defaults)
}

/// Drops `note`'s overrides with its other rows on delete and erase.
pub(super) fn delete_overrides_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    note: &EntityId,
) -> Result<bool> {
    NOTE_OVERRIDE.delete(store, txn, note)
}

/// The overrides section of `note`'s next frame (FIX 3819): its row in the
/// side table's own encoding, or an empty set when it overrides nothing.
/// Read in the export's own `txn`, beside the seal it rides with.
#[cfg(feature = "sync")]
pub(crate) fn encode_frame_overrides_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: &EntityId,
) -> Result<Vec<u8>> {
    match note_overrides_in_txn(&vault.store, txn, note)? {
        Some(overrides) => {
            rmp_serde::to_vec_named(&overrides).map_err(|_| invalid("NOTE overrides encode"))
        }
        None => Ok(Vec::new()),
    }
}

/// Installs the overrides section of a NOTE frame (FIX 3819): it decodes
/// through [`NoteOverrides`] to its one canonical spelling, validates, and
/// lands beside a live NOTE row in the frame's own write, as
/// `set_note_overrides` lands it — an empty set deletes the row. A set that
/// does not decode or validate is refused like any undecodable frame. A
/// frame never recreates overrides for a NOTE this vault deleted, erased or
/// tombstoned; that stays `delete_overrides_in_txn`'s path.
#[cfg(feature = "sync")]
pub(crate) fn install_frame_overrides_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: &EntityId,
    overrides: &[u8],
) -> Result<()> {
    let row = if overrides.is_empty() {
        None
    } else {
        let row: NoteOverrides =
            rmp_serde::from_slice(overrides).map_err(|_| invalid("NOTE frame overrides"))?;
        let canonical =
            rmp_serde::to_vec_named(&row).map_err(|_| invalid("NOTE frame overrides"))?;
        if canonical != overrides {
            return Err(invalid("NOTE frame overrides"));
        }
        row.validate()?;
        Some(row)
    };
    if vault.local_hard_delete_marker_exists_in_txn(txn, note)?
        || crate::ports::TombstoneStore::port_tombstone_is_deleted(vault, txn, note)?
        || vault.get_entity_type_in_txn(txn, note)? != Some(crate::registry::ENTITY_TYPE_NOTE)
    {
        return Ok(());
    }
    match row {
        Some(row) if !row.is_empty() => NOTE_OVERRIDE.put(&vault.store, txn, note, &row),
        _ => NOTE_OVERRIDE.delete(&vault.store, txn, note).map(|_| ()),
    }
}

impl Vault {
    /// `note`'s overrides and the defaults its gates read.
    pub fn note_defaults(&self, note: EntityId) -> Result<NoteDefaultsView> {
        let txn = self.store.env.read_txn()?;
        defaults_view_in_txn(self, &txn, note)
    }

    /// Sets `note`'s overrides, by its author or the owner, as a seal is set
    /// (CALLS "FIX 2418 NOTE overrides"). A seal freezes the text, not these,
    /// so a sealed NOTE takes them too. A replica NOTE's need the authority
    /// its edits need, so they refuse.
    pub fn set_note_overrides(
        &self,
        note: EntityId,
        overrides: &NoteOverrides,
        actor: WriteActor,
    ) -> MemoryResult<NoteDefaultsView> {
        overrides.validate()?;
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_actor_content_write_txn_as(actor, |content| {
                content.update_note(note, |txn| {
                    let (_, core) = super::verbs::note_core(self, txn, note)?;
                    if SYNC_DS_E.contains(&self.store, txn, &HexId(note))? {
                        return Err(invalid(
                            "replica NOTE overrides require authenticated authority",
                        )
                        .into());
                    }
                    self.authorize_shared_note_write_in_txn(txn, note, &actor)?;
                    let owner = actor.actor_class() == EdgeActorClass::Human
                        && crate::memory::verify_owner_actor_binding_in_txn(
                            self,
                            txn,
                            actor.entity_ref(),
                        )
                        .is_ok();
                    if !owner && !core.author_ref.is(actor.entity_ref()) {
                        return Err(
                            invalid("NOTE overrides require its author or the owner").into()
                        );
                    }
                    if overrides.is_empty() {
                        NOTE_OVERRIDE.delete(&self.store, txn, &note)?;
                    } else {
                        NOTE_OVERRIDE.put(&self.store, txn, &note, overrides)?;
                    }
                    Ok(defaults_view_in_txn(self, txn, note)?)
                })
            })
    }
}

fn defaults_view_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> Result<NoteDefaultsView> {
    let (_, core) = super::verbs::note_core(vault, txn, note)?;
    Ok(NoteDefaultsView {
        overrides: note_overrides_in_txn(&vault.store, txn, &note)?.unwrap_or_default(),
        defaults: note_defaults_in_txn(&vault.store, txn, &note, core.kind.as_str().as_ref())?,
    })
}

impl Memory<'_> {
    /// `vault.notes.set_overrides`: sets one NOTE's overrides as this actor.
    pub fn set_note_overrides(
        &self,
        input: &SetNoteOverridesRequest,
    ) -> MemoryResult<NoteDefaultsView> {
        let note = crate::memory::resolve_entity_ref(self.vault(), &input.note_ref)?;
        self.vault()
            .set_note_overrides(note, &input.overrides, self.write_actor())
    }

    /// `vault.notes.defaults`: one NOTE's overrides and the defaults its
    /// gates read.
    pub fn note_defaults(&self, input: &NoteRefRequest) -> MemoryResult<NoteDefaultsView> {
        let note = crate::memory::resolve_entity_ref(self.vault(), &input.note_ref)?;
        Ok(self.vault().note_defaults(note)?)
    }
}
