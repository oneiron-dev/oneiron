//! The vault's embedding setup in the logical whole-vault exports (OF-370): each declared
//! space's descriptor and the three kind-slot bindings, never a vector. Media vectors are
//! recomputed where the export lands, from the admitted ASSET bytes: an import declares or
//! binds the setup, and the media backfill fills each bound space. Vector rows and their text
//! hashes, a space's physical key, device provenance and locality, refusal caches, moves and
//! probes, and provider configuration stay home. A space id's `@where` names an offer key,
//! which the receiving host resolves against its own models.
use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::WholeVaultDocument;
use crate::config::VectorEvidenceFloors;
use crate::embed::{EmbeddingSpace, InputKind, KindSlotBindings};
use crate::error::{Error, Result};
use crate::side_table::SideTableDbs;

/// Which records an export holds, for [`carries_embedding_setup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportScope {
    /// Every record: the whole-vault JSON export and the whole-vault archive.
    WholeVault,
    /// Records a caller chose: an entity bundle of some ids, a records archive.
    Records,
    /// The lossy OKF bundle, which never re-imports as a vault.
    Okf,
}

/// Whether an export of `scope` carries the embedding setup: only a whole-vault export does.
/// The setup is vault-wide, so a record subset that carried it would bind a receiver's slots
/// for records it never held.
pub(super) const fn carries_embedding_setup(scope: ExportScope) -> bool {
    matches!(scope, ExportScope::WholeVault)
}

/// One declared space as an export carries it: its declaration's five fields, nothing else.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableEmbeddingSpace {
    /// `model@revision@where`, whole: a host without that offer declares it all the same, its
    /// vectors pending until a model there fills it.
    pub id: String,
    pub dimensions: usize,
    pub accepts: BTreeSet<InputKind>,
    pub query_towers: BTreeSet<InputKind>,
    /// The space's own evidence floors; `None` judges it by the receiver's vault floors.
    pub evidence: Option<PortableEvidenceFloors>,
}

/// A space's evidence floors as an export carries them.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableEvidenceFloors {
    pub floor: f32,
    pub strong: f32,
}

impl From<EmbeddingSpace> for PortableEmbeddingSpace {
    fn from(space: EmbeddingSpace) -> Self {
        Self {
            id: space.id,
            dimensions: space.dimensions,
            accepts: space.accepts,
            query_towers: space.query_towers,
            evidence: space.evidence.map(|floors| PortableEvidenceFloors {
                floor: floors.floor,
                strong: floors.strong,
            }),
        }
    }
}

impl PortableEmbeddingSpace {
    /// The declaration this descriptor names.
    #[must_use]
    pub fn declaration(&self) -> EmbeddingSpace {
        EmbeddingSpace {
            id: self.id.clone(),
            dimensions: self.dimensions,
            accepts: self.accepts.clone(),
            query_towers: self.query_towers.clone(),
            evidence: self.evidence.map(|floors| VectorEvidenceFloors {
                floor: floors.floor,
                strong: floors.strong,
            }),
        }
    }
}

/// The three kind slots as an export carries them: each bound space's id, or an explicit null
/// for an unbound slot (for text, the receiver's own vector index).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableSlotBindings {
    pub text: Option<String>,
    pub image: Option<String>,
    pub audio: Option<String>,
}

impl From<KindSlotBindings> for PortableSlotBindings {
    fn from(slots: KindSlotBindings) -> Self {
        Self {
            text: slots.text,
            image: slots.image,
            audio: slots.audio,
        }
    }
}

impl PortableSlotBindings {
    /// The space a kind's slot binds to; `None` when it is unbound.
    #[must_use]
    pub fn space_for(&self, kind: InputKind) -> Option<&str> {
        match kind {
            InputKind::Text => self.text.as_deref(),
            InputKind::Image => self.image.as_deref(),
            InputKind::Audio => self.audio.as_deref(),
        }
    }

    fn slot_mut(&mut self, kind: InputKind) -> &mut Option<String> {
        match kind {
            InputKind::Text => &mut self.text,
            InputKind::Image => &mut self.image,
            InputKind::Audio => &mut self.audio,
        }
    }

    /// The slots from the archive's slot rows, which name each kind exactly once.
    pub(crate) fn from_archive_rows(rows: Vec<Value>) -> Result<Self> {
        let mut slots = BTreeMap::new();
        for row in rows {
            let row: ArchiveSlotBinding =
                serde_json::from_value(row).map_err(|_| invalid("invalid archive slot binding"))?;
            if slots.insert(row.kind, row.space).is_some() {
                return Err(invalid("archive slot binding appears twice"));
            }
        }
        if slots.len() != InputKind::ALL.len() {
            return Err(invalid("archive slot bindings miss a kind"));
        }
        let mut take = |kind: InputKind| slots.remove(&kind).flatten();
        Ok(Self {
            text: take(InputKind::Text),
            image: take(InputKind::Image),
            audio: take(InputKind::Audio),
        })
    }
}

/// One row of the archive's `records/slot_binding.jsonl`; a null `space` is an unbound slot.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveSlotBinding {
    kind: InputKind,
    space: Option<String>,
}

/// The archive's slot rows, cut from the nulled document: one `{kind, space}` row per kind
/// slot, or none when the document carries no setup.
pub(crate) fn archive_slot_rows(document: &mut Value) -> Vec<Value> {
    match document.get_mut("slot_bindings").map(Value::take) {
        Some(Value::Object(slots)) => slots
            .into_iter()
            .map(|(kind, space)| serde_json::json!({"kind": kind, "space": space}))
            .collect(),
        _ => Vec::new(),
    }
}

/// Setup the export's nulling pass would have changed, so the export carries none of it, never
/// a nulled or substituted id: spaces by count (the text withheld is the id), slots by kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSetupWithheld {
    pub spaces: u64,
    pub slots: Vec<InputKind>,
}

impl EmbeddingSetupWithheld {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spaces == 0 && self.slots.is_empty()
    }
}

/// The setup a whole-vault export read in its snapshot.
pub(crate) struct ExportEmbeddingSetup {
    pub(crate) spaces: Vec<PortableEmbeddingSpace>,
    pub(crate) slots: PortableSlotBindings,
    pub(crate) withheld: EmbeddingSetupWithheld,
}

/// The vault's setup in `txn`: every declared space, in id order, and the three slots.
pub(super) fn embedding_setup_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<ExportEmbeddingSetup> {
    Ok(ExportEmbeddingSetup {
        spaces: crate::embed::embedding_spaces_in_txn(store, txn)?
            .into_iter()
            .map(PortableEmbeddingSpace::from)
            .collect(),
        slots: crate::embed::kind_slot_bindings_in_txn(store, txn)?.into(),
        withheld: EmbeddingSetupWithheld::default(),
    })
}

impl ExportEmbeddingSetup {
    /// The setup once `nulls`, the export's own nulling pass (true when it would change a
    /// value), has read each descriptor alone. A space or binding it would change is withheld
    /// whole and counted, never carried as a nulled or substituted id; a binding goes only
    /// beside the space it names.
    pub(crate) fn released(mut self, nulls: impl Fn(&Value) -> bool) -> Result<Self> {
        for space in std::mem::take(&mut self.spaces) {
            let value = serde_json::to_value(&space)
                .map_err(|_| Error::InvariantViolation("embedding setup JSON encode failed"))?;
            if nulls(&value) {
                self.withheld.spaces += 1;
            } else {
                self.spaces.push(space);
            }
        }
        for kind in InputKind::ALL {
            let carried = &self.spaces;
            let slot = self.slots.slot_mut(kind);
            if slot.as_deref().is_some_and(|id| {
                nulls(&Value::from(id)) || !carried.iter().any(|space| space.id == id)
            }) {
                *slot = None;
                self.withheld.slots.push(kind);
            }
        }
        Ok(self)
    }
}

/// What an archive's embedding setup did here (OF-370). It declares and binds only what is
/// absent here, through the owning doors, and never overwrites this vault's setup or refuses
/// the import over it. No vector travels: each bound space's vectors are pending until the
/// media backfill recomputes them from the admitted ASSET bytes, as a served vault's media
/// worker does on its next pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmbeddingSetupImport {
    /// Spaces declared here.
    pub declared_spaces: Vec<String>,
    /// Spaces already declared here with the same descriptor.
    pub unchanged_spaces: Vec<String>,
    /// Spaces declared here with another descriptor under the same id; this vault's stays.
    pub conflicted_spaces: Vec<String>,
    /// Slots bound here.
    pub bound_slots: Vec<InputKind>,
    /// Slots already bound here to the same space.
    pub unchanged_slots: Vec<InputKind>,
    /// Slots bound here to another space, or whose binding the owning checks refuse here (the
    /// space as declared here does not take it, or an open move carries the slot); this
    /// vault's stays.
    pub conflicted_slots: Vec<InputKind>,
    /// What the export's nulling pass withheld from the archive.
    pub withheld: EmbeddingSetupWithheld,
}

impl EmbeddingSetupImport {
    /// Whether the archive carried any setup. Its vectors never travel, so they are then
    /// pending recompute here.
    #[must_use]
    pub fn vectors_pending_recompute(&self) -> bool {
        !(self.declared_spaces.is_empty()
            && self.unchanged_spaces.is_empty()
            && self.conflicted_spaces.is_empty()
            && self.bound_slots.is_empty()
            && self.unchanged_slots.is_empty()
            && self.conflicted_slots.is_empty())
    }
}

/// What an import does with one descriptor.
enum SetupOutcome<T> {
    /// Nothing comes in: the archive's slot is unbound.
    Skip,
    /// Absent here: declare or bind it through its owning door.
    Write(T),
    /// Here alike.
    Unchanged,
    /// Here otherwise: this vault's stays.
    Conflict,
}

/// The import's conflict policy, for a space by its id and a slot by its kind alike: what this
/// vault holds against what the archive carries. Import never overwrites this vault's setup,
/// and no conflict refuses the import.
fn import_setup_outcome<T: PartialEq>(here: Option<T>, incoming: Option<T>) -> SetupOutcome<T> {
    match (here, incoming) {
        (_, None) => SetupOutcome::Skip,
        (None, Some(incoming)) => SetupOutcome::Write(incoming),
        (Some(here), Some(incoming)) if here == incoming => SetupOutcome::Unchanged,
        (Some(_), Some(_)) => SetupOutcome::Conflict,
    }
}

/// Declares each space the archive carries that is absent here, then binds each slot it binds
/// that is unbound here, in the import's own write. No model runs before the commit and no
/// provider is looked up: a space whose offer this host lacks is declared all the same, under
/// its own id, with its vectors pending recompute.
pub(super) fn import_embedding_setup_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    document: &WholeVaultDocument,
) -> Result<EmbeddingSetupImport> {
    let mut report = EmbeddingSetupImport {
        withheld: document.manifest.embedding_setup_withheld.clone(),
        ..EmbeddingSetupImport::default()
    };
    for space in &document.embedding_spaces {
        let incoming = space.declaration();
        let here = crate::embed::embedding_space_in_txn(store, txn, &space.id)?;
        match import_setup_outcome(here.as_ref(), Some(&incoming)) {
            SetupOutcome::Write(incoming) => {
                crate::embed::declare_embedding_space_in_txn(store, txn, incoming)?;
                report.declared_spaces.push(space.id.clone());
            }
            SetupOutcome::Unchanged => report.unchanged_spaces.push(space.id.clone()),
            SetupOutcome::Conflict => report.conflicted_spaces.push(space.id.clone()),
            SetupOutcome::Skip => {}
        }
    }
    let Some(slots) = &document.slot_bindings else {
        return Ok(report);
    };
    let here = crate::embed::kind_slot_bindings_in_txn(store, txn)?;
    for kind in InputKind::ALL {
        match import_setup_outcome(here.space_for(kind), slots.space_for(kind)) {
            SetupOutcome::Write(space) => {
                match crate::embed::bind_kind_slot_in_txn(store, txn, kind, space) {
                    Ok(()) => report.bound_slots.push(kind),
                    // The owning checks refuse the binding here: this vault's slot stays.
                    Err(Error::InvalidConfig(_)) => report.conflicted_slots.push(kind),
                    Err(error) => return Err(error),
                }
            }
            SetupOutcome::Unchanged => report.unchanged_slots.push(kind),
            SetupOutcome::Conflict => report.conflicted_slots.push(kind),
            SetupOutcome::Skip => {}
        }
    }
    Ok(report)
}

impl WholeVaultDocument {
    /// The setup's own shape: each descriptor a valid declaration under an id carried once,
    /// each binding naming a carried space, and no space without the slots. Whether a binding
    /// fits is the owning door's check at import, against the space as declared there.
    pub(super) fn validate_embedding_setup(&self) -> Result<()> {
        let mut ids = BTreeSet::new();
        for space in &self.embedding_spaces {
            space.declaration().validate()?;
            if !ids.insert(space.id.as_str()) {
                return Err(invalid("duplicate embedding space"));
            }
        }
        let Some(slots) = &self.slot_bindings else {
            return if ids.is_empty() {
                Ok(())
            } else {
                Err(invalid("embedding spaces without slot bindings"))
            };
        };
        if InputKind::ALL
            .iter()
            .any(|kind| slots.space_for(*kind).is_some_and(|id| !ids.contains(id)))
        {
            return Err(invalid(
                "slot binding names a space the archive does not carry",
            ));
        }
        Ok(())
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault import: {reason}"))
}
