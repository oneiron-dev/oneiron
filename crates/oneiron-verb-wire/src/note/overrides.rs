//! Moved from `crates/oneiron/src/note/overrides.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::note::documents::invalid;
use crate::note::lifecycle::NoteRefRequest;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::note_kind::ContextDefault;
use oneiron_store::note_kind::ExtractionDefault;
use oneiron_store::note_kind::NoteKindDescriptor;
use oneiron_store::note_kind::RetentionDefault;
use oneiron_store::side_table::key::HexId;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;

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
