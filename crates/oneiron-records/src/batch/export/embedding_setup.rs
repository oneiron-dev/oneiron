//! Moved from `crates/oneiron/src/batch/export/embedding_setup.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::config::VectorEvidenceFloors;
use oneiron_store::embedding::EmbeddingSpace;
use oneiron_store::embedding_vocabulary::InputKind;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

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
