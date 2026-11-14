//! Moved from `crates/oneiron/src/embed/space.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::embedding::EMBEDDING_SETUP_LEARNED_AT;
pub use oneiron_store::embedding::EMBEDDING_SPACE_ID_MAX_LEN;
pub use oneiron_store::embedding::EMBEDDING_SPACE_MAX_DIMENSIONS;
pub use oneiron_store::embedding::EmbeddingSpace;
pub use oneiron_store::embedding::KindSlotBindings;
pub(super) use oneiron_store::embedding::space_key;
pub use oneiron_store::embedding_vocabulary::InputKind;
pub(crate) use oneiron_store::embedding_vocabulary::TEXT_HASH_LEN;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Who wrote an EMBEDDING_SETUP retirement or slot row (FIX 6697): the owner through a door, or a
/// system move. Startup seeding honours only the owner's retirements and returns to a default;
/// a system move's re-seed from the config as they did before #3485.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupActor {
    /// The owner, through a door: retiring a space, unbinding or binding a slot, declaring a
    /// space, abandoning a move, saying yes to one.
    Owner,
    /// The engine: a timed-out or worse move's dropped candidate, an undo back to the vault's
    /// own text index, a swap's backfill retiring the incumbent, and any other engine-driven
    /// write. A row that names no actor is one of these.
    #[default]
    System,
}

impl SetupActor {
    fn is_system(&self) -> bool {
        *self == Self::System
    }
}

/// One EMBEDDING_SETUP row (OF-370): a piece of this vault's embedding setup its other devices
/// need to embed the same inputs into the same spaces. A row's id derives from what it names,
/// so every device writes one row per space and one per kind slot. A retirement and a slot's
/// return to its default are rows too, never a missing one, and each names who wrote it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingSetup {
    /// A declared space.
    Space(EmbeddingSpace),
    /// A space retired here: its declaration and rows went.
    Retired {
        id: String,
        #[serde(default, skip_serializing_if = "SetupActor::is_system")]
        by: SetupActor,
    },
    /// A kind slot's binding; `None` is the slot's default.
    Slot {
        kind: InputKind,
        space: Option<String>,
        #[serde(default, skip_serializing_if = "SetupActor::is_system")]
        by: SetupActor,
    },
}

/// The id of declared space `id`'s EMBEDDING_SETUP row: the entity that names the space, as the
/// scorer of its retests does (FIX 1638).
pub fn space_setup_id(id: &str) -> Result<EntityId> {
    let domain = oneiron_contracts::entity_id::derived_domains::EMBEDDING_SETUP;
    EntityId::derive(domain, &[b"space".as_slice(), id.as_bytes()])
}

/// The id of `kind`'s slot EMBEDDING_SETUP row.
pub fn slot_setup_id(kind: InputKind) -> Result<EntityId> {
    let domain = oneiron_contracts::entity_id::derived_domains::EMBEDDING_SETUP;
    EntityId::derive(domain, &[b"slot".as_slice(), &[kind.byte()]])
}

impl EmbeddingSetup {
    fn id(&self) -> Result<EntityId> {
        match self {
            Self::Space(EmbeddingSpace { id, .. }) | Self::Retired { id, .. } => space_setup_id(id),
            Self::Slot { kind, .. } => slot_setup_id(*kind),
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvariantViolation("embedding setup row encode"))
    }

    /// The setup this row states, whoever wrote it: two rows of one state are one row.
    fn state(&self) -> Self {
        match self {
            Self::Space(space) => Self::Space(space.clone()),
            Self::Retired { id, .. } => Self::Retired {
                id: id.clone(),
                by: SetupActor::System,
            },
            Self::Slot { kind, space, .. } => Self::Slot {
                kind: *kind,
                space: space.clone(),
                by: SetupActor::System,
            },
        }
    }

    /// The row `data` holds, refused unless it is exactly the bytes its writer encodes.
    fn decode(data: &[u8]) -> Result<Self> {
        let setup: Self = rmp_serde::from_slice(data)
            .map_err(|_| refused_setup("the row does not decode".into()))?;
        if setup.encode()? != data {
            return Err(refused_setup(
                "the row is not in its canonical encoding".into(),
            ));
        }
        Ok(setup)
    }
}

pub fn refused_setup(reason: String) -> Error {
    Error::Artifact(ArtifactError::InvalidEmbeddingSetupBody(reason))
}

/// One document a space's model refused, as the owner sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaRefused {
    pub id: EntityId,
    pub reason: String,
    /// Vault seconds.
    pub at: u64,
}
