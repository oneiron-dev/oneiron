//! The pin an agent id keeps across a delete (H215): the narrowest ceiling a
//! row at the id has held, and the fork lineage it was born with.
//!
//! The gate reads an agent's bound off the row stored AT its id, so the id is
//! what a ceiling binds. An update cannot widen the row it replaces
//! (`validate_agent_definition_update`), but a delete ends the row, and a put
//! at the same id afterwards has no prior to compare with. Recreated wider,
//! without the parent that clamped it, or as another entity type the gate
//! reads no bound off, it would hand the agent at that id more than it ever
//! held. The pin survives the delete, so every later put at the id answers to
//! it, on every road (typed, raw batch, replicated, the seeder's).

use super::types::{AgentCeiling, AgentDefinition};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, RegistryError, Result};
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable, StagedRow};
use crate::store::Store;

/// What an agent id answers to on every later put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AgentIdPin {
    /// The narrowest ceiling a row at this id has held.
    ceiling: AgentCeiling,
    /// The parent row the id was born forked from, if any.
    forked_from: Option<EntityId>,
}

impl RawValue for AgentIdPin {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut bytes = vec![u8::from(self.ceiling == AgentCeiling::Auto)];
        if let Some(parent) = self.forked_from {
            bytes.extend_from_slice(parent.as_bytes());
        }
        Ok(bytes)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (ceiling, parent) = match bytes.split_first() {
            Some((0, parent)) => (AgentCeiling::Proposed, parent),
            Some((1, parent)) => (AgentCeiling::Auto, parent),
            _ => return Err(Error::CorruptedIndex("agent id pin").into()),
        };
        let forked_from = match parent.len() {
            0 => None,
            16 => Some(crate::entity_id::parse_entity_id(
                parent,
                "agent id pin parent",
            )?),
            _ => return Err(Error::CorruptedIndex("agent id pin").into()),
        };
        Ok(Self {
            ceiling,
            forked_from,
        })
    }
}

const PIN: SideTable<EntityId, AgentIdPin, Raw> = SideTable::new(&side_table::AGENT_DEF_ID_PIN);

/// The pin a seeded row id answers to before its own is stored: its seed's
/// ceiling and lineage.
fn seeded_pin(id: &EntityId) -> Result<Option<AgentIdPin>> {
    Ok(
        super::manifest::seeded_lineage(id)?.map(|(ceiling, forked_from)| AgentIdPin {
            ceiling,
            forked_from,
        }),
    )
}

/// Checks a put of `def` at `id` against the id's pin, and returns the pin row
/// the put stages with its body, or `None` when the stored pin already says
/// it. A first put pins the id at its own ceiling and lineage; a later one may
/// narrow the ceiling, never widen it, and keeps the lineage.
///
/// # Errors
///
/// [`ArtifactError::InvalidAgentDefBody`] when `def` widens beyond the pin or
/// names another parent.
pub(crate) fn agent_id_pin_for_put_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    def: &AgentDefinition,
) -> Result<Option<StagedRow>> {
    let stored = PIN.get(store, txn, id)?;
    let bound = match stored {
        Some(pin) => Some(pin),
        None => seeded_pin(id)?,
    };
    let next = match bound {
        None => AgentIdPin {
            ceiling: def.ceiling,
            forked_from: def.forked_from,
        },
        Some(pin) => {
            answer_to_pin(pin, def)?;
            AgentIdPin {
                ceiling: def.ceiling,
                forked_from: pin.forked_from,
            }
        }
    };
    if stored == Some(next) {
        return Ok(None);
    }
    PIN.stage(id, &next).map(Some)
}

/// Refuses `def` when it widens beyond `pin` or names another parent.
fn answer_to_pin(pin: AgentIdPin, def: &AgentDefinition) -> Result<()> {
    if def.ceiling.widens_beyond(pin.ceiling) {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "an agent id's ceiling cannot widen beyond the narrowest it has held",
        )));
    }
    if def.forked_from != pin.forked_from {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "an agent id keeps the lineage it was born with, across a delete too",
        )));
    }
    Ok(())
}

/// The stateless half of the pin, for a door that reads no transaction (the
/// federation admission prefilter): a seeded row id holds only an AGENT_DEF,
/// no wider than its seed and on its seed's lineage. `def` is the decoded
/// body when `entity_type` is AGENT_DEF.
///
/// # Errors
///
/// As [`agent_id_pin_for_put_in_txn`] and [`refuse_agent_id_retype_in_txn`],
/// for a seeded row id.
#[cfg(feature = "sync")]
pub(crate) fn validate_put_at_seeded_id(
    id: &EntityId,
    entity_type: u8,
    def: Option<&AgentDefinition>,
) -> Result<()> {
    let Some(seed) = seeded_pin(id)? else {
        return Ok(());
    };
    match def {
        Some(def) if entity_type == ENTITY_TYPE_AGENT_DEF => answer_to_pin(seed, def),
        _ => Err(Error::Registry(RegistryError::EntityTypeImmutable {
            id: *id,
            existing: ENTITY_TYPE_AGENT_DEF,
            attempted: entity_type,
        })),
    }
}

/// The ceiling a row at `id` may hold at most, when the id is pinned: what
/// the seeder narrows a seed to before it re-creates a deleted seeded row.
pub(super) fn pinned_ceiling_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<AgentCeiling>> {
    Ok(PIN.get(store, txn, id)?.map(|pin| pin.ceiling))
}

/// An id that has been an agent stays one: a put of another entity type at a
/// pinned or seeded agent id is refused, so a delete cannot reopen the id as a
/// row the gate reads no ceiling off.
///
/// # Errors
///
/// [`RegistryError::EntityTypeImmutable`] for a put of another type at such an
/// id.
pub(crate) fn refuse_agent_id_retype_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<()> {
    if entity_type == ENTITY_TYPE_AGENT_DEF
        || !(PIN.contains(store, txn, id)? || seeded_pin(id)?.is_some())
    {
        return Ok(());
    }
    Err(Error::Registry(RegistryError::EntityTypeImmutable {
        id: *id,
        existing: ENTITY_TYPE_AGENT_DEF,
        attempted: entity_type,
    }))
}
