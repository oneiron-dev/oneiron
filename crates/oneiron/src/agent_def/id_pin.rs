//! The pin an agent id keeps (H215): the widest ceiling a row at the id may
//! hold, and the fork lineage it was born with.
//!
//! The gate reads an agent's bound off the row stored AT its id, so the id is
//! what a ceiling binds, and the agent there may hold `core:write` over its
//! own row. Updated wider, deleted and recreated wider or without the parent
//! that clamped it, or recreated as another entity type the gate reads no
//! bound off, the row would hand that agent more than it was given. So the
//! id holds a pin that survives the delete: a put's ceiling becomes the pin,
//! and every later put at the id, on every road (typed, raw batch,
//! replicated, the seeder's), is no wider and keeps the lineage. A row older
//! than the pin answers to itself, and a seeded id to its seed. Only the
//! owner's door (`Vault::update_agent_definition_as`) moves a pin wider.
//! A shell pins its id before any body says the lineage: the id holds
//! `Proposed`, where no parent clamps it further, and the first definition
//! put there names the lineage.

use super::codec::decode_agent_definition;
use super::types::{AgentCeiling, AgentDefinition};
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, RegistryError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_AUTHORITY_LOG};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable, StagedRow};
use crate::store::Store;

mod scan;

/// The pin's first byte: `Auto` ceiling.
const PIN_AUTO: u8 = 1;
/// The pin's first byte: lineage unread (a `Proposed` pin only).
const PIN_UNREAD: u8 = 2;
/// The pin's first byte: a delegation parent's 16 bytes follow it.
const PIN_DELEGATED: u8 = 4;

/// What an agent id answers to on every later put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AgentIdPin {
    /// The widest ceiling a row at this id may hold: the last put's, which
    /// was no wider than the one before, unless the owner widened it.
    ceiling: AgentCeiling,
    /// The parent the id was born forked from.
    lineage: Lineage,
    /// The attempt whose spawn delegated this id's agent, when a dispatch
    /// minted it as an attenuated fork (FIX 9559). The host binds it once;
    /// every later put, delete, recreate and restore keeps it.
    delegation_parent: Option<AttemptId>,
}

/// The parent an agent id was born forked from, as its pin knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lineage {
    /// Born forked from this row, or from none.
    Born(Option<EntityId>),
    /// Not yet read: the id was pinned off a definition shell, which keeps
    /// no body, so the pin holds `Proposed` and the next put names it.
    Unread,
}

impl Lineage {
    /// The lineage a put of `def` leaves the id with.
    fn named_by(self, def: &AgentDefinition) -> Self {
        match self {
            Self::Unread => Self::Born(def.forked_from),
            born => born,
        }
    }
}

/// The first byte holds the ceiling, an unread lineage and whether a
/// delegation parent follows; then that parent's 16 bytes, then the born
/// lineage's parent, if any. A pin without a delegation parent encodes as it
/// always has.
impl RawValue for AgentIdPin {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let auto = self.ceiling == AgentCeiling::Auto;
        let mut flags = match self.lineage {
            Lineage::Born(_) if auto => PIN_AUTO,
            Lineage::Born(_) => 0,
            // Only a `Proposed` pin leaves its lineage unread.
            Lineage::Unread if !auto => PIN_UNREAD,
            Lineage::Unread => return Err(Error::CorruptedIndex("agent id pin").into()),
        };
        if self.delegation_parent.is_some() {
            flags |= PIN_DELEGATED;
        }
        let mut bytes = vec![flags];
        if let Some(parent) = self.delegation_parent {
            bytes.extend_from_slice(parent.as_bytes());
        }
        if let Lineage::Born(Some(parent)) = self.lineage {
            bytes.extend_from_slice(parent.as_bytes());
        }
        Ok(bytes)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let corrupt = || CodecError::from(Error::CorruptedIndex("agent id pin"));
        let (&flags, rest) = bytes.split_first().ok_or_else(corrupt)?;
        if flags & !(PIN_AUTO | PIN_UNREAD | PIN_DELEGATED) != 0
            || flags & (PIN_AUTO | PIN_UNREAD) == PIN_AUTO | PIN_UNREAD
        {
            return Err(corrupt());
        }
        let (delegation_parent, parent) = if flags & PIN_DELEGATED == 0 {
            (None, rest)
        } else {
            let (attempt, parent) = rest.split_at_checked(16).ok_or_else(corrupt)?;
            (Some(AttemptId::from_bytes(attempt)?), parent)
        };
        let ceiling = if flags & PIN_AUTO == 0 {
            AgentCeiling::Proposed
        } else {
            AgentCeiling::Auto
        };
        let lineage = if flags & PIN_UNREAD != 0 {
            if !parent.is_empty() {
                return Err(corrupt());
            }
            Lineage::Unread
        } else {
            Lineage::Born(match parent.len() {
                0 => None,
                16 => Some(crate::entity_id::parse_entity_id(
                    parent,
                    "agent id pin parent",
                )?),
                _ => return Err(corrupt()),
            })
        };
        Ok(Self {
            ceiling,
            lineage,
            delegation_parent,
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
            lineage: Lineage::Born(forked_from),
            delegation_parent: None,
        }),
    )
}

/// What a put at `id` answers to: its stored pin; before one is stored, the
/// narrower of its seed and the row it holds now, when either is there.
fn bound_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Option<AgentIdPin>> {
    if let Some(pin) = PIN.get(store, txn, id)? {
        return Ok(Some(pin));
    }
    Ok(match (seeded_pin(id)?, stored_row_pin(store, txn, id)?) {
        (Some(seed), Some(row)) if seed.ceiling.widens_beyond(row.ceiling) => Some(AgentIdPin {
            ceiling: row.ceiling,
            lineage: seed.lineage,
            delegation_parent: None,
        }),
        (seed, row) => seed.or(row),
    })
}

/// The ceiling and lineage of the definition stored at `id`. A row of another
/// type, or one that does not decode, bounds nothing here: the type check and
/// the update arm refuse a put over it.
fn stored_row_pin(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<AgentIdPin>> {
    Ok(store
        .port_entity_record(txn, id)?
        .filter(|row| row.entity_type == ENTITY_TYPE_AGENT_DEF)
        .and_then(|row| decode_agent_definition(&row.body).ok())
        .map(|def| AgentIdPin {
            ceiling: def.ceiling,
            lineage: Lineage::Born(def.forked_from),
            delegation_parent: None,
        }))
}

/// Checks a put of `def` at `id` against what the id answers to, and returns
/// the pin row the put stages with its body, or `None` when the stored pin
/// already says it. A first put pins the id at its own ceiling and lineage; a
/// later one may narrow the ceiling, never widen it, and keeps the lineage
/// (or names it, where the id's pin has not read it).
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
    scan::observe_list_entries(store, txn, id, def);
    let next = match bound_in_txn(store, txn, id)? {
        None => AgentIdPin {
            ceiling: def.ceiling,
            lineage: Lineage::Born(def.forked_from),
            delegation_parent: None,
        },
        Some(pin) => {
            answer_to_pin(pin, def)?;
            AgentIdPin {
                ceiling: def.ceiling,
                lineage: pin.lineage.named_by(def),
                delegation_parent: pin.delegation_parent,
            }
        }
    };
    if PIN.get(store, txn, id)? == Some(next) {
        return Ok(None);
    }
    PIN.stage(id, &next).map(Some)
}

/// Moves the pin at `id` to `def`'s ceiling, wider or not, keeping the
/// lineage the id answers to. The owner's door
/// (`Vault::update_agent_definition_as`) calls it in the transaction that
/// writes `def`, after rechecking the owner's proof, and nothing else does.
///
/// # Errors
///
/// [`ArtifactError::InvalidAgentDefBody`] when `def` names another parent.
pub(super) fn move_pin_for_owner_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    def: &AgentDefinition,
) -> Result<()> {
    let bound = bound_in_txn(store, wtxn, id)?;
    let pin = AgentIdPin {
        ceiling: def.ceiling,
        lineage: bound.map_or(Lineage::Born(def.forked_from), |pin| {
            pin.lineage.named_by(def)
        }),
        delegation_parent: bound.and_then(|pin| pin.delegation_parent),
    };
    // The ceiling is the owner's to move; the lineage is not.
    answer_to_pin(pin, def)?;
    PIN.put(store, wtxn, id, &pin)
}

/// Refuses `def` when it widens beyond `pin` or names another parent than
/// the one `pin` has read.
fn answer_to_pin(pin: AgentIdPin, def: &AgentDefinition) -> Result<()> {
    if def.ceiling.widens_beyond(pin.ceiling) {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "an agent id's ceiling cannot widen beyond the narrowest it has held",
        )));
    }
    if let Lineage::Born(parent) = pin.lineage
        && def.forked_from != parent
    {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "an agent id keeps the lineage it was born with, across a delete too",
        )));
    }
    Ok(())
}

/// The stateless half of the pin, for a door that reads no transaction (the
/// federation admission prefilter): a seeded row id holds only an AGENT_DEF,
/// no wider than its seed and on its seed's lineage. `def` is the decoded
/// body when `entity_type` is AGENT_DEF. Where this vault's owner widened a
/// seeded row, it refuses a foreign row materialization would take at that
/// ceiling: fail-closed, as no foreign row carries this owner's widening.
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

/// Whether `theirs` holds an agent id looser than `ours`: wider, off a
/// lineage `ours` has read, or without the delegation parent `ours` binds.
fn loosens(ours: AgentIdPin, theirs: AgentIdPin) -> bool {
    theirs.ceiling.widens_beyond(ours.ceiling)
        || (matches!(ours.lineage, Lineage::Born(_)) && theirs.lineage != ours.lineage)
        || (ours.delegation_parent.is_some() && theirs.delegation_parent != ours.delegation_parent)
}

/// What a restore's decision reads at an agent id: the id's pin, and whether
/// the row there answers to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AgentIdAnswer {
    pin: Option<AgentIdPin>,
    row_within: bool,
}

impl AgentIdAnswer {
    /// Whether `restored` holds the agent id looser than `live`: a row off
    /// its own pin, or a pin the live vault holds missing, wider or off its
    /// lineage. The pins are live authority, so a live pin narrowed or taken
    /// after the restore carried them is no looser in the restored vault.
    pub(crate) fn loosened(live: &Self, restored: &Self) -> bool {
        !restored.row_within
            || match (live.pin, restored.pin) {
                (Some(ours), Some(theirs)) => loosens(ours, theirs),
                (Some(_), None) => true,
                (None, _) => false,
            }
    }
}

/// [`AgentIdAnswer`] at `id`.
///
/// # Errors
///
/// When the id's pin does not read.
pub(crate) fn agent_id_answer_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<AgentIdAnswer> {
    Ok(AgentIdAnswer {
        pin: PIN.get(store, txn, id)?,
        row_within: row_within_pin_in_txn(store, txn, id)?,
    })
}

/// Refuses to publish `replacement`, a restore made for `store`'s place, when
/// it holds any agent id looser than `store` does now: without the id's pin,
/// wider, or off the lineage the pin has read. A pin narrowed or taken after
/// the replacement carried the pins would be lost. Read in `txn`, under
/// `store`'s writer, before the swap.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for such a replacement; when a pin does not read.
pub(crate) fn refuse_loosened_agent_id_pins(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    replacement: &Store,
) -> Result<()> {
    let their_txn = replacement.env.read_txn()?;
    for id in PIN.scan_keys(store, txn, &[])? {
        let Some(ours) = PIN.get(store, txn, &id)? else {
            continue;
        };
        if PIN
            .get(replacement, &their_txn, &id)?
            .is_none_or(|theirs| loosens(ours, theirs))
        {
            return Err(Error::InvalidConfig(
                "this vault narrowed or took an agent id after the restore was prepared; \
                 prepare it again"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// Binds `parent`, the attempt whose spawn minted the attenuated fork at
/// `id`, into the id's pin (FIX 9559). Only the dispatcher calls it, in the
/// transaction that writes the fork, after the fork's put pinned the id. An
/// id already bound keeps the parent it was minted under; an unpinned id is
/// left as it is. It never fails the fork's write but on a store fault.
///
/// # Errors
///
/// When the pin does not read or write.
pub(crate) fn bind_delegation_parent_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    parent: AttemptId,
) -> Result<()> {
    let Some(pin) = PIN.get(store, wtxn, id)? else {
        return Ok(());
    };
    if pin.delegation_parent.is_some() {
        return Ok(());
    }
    PIN.put(
        store,
        wtxn,
        id,
        &AgentIdPin {
            delegation_parent: Some(parent),
            ..pin
        },
    )
}

/// The attempt whose spawn delegated the agent at `id`, when its pin binds
/// one: the durable link a live ceiling walk follows up the delegation chain.
///
/// # Errors
///
/// When the pin does not read.
pub(crate) fn delegation_parent_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<AttemptId>> {
    Ok(PIN
        .get(store, txn, id)?
        .and_then(|pin| pin.delegation_parent))
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
/// row the gate reads no ceiling off. A signed authority entry is the one
/// exception: its id is its content's hash, which no one aims at an agent id,
/// and it takes its id from any row there (ONE-1604-D1), so an agent put
/// first cannot keep it out. The gate holds the id at `Proposed` after.
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
        || entity_type == ENTITY_TYPE_AUTHORITY_LOG
        || !is_agent_id_in_txn(store, txn, id)?
    {
        return Ok(());
    }
    Err(Error::Registry(RegistryError::EntityTypeImmutable {
        id: *id,
        existing: ENTITY_TYPE_AGENT_DEF,
        attempted: entity_type,
    }))
}

/// Whether `id` is an agent id: pinned, or a seeded row's.
pub(crate) fn is_agent_id_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(PIN.contains(store, txn, id)? || seeded_pin(id)?.is_some())
}

/// Every agent id: each pinned one, and each seeded row's.
pub(crate) fn agent_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<std::collections::BTreeSet<EntityId>> {
    let mut ids: std::collections::BTreeSet<EntityId> =
        PIN.scan_keys(store, txn, &[])?.into_iter().collect();
    ids.extend(
        super::manifest::system_agent_manifest()?
            .definitions
            .iter()
            .map(|seed| seed.entity_id.0),
    );
    Ok(ids)
}

/// Refuses the `vault_meta` rows a restore is about to write when one is an
/// agent id pin no pin decodes from. The restore's pin pass, and the
/// open after it, would refuse the same pin once the copy exists; read
/// here, before the restore makes its destination, the refusal leaves
/// nothing behind.
pub(crate) fn refuse_unreadable_agent_id_pins(vault_meta: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
    for (key, value) in vault_meta {
        if key.starts_with(PIN.decl().prefix) {
            PIN.decode_value(value)?;
        }
    }
    Ok(())
}

/// Pins every stored definition as [`pin_stored_row_in_txn`] pins one. Rows
/// reach the store without a put two ways: a restore writes them raw, and a
/// row older than the pin was put before the pin existed. So the restore
/// calls this in the transaction that writes its rows, and every seeded open
/// calls it before any caller holds the vault.
pub(crate) fn pin_stored_rows_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
    let ids = store
        .port_entity_ids_by_type(wtxn, ENTITY_TYPE_AGENT_DEF, None)?
        .collect::<Result<Vec<_>>>()?;
    for id in ids {
        pin_stored_row_in_txn(store, wtxn, &id)?;
    }
    Ok(())
}

/// Pins the definition stored at `id` as a put of it would have: a row
/// narrower than its id's pin narrows the pin, a row within a pin whose
/// lineage is unread names it, and a row whose id holds no pin is pinned at its own ceiling and lineage (no wider than its seed), or
/// at `Proposed` when it does not decode (a retained shell keeps no body), on
/// its seed's lineage or, for an unseeded id, with the lineage unread.
/// Unpinned, a row that reached the store without a put could be deleted and
/// come back wider or as another type; so the shell door pins what it
/// writes, and a delete pins the row it removes. A row wider than its pin,
/// or off its lineage, stays for a restore's decisions to refuse.
pub(crate) fn pin_stored_row_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let row = stored_row_pin(store, wtxn, id)?;
    let pin = match (PIN.get(store, wtxn, id)?, row) {
        (Some(pin), Some(row)) => {
            let within = !row.ceiling.widens_beyond(pin.ceiling);
            let next = AgentIdPin {
                ceiling: if within { row.ceiling } else { pin.ceiling },
                lineage: match pin.lineage {
                    Lineage::Unread if within => row.lineage,
                    lineage => lineage,
                },
                delegation_parent: pin.delegation_parent,
            };
            if next == pin {
                return Ok(());
            }
            next
        }
        (Some(_), None) => return Ok(()),
        (None, Some(row)) => bound_in_txn(store, wtxn, id)?.unwrap_or(row),
        (None, None) => AgentIdPin {
            ceiling: AgentCeiling::Proposed,
            lineage: seeded_pin(id)?.map_or(Lineage::Unread, |seed| seed.lineage),
            delegation_parent: None,
        },
    };
    PIN.put(store, wtxn, id, &pin)
}

/// Whether the row at agent id `id` answers to the id's pin: absent, or a
/// definition no wider than the pin, on its lineage. A restore writes rows
/// without a put, so it asks this of every row it brings back to an agent id.
/// A definition that does not decode is within, as is a signed authority
/// entry, which takes its id from any row there: the gate holds either at
/// `Proposed`.
fn row_within_pin_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let pin = match PIN.get(store, txn, id)? {
        Some(pin) => pin,
        None => match seeded_pin(id)? {
            Some(seed) => seed,
            None => return Ok(true),
        },
    };
    Ok(match store.port_entity_record(txn, id)? {
        None => true,
        Some(row) if row.entity_type == ENTITY_TYPE_AUTHORITY_LOG => true,
        Some(row) if row.entity_type != ENTITY_TYPE_AGENT_DEF => false,
        Some(row) => decode_agent_definition(&row.body)
            .ok()
            .is_none_or(|def| answer_to_pin(pin, &def).is_ok()),
    })
}
