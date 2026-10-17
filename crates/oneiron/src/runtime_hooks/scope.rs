//! A hook's scope (ARCH-0080 §3): a world, facet, room or project, named
//! `<axis>:<32 hex>`. A scope only narrows. It takes a call or a fact only
//! when the authority helpers place it inside, never by its text.

use std::collections::BTreeSet;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ScopedReadActorKey};
use crate::error::RecordError;
use crate::federation::{ScopeAxis, ScopeId};
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::{EntityId, Error, Result, Vault};

use super::VerbCall;

/// How many parent steps a project scope walks up from a room's or a
/// claim's project, as the projects' effective authority serves them.
const PROJECT_SCOPE_DEPTH: usize = 32;

/// What a hook's `scope`, or a call's, names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookScope {
    World(EntityId),
    Facet(EntityId),
    Room(EntityId),
    Project(EntityId),
}

impl HookScope {
    /// Parses `<axis>:<id>`, the id as 32 lowercase hex digits; `None` for
    /// anything else.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (axis, id) = text.split_once(':')?;
        if id.len() != 32 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let id = EntityId::from_hex(id).ok()?;
        Some(match axis {
            "world" => Self::World(id),
            "facet" => Self::Facet(id),
            "room" => Self::Room(id),
            "project" => Self::Project(id),
            _ => return None,
        })
    }
}

/// Whether the selector scope `scope` holds `call`'s own. On one axis, the
/// same id does. Over a room call, a project holds it when the room's
/// project is that one or reaches it through effective parents
/// ([`project_within`]), a world when the room's read-world ceiling holds
/// it, and a facet when the room's facets do. The world ceiling is the
/// caller's own room turn's, as its reads narrowed it, when its read key
/// holds one for that room; else the room's roster meets it now. Any other
/// pairing, a call with no scope, or a scope that does not parse, takes
/// nothing.
pub(super) fn call_within(vault: &Vault, scope: &str, call: &VerbCall) -> Result<bool> {
    let (Some(wanted), Some(own)) = (
        HookScope::parse(scope),
        call.scope.as_deref().and_then(HookScope::parse),
    ) else {
        return Ok(false);
    };
    if std::mem::discriminant(&wanted) == std::mem::discriminant(&own) {
        return Ok(wanted == own);
    }
    let HookScope::Room(room) = own else {
        return Ok(false);
    };
    let txn = vault.store.env.read_txn()?;
    Ok(match wanted {
        HookScope::Project(project) => match room_project(vault, &txn, room)? {
            Some(own) => project_within(vault, &txn, own, project)?,
            None => false,
        },
        HookScope::World(world) => {
            let world = ScopeId(world);
            match call.reader.as_ref().and_then(ScopedReadActorKey::room_turn) {
                Some(turn) if turn.room == room => turn
                    .terms
                    .with(|terms| terms.worlds.worlds.contains(&world)),
                // The room's world ceiling as its roster meets it now, the
                // one `room_read_worlds` reads, for a caller that reads the
                // room.
                _ => crate::context_board::room_ceiling_in(vault, &txn, room, call.actor)?
                    .is_some_and(|ceiling| ceiling.terms.get().worlds.worlds.contains(&world)),
            }
        }
        HookScope::Facet(facet) => crate::workspace_roster::room_facets_in(vault, &txn, room)?
            .is_some_and(|facets| facets.contains(&ScopeId(facet))),
        HookScope::Room(_) => false,
    })
}

/// Whether the selector scope `scope` holds the fact on `entity`, with
/// `claim` its claim when it is one. A world holds the record's world; a
/// facet a record the one facet rule places in it; a project a claim stamped
/// to it or to a project under it ([`project_within`]), else a record whose
/// room's project is; a room a record said in it. A fact that proves none of
/// these, or a scope that does not parse, takes nothing.
pub(super) fn fact_within(
    vault: &Vault,
    scope: &str,
    entity: EntityId,
    claim: Option<&ClaimBody>,
) -> Result<bool> {
    let Some(wanted) = HookScope::parse(scope) else {
        return Ok(false);
    };
    let txn = vault.store.env.read_txn()?;
    match wanted {
        HookScope::World(world) => {
            let Some(raw) = stored_raw(vault, &txn, entity)? else {
                return Ok(false);
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            let data = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
            // Base reality reads as the base world, as a read lane places it.
            Ok(crate::federation::record_scope::record_world_in(
                &vault.store,
                &txn,
                entity,
                header.entity_type,
                data,
            )?
            .is_some_and(|own| own.unwrap_or_else(crate::claim::base_world_id) == world))
        }
        HookScope::Facet(facet) => {
            let Some(raw) = stored_raw(vault, &txn, entity)? else {
                return Ok(false);
            };
            crate::federation::facet_read::facets_admit_in(
                vault,
                &vault.store,
                &txn,
                entity,
                &raw,
                &ScopeAxis::Some(BTreeSet::from([ScopeId(facet)])),
            )
        }
        HookScope::Project(project) => {
            let stamped = claim
                .map(|body| body.scope_project)
                .filter(|own| *own != crate::claim::default_project_id());
            let own = match stamped {
                Some(own) => Some(own),
                None => match record_room(vault, &txn, entity)? {
                    Some(room) => room_project(vault, &txn, room)?,
                    None => None,
                },
            };
            match own {
                Some(own) => project_within(vault, &txn, own, project),
                None => Ok(false),
            }
        }
        HookScope::Room(room) => Ok(record_room(vault, &txn, entity)? == Some(room)),
    }
}

/// The stored row `entity`, header and body.
fn stored_raw(vault: &Vault, txn: &heed::RoTxn<'_>, entity: EntityId) -> Result<Option<Vec<u8>>> {
    crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &entity)
}

/// The project `room` is the home room of, as its project's signed history
/// vouches for it; `None` for any other room, a room that is not live, or
/// one its project no longer vouches for.
fn room_project(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<Option<EntityId>> {
    if crate::vault::live_entity_row_in_txn(&vault.store, txn, &room)?.live_type()
        != Some(ENTITY_TYPE_CONVERSATION)
    {
        return Ok(None);
    }
    match crate::workspace_roster::room_project_in(vault, txn, room) {
        Ok(project) => Ok(project),
        // The roster's refusal for a room its project does not vouch for.
        Err(Error::InvalidConfig(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether project `own` is `wanted`, or reaches it up the parents each
/// project's effective authority serves (never a stored row's own list),
/// within [`PROJECT_SCOPE_DEPTH`] steps. Each project is read once.
fn project_within(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    own: EntityId,
    wanted: EntityId,
) -> Result<bool> {
    if own == wanted {
        return Ok(true);
    }
    let Some(reader) =
        crate::workspace_roster::ProjectReader::new(&vault.store, txn, vault.privacy_posture())?
    else {
        return Ok(false);
    };
    let mut seen = BTreeSet::from([own]);
    let mut ring = vec![own];
    for _ in 0..PROJECT_SCOPE_DEPTH {
        let mut next = Vec::new();
        for id in ring {
            let Some(effective) = reader.effective(id)? else {
                continue;
            };
            for parent in &effective.parents {
                let Ok(parent) = EntityId::from_hex(parent) else {
                    continue;
                };
                if parent == wanted {
                    return Ok(true);
                }
                if seen.insert(parent) {
                    next.push(parent);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        ring = next;
    }
    Ok(false)
}

/// The one room the record `entity` was said in; `None` when it names none,
/// names more than one, or points at a row that is gone.
fn record_room(vault: &Vault, txn: &heed::RoTxn<'_>, entity: EntityId) -> Result<Option<EntityId>> {
    match crate::conversation::room_for_record_in(vault, txn, entity) {
        Ok(room) => Ok(room),
        Err(Error::EntityNotFound | Error::Record(RecordError::ConversationState(_))) => Ok(None),
        Err(error) => Err(error),
    }
}
