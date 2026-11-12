//! Project extra rooms: grouping ordinary rooms beside a project's home room.
//!
//! An extra room keeps its own members and scope; the project only groups it.
//! The link rides the room row as the door-owned CONVERSATION body key
//! `project_group` (the project id as 32-hex), stamped only by
//! [`Memory::projects_rooms_link`] and [`Memory::projects_rooms_unlink`].
//! Linking or unlinking never widens or narrows any room's audience and
//! writes no membership, role, audience, join or scope row.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::workspace_roster::ProjectRoomPlace;
use crate::{EntityId, Vault, WriteActor};

/// Groups `room_ref` into `project_ref` as an extra room, or takes it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoomLinkRequest {
    /// The grouping project, 32-hex.
    pub project_ref: String,
    /// The room grouped as an extra room, 32-hex.
    pub room_ref: String,
}

/// The extra-room link a link or unlink committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectRoomLink {
    /// The grouping project, 32-hex.
    pub project_ref: String,
    /// The grouped room, 32-hex.
    pub room_ref: String,
    /// Always `Extra`: link and unlink never touch a home room.
    pub place: ProjectRoomPlace,
}

/// Lists the rooms `project_ref` groups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoomsRequest {
    /// The project whose rooms are listed, 32-hex.
    pub project_ref: String,
}

/// The home room first, then the caller's readable extra rooms by room id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectRoomsPage {
    /// The home room first, then extra rooms by room id. No paging.
    pub rows: Vec<ProjectRoomRow>,
}

/// One room a project groups, with how it groups it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectRoomRow {
    /// The room, 32-hex.
    pub room_ref: String,
    /// Whether the project groups it as its home room or as an extra room.
    pub place: ProjectRoomPlace,
}

/// Whether `caller` may link or unlink an extra room of `project`: the bound
/// vault owner, or the project's effective leader or a board holder, by its
/// own id or its PERSON's. A roster seat alone is NOT admin.
pub(crate) fn project_admin_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    caller: WriteActor,
) -> Result<bool> {
    if vault.verify_write_actor_in_txn(txn, &caller).is_err() {
        return Ok(false);
    }
    if crate::memory::verify_owner_actor_binding_in_txn(vault, txn, caller.entity_ref()).is_ok() {
        return Ok(true);
    }
    let Some((_, effective)) = vault.effective_project_in_txn(txn, project)? else {
        return Ok(false);
    };
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let me = caller.entity_ref();
    let person = crate::workspace_roster::person_of_actor_in_txn(vault, txn, me, at)?;
    let signs = std::iter::once(me).chain(person).any(|id| {
        let id = id.to_hex();
        effective.leader == id || effective.board.contains(&id)
    });
    Ok(match person {
        _ if signs => true,
        Some(person) => crate::policy_model::owners_in_txn(vault, txn)?.contains(&person),
        None => false,
    })
}

/// Whether `caller_entity` reads `project`: the bound vault owner, or the
/// caller or its PERSON holds an effective seat, leads, or sits on the board.
/// A project with no live effective record reads as unreadable for everyone.
/// The room list and every `project_group` redaction read through this one
/// predicate, so a served key and a listed row agree on who reads the project.
pub(crate) fn project_reader_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    caller_entity: EntityId,
) -> Result<bool> {
    // A soft delete keeps the wiped row the fold still reads, so the fold alone cannot tell a
    // live project from a deleted one: require a live row first, before the fold and before
    // the owner shortcut. A gone or deleted project reads as unreadable for everyone.
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &project)?.is_live() {
        return Ok(false);
    }
    let Some((_, effective)) = vault.effective_project_in_txn(txn, project)? else {
        return Ok(false);
    };
    if crate::memory::verify_owner_actor_binding_in_txn(vault, txn, caller_entity).is_ok() {
        return Ok(true);
    }
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let person = crate::workspace_roster::person_of_actor_in_txn(vault, txn, caller_entity, at)?;
    Ok(std::iter::once(caller_entity).chain(person).any(|id| {
        let id = id.to_hex();
        effective.seats(&id) || effective.leader == id || effective.board.contains(&id)
    }))
}

/// The one refusal for a room the caller cannot link or unlink: missing, deleted, not a
/// Conversation, or not the caller's. Nothing about the room leaks first.
fn room_not_found() -> MemoryError {
    MemoryError::not_found("room not found")
}

/// Whether `caller` is the bound vault owner, who needs no room standing.
fn is_bound_owner_in(vault: &Vault, txn: &heed::RoTxn<'_>, caller: EntityId) -> bool {
    crate::memory::verify_owner_actor_binding_in_txn(vault, txn, caller).is_ok()
}

/// Whether `caller` reads `room` as `txn` reads it, through the room's roster
/// and read standing. `false` for a room with no valid roster.
fn caller_reads_room_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: EntityId,
) -> Result<bool> {
    let Some(members) = crate::context_board::room_roster_in(vault, txn, room)? else {
        return Ok(false);
    };
    Ok(crate::context_board::room_reader_in(
        vault, txn, room, &members, caller,
    )?)
}

/// Rewrites `room`'s CONVERSATION body through the ordinary entity put, as the
/// membership door rewrites it: the header interval is preserved, so the write
/// rides sync exactly like that door's write. No other row is touched.
fn rewrite_room_body_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    body: &crate::conversation::ConversationBody,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &room)?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("conversation header"))?;
    vault
        .batch_in()
        .put(
            &room,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            crate::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            &body.to_bytes()?,
        )
        .apply(txn)
}

impl Memory<'_> {
    /// Groups an ordinary room into a project as an extra room, for the bound
    /// actor. The vault's owner or the project's leader or board links; the
    /// room keeps its own members and scope.
    ///
    /// # Errors
    ///
    /// Bad refs, a missing project or room, a caller with no standing, or a
    /// room that already belongs to a project.
    pub fn projects_rooms_link(
        &self,
        request: &ProjectRoomLinkRequest,
    ) -> MemoryResult<ProjectRoomLink> {
        let vault = self.vault();
        let caller = self.write_actor();
        vault.try_with_write_txn_grouped(|txn| {
            let project = EntityId::from_hex(&request.project_ref)
                .map_err(|_| MemoryError::bad_request("project_ref is the project's 32-hex id"))?;
            let room = EntityId::from_hex(&request.room_ref)
                .map_err(|_| MemoryError::bad_request("room_ref is the room's 32-hex id"))?;
            // A soft delete keeps the wiped row the fold reads: the row must be live too.
            let live_project = vault.effective_project_in_txn(txn, project)?.is_some()
                && crate::vault::live_entity_row_in_txn(&vault.store, txn, &project)?.is_live();
            if !live_project {
                return Err(MemoryError::from(Error::EntityNotFound));
            }
            if !project_admin_in_txn(vault, txn, project, caller)? {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "only the vault's owner or the project's leader or board links a room into it",
                    &["Ask the vault's owner or the project's leader or board to link it."],
                ));
            }
            let live_room = vault.get_entity_type_in_txn(txn, &room)?
                == Some(crate::registry::ENTITY_TYPE_CONVERSATION)
                && crate::vault::live_entity_row_in_txn(&vault.store, txn, &room)?.is_live();
            if !live_room {
                return Err(room_not_found());
            }
            if !is_bound_owner_in(vault, txn, caller.entity_ref())
                && !caller_reads_room_in(vault, txn, room, caller.entity_ref())?
            {
                return Err(room_not_found());
            }
            if super::ROOM_PROJECT.contains(&vault.store, txn, &room)?
                || crate::workspace_roster::room_project_in(vault, txn, room)?.is_some()
            {
                return Err(MemoryError::bad_request(
                    "a project's home room belongs to its project; it cannot be linked as an extra room",
                ));
            }
            if crate::workspace_roster::room_group_project_in(vault, txn, room)?.is_some() {
                return Err(MemoryError::bad_request(
                    "the room already belongs to a project; unlink it first",
                ));
            }
            let key = crate::store::conversation_body::ROOM_PROJECT_GROUP_KEY;
            let project_hex = project.to_hex();
            let mut body = crate::conversation::body_in(vault, txn, room)?;
            body.extra.insert(key.to_owned(), rmpv::Value::from(project_hex.clone()));
            rewrite_room_body_in_txn(vault, txn, room, &body)?;
            Ok(ProjectRoomLink {
                project_ref: project_hex,
                room_ref: room.to_hex(),
                place: ProjectRoomPlace::Extra,
            })
        })
    }

    /// Takes an extra room out of a project, for the bound actor. The vault's
    /// owner or the project's leader or board unlinks; the room keeps its own
    /// members and scope.
    ///
    /// # Errors
    ///
    /// Bad refs, a missing project or room, a caller with no standing, a home
    /// room, or a room that is not this project's extra room.
    pub fn projects_rooms_unlink(
        &self,
        request: &ProjectRoomLinkRequest,
    ) -> MemoryResult<ProjectRoomLink> {
        let vault = self.vault();
        let caller = self.write_actor();
        vault.try_with_write_txn_grouped(|txn| {
            let project = EntityId::from_hex(&request.project_ref)
                .map_err(|_| MemoryError::bad_request("project_ref is the project's 32-hex id"))?;
            let room = EntityId::from_hex(&request.room_ref)
                .map_err(|_| MemoryError::bad_request("room_ref is the room's 32-hex id"))?;
            // A soft delete keeps the wiped row the fold reads: the row must be live too.
            let live_project = vault.effective_project_in_txn(txn, project)?.is_some()
                && crate::vault::live_entity_row_in_txn(&vault.store, txn, &project)?.is_live();
            if !live_project {
                return Err(MemoryError::from(Error::EntityNotFound));
            }
            if !project_admin_in_txn(vault, txn, project, caller)? {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "only the vault's owner or the project's leader or board unlinks a room from it",
                    &["Ask the vault's owner or the project's leader or board to unlink it."],
                ));
            }
            let live_room = vault.get_entity_type_in_txn(txn, &room)?
                == Some(crate::registry::ENTITY_TYPE_CONVERSATION)
                && crate::vault::live_entity_row_in_txn(&vault.store, txn, &room)?.is_live();
            if !live_room {
                return Err(room_not_found());
            }
            if !is_bound_owner_in(vault, txn, caller.entity_ref())
                && !caller_reads_room_in(vault, txn, room, caller.entity_ref())?
            {
                return Err(room_not_found());
            }
            if super::ROOM_PROJECT.contains(&vault.store, txn, &room)?
                || crate::workspace_roster::room_project_in(vault, txn, room)?.is_some()
            {
                return Err(MemoryError::bad_request(
                    "a project's home room cannot be unlinked from its project",
                ));
            }
            let key = crate::store::conversation_body::ROOM_PROJECT_GROUP_KEY;
            let project_hex = project.to_hex();
            let mut body = crate::conversation::body_in(vault, txn, room)?;
            let grouped = body.extra.get(key).and_then(|value| value.as_str());
            if grouped != Some(project_hex.as_str()) {
                return Err(MemoryError::bad_request(
                    "the room is not an extra room of this project",
                ));
            }
            body.extra.remove(key);
            rewrite_room_body_in_txn(vault, txn, room, &body)?;
            Ok(ProjectRoomLink {
                project_ref: project_hex,
                room_ref: room.to_hex(),
                place: ProjectRoomPlace::Extra,
            })
        })
    }

    /// The project's home room and the extra rooms it groups that the caller
    /// can read. A caller that cannot read the project gets an empty page.
    pub fn projects_rooms_list(
        &self,
        request: &ProjectRoomsRequest,
    ) -> MemoryResult<ProjectRoomsPage> {
        let project = EntityId::from_hex(&request.project_ref)
            .map_err(|_| MemoryError::bad_request("project_ref is the project's 32-hex id"))?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let Some((record, _)) = vault.effective_project_in_txn(&txn, project)? else {
            return Ok(ProjectRoomsPage { rows: Vec::new() });
        };
        if !project_reader_in_txn(vault, &txn, project, self.actor())? {
            return Ok(ProjectRoomsPage { rows: Vec::new() });
        }
        let home = EntityId::from_hex(&record.home_room)
            .map_err(|_| Error::CorruptedIndex("project home room"))?;
        let mut rows = vec![ProjectRoomRow {
            room_ref: home.to_hex(),
            place: ProjectRoomPlace::Home,
        }];
        let mut extras = Vec::new();
        for (room, grouped) in super::EXTRA_ROOM_PROJECT.scan(&vault.store, &txn)? {
            if grouped != project
                || crate::workspace_roster::room_group_project_in(vault, &txn, room)?
                    != Some((project, ProjectRoomPlace::Extra))
                || !caller_reads_room_in(vault, &txn, room, self.actor())?
            {
                continue;
            }
            extras.push(room);
        }
        extras.sort();
        rows.extend(extras.into_iter().map(|room| ProjectRoomRow {
            room_ref: room.to_hex(),
            place: ProjectRoomPlace::Extra,
        }));
        Ok(ProjectRoomsPage { rows })
    }
}
