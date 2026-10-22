//! Which call serves a room NOTE, and so keeps no durable call receipt or
//! hook record (FIX 4280; Engine 10-22). The engine decides
//! ([`oneiron::Vault::room_note_call_for`]): a NOTE read, history or editor
//! bind of a NOTE the room the call names holds, for a principal verified in
//! that room, or an editor's close of a room hold this host keeps for the
//! caller. A session header alone never decides, and a vault NOTE read
//! inside a session keeps its receipt as it did.
//!
//! Each transport asks once its call's input is read and before the call
//! runs, so a close that drops its hold keeps the answer it arrived with;
//! its receipt ORs that answer in, as it ORs the anonymous exception.

use axum::http::HeaderMap;
use oneiron::EntityId;
use oneiron::off_record::RoomNoteHandle;
use serde_json::Value;

use crate::server::SyncServer;

/// The room hold an editor's close names in `input` (its `binding`), as
/// this host keeps it for `principal`; `None` for any other call, a binding
/// that holds a vault document, or another caller's.
pub(crate) fn held_room_note(
    server: &SyncServer,
    principal: Option<EntityId>,
    input: Option<&Value>,
) -> Option<RoomNoteHandle> {
    let binding = input?.get("binding")?.as_str()?;
    server.note_editors.room_hold(principal?, binding)
}

/// Whether a call of row `verb` with `input`, made for `principal` in the
/// session `session_ref` names, serves a room NOTE
/// ([`oneiron::Vault::room_note_call_for`]).
pub(crate) fn room_note_call(
    server: &SyncServer,
    session_ref: Option<&str>,
    principal: Option<EntityId>,
    verb: &str,
    input: Option<&Value>,
) -> bool {
    let held = held_room_note(server, principal, input);
    server
        .vault()
        .room_note_call_for(session_ref, principal, verb, input, held.as_ref())
}

/// [`room_note_call`] of a call whose `x-oneiron-session` header names its
/// session: the HTTP facade's.
pub(crate) fn header_room_note_call(
    server: &SyncServer,
    headers: &HeaderMap,
    principal: Option<EntityId>,
    verb: &str,
    input: Option<&Value>,
) -> bool {
    room_note_call(
        server,
        super::request_session_ref(headers),
        principal,
        verb,
        input,
    )
}

/// [`header_room_note_call`] of an MCP `tools/call`, whose `params` carry
/// the row's input as `arguments.spec`.
pub(crate) fn mcp_room_note_call(
    server: &SyncServer,
    headers: &HeaderMap,
    principal: Option<EntityId>,
    tool: &str,
    params: Option<&Value>,
) -> bool {
    let input = params
        .and_then(|params| params.get("arguments"))
        .and_then(|arguments| arguments.get("spec"));
    header_room_note_call(server, headers, principal, tool, input)
}
