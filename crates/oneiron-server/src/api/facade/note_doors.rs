//! Host-held NOTE editor bindings beside the ordinary scoped NOTE reads.

use std::sync::Arc;

use oneiron::claim::ScopedReadResult;
use oneiron::memory::MemoryError;
use oneiron::note::{
    NoteAccessRequest, NoteEditorBinding, NoteEditorCloseRequest, NoteEditorClosed, NoteReadRequest,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// A bind retains the engine's actual edit handle. Admission is checked again
/// after its live-document turn, so waiting never extends an expired grant.
pub(crate) async fn vault_notes_editor_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: NoteAccessRequest,
) -> Listed<ScopedReadResult<Option<NoteEditorBinding>>> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.notes.editor.bind",
        move |server, _, memory| {
            let admitted = memory.get_entity(&input.note_ref)?;
            if admitted.value.is_none() {
                return Ok(ScopedReadResult {
                    value: None,
                    receipt: admitted.receipt,
                });
            }
            let note = oneiron::memory::resolve_entity_ref(server.vault(), &input.note_ref)?;
            if server.vault().get_entity_type(&note)? != Some(oneiron::registry::ENTITY_TYPE_NOTE) {
                return Err(MemoryError::bad_request("entity is not a NOTE"));
            }
            let document = server
                .reassert_manager
                .documents()
                .open_for(note, caller.0.as_bytes())?;
            let read = memory.read_note(&NoteReadRequest {
                note_ref: input.note_ref,
                reason: input.reason,
                version: None,
                spans: Vec::new(),
            })?;
            let value = match read.value {
                Some(note) => {
                    let bytes = server
                        .retained
                        .try_reserve_alone(
                            crate::server::NoteEditors::binding_bytes(),
                            server.wire_telemetry.limit_questions(),
                        )
                        .ok_or_else(|| {
                            MemoryError::new(
                                oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
                                "NOTE editor binding reached the host's retained-memory floor",
                                &[],
                            )
                        })?;
                    let binding = server.note_editors.bind(caller.0, document, bytes)?;
                    Some(NoteEditorBinding { binding, note })
                }
                None => None,
            };
            Ok(ScopedReadResult {
                value,
                receipt: read.receipt,
            })
        },
    )
    .await
}

/// Only the binding's own principal can close it; its id is not a credential.
pub(crate) async fn vault_notes_editor_close(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: NoteEditorCloseRequest,
) -> Listed<NoteEditorClosed> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.notes.editor.close",
        move |server, _, _| {
            Ok(NoteEditorClosed {
                closed: server.note_editors.close(caller.0, &input.binding)?,
            })
        },
    )
    .await
}
