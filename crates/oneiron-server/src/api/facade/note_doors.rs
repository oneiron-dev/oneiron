//! Host-held NOTE editor bindings beside the ordinary scoped NOTE reads.

use std::sync::Arc;

use oneiron::claim::ScopedReadResult;
use oneiron::memory::MemoryError;
use oneiron::note::{
    NoteAccessRequest, NoteEditorBinding, NoteEditorCloseRequest, NoteEditorClosed, NoteReadRequest,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing};
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
            let admitted = memory.get_entity_tolerant(&input.note_ref)?;
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

/// The owner explicitly erases a NOTE's history through the engine's pin
/// boundary, or opens the shared vault's existing erase veto window.
pub(crate) async fn vault_notes_history_purge(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::NoteHistoryPurgeRequest,
) -> Listed<oneiron::task_verb::sdk::NoteHistoryPurgeOutcome> {
    super::legal_hold_doors::as_owner_naming(
        server,
        auth,
        "vault.notes.history_purge",
        move |server, owner| {
            oneiron::task_verb::sdk::purge_note_history_as_owner(server.vault(), owner, input)
        },
        |outcome| match outcome {
            oneiron::task_verb::sdk::NoteHistoryPurgeOutcome::Erased { receipt } => {
                super::host_doors::support::hex_rows([&receipt.entity])
            }
            oneiron::task_verb::sdk::NoteHistoryPurgeOutcome::Waiting { note_ref, .. } => {
                super::host_doors::support::hex_rows([note_ref])
            }
        },
    )
    .await
}

/// Run the exact history erase the owner already opened, once its shared
/// veto window permits it. The act id is not an authority credential.
pub(crate) async fn vault_notes_history_purge_execute(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::NoteHistoryPurgeExecuteRequest,
) -> Listed<oneiron::task_verb::sdk::NoteHistoryPurgeReceipt> {
    super::legal_hold_doors::as_owner_naming(
        server,
        auth,
        "vault.notes.history_purge_execute",
        move |server, owner| {
            oneiron::task_verb::sdk::execute_note_history_purge_as_owner(
                server.vault(),
                owner,
                input,
            )
        },
        |receipt| super::host_doors::support::hex_rows([&receipt.entity]),
    )
    .await
}

/// Durable engine receipts survive a host restart; an editor binding does not.
pub(crate) async fn vault_notes_history_purge_receipts(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::NoteHistoryPurgeRequest,
) -> Listed<Vec<oneiron::task_verb::sdk::NoteHistoryPurgeReceipt>> {
    super::legal_hold_doors::as_owner_naming(
        server,
        auth,
        "vault.notes.history_purge_receipts",
        move |server, owner| {
            oneiron::task_verb::sdk::note_history_purge_receipts_as_owner(
                server.vault(),
                owner,
                input,
            )
        },
        |receipts| {
            receipts
                .iter()
                .flat_map(|receipt| super::host_doors::support::hex_rows([&receipt.entity]))
                .collect()
        },
    )
    .await
}
