//! Frame-bound selections and result-set actions on a held card. The card id
//! locates the held manifest; each selection is the selecting credential's,
//! proved under its own read, and a result-set action is the clicking
//! credential's (FIX 3267).

use std::sync::Arc;

use oneiron::lens::{
    LensResultSetActionRequest, LensResultSetActionResult, LensSelectRequest, LensSelection,
    LensSelectionResolveRequest, LensSelectionResolved,
};
use oneiron::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::action_routes::execute_result_set_action;
use super::host_doors::support::{Listed, credential_listing, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn missing() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        "this server holds no such card, or this caller no such selection on it; re-render and select again",
        &[],
    )
}

pub(crate) async fn vault_lenses_select(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: LensSelectRequest,
) -> Listed<LensSelection> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.lenses.select",
        move |server, auth, memory| {
            let held = server
                .lens_frames
                .card(&input.card_id)
                .ok_or_else(missing)?;
            let selected = memory.lens_frame_select(&held.frame, &held.render, &input)?;
            let view = selected.clone();
            let selection_ref = server
                .lens_frames
                .remember_selection(auth, &held, selected)?
                .ok_or_else(missing)?;
            Ok(LensSelection::of_handle(selection_ref, &view))
        },
    )
    .await
}

pub(crate) async fn vault_lenses_resolve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: LensSelectionResolveRequest,
) -> Listed<LensSelectionResolved> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.lenses.resolve",
        move |server, auth, memory| {
            let held = server
                .lens_frames
                .card(&input.card_id)
                .ok_or_else(missing)?;
            let selected = server
                .lens_frames
                .selection(auth, &held, &input.selection_ref)
                .ok_or_else(missing)?;
            let source =
                memory.lens_frame_resolve_selection(&held.frame, &held.render, &selected)?;
            Ok(LensSelectionResolved {
                selection: LensSelection::of_handle(input.selection_ref, &selected),
                source,
            })
        },
    )
    .await
}

pub(crate) async fn vault_lenses_result_set_action(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: LensResultSetActionRequest,
) -> MemoryResult<LensResultSetActionResult> {
    let held = server
        .lens_frames
        .card(&input.event.action.card_id)
        .ok_or_else(missing)?;
    // Keep the same per-card lock the existing UI event door holds through effects.
    let state = held.state.lock().await;
    let current = state.clone();
    let event = input.event;
    let selected_refs = input.selected;
    let check_held = Arc::clone(&held);
    let (validated, _) = credential_listing(
        server,
        auth,
        caller,
        "vault.lenses.result_set.action",
        move |server, auth, memory| {
            let selected = selected_refs
                .iter()
                .map(|reference| {
                    server
                        .lens_frames
                        .selection(auth, &check_held, reference)
                        .ok_or_else(missing)
                })
                .collect::<MemoryResult<Vec<_>>>()?;
            memory.lens_frame_result_set_action(
                &check_held.frame,
                &check_held.render,
                &current,
                &event,
                &selected,
            )
        },
    )
    .await;
    let validated = validated?;
    let dispatch = execute_result_set_action(server, auth, &held, validated, input.idempotency_key)
        .await
        .map_err(super::FacadeApiError::into_memory_error)?;
    let outcome = dispatch
        .outcome_value()
        .map_err(|_| internal("vault.lenses.result_set.action"))?;
    drop(state);
    Ok(LensResultSetActionResult {
        outcome,
        read_receipt: dispatch.read_receipt,
    })
}
