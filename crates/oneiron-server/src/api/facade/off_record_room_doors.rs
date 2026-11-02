//! Typed room off-record verbs over the existing participant handlers.
//! The room's own authority and membership guards apply on every transport.

use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult, WitnessReceipt};
use oneiron::task_verb::sdk::{
    OffRecordRoomExport, OffRecordRoomExportRequest, OffRecordRoomRequest, OffRecordRoomSaved,
    OffRecordRoomStartRequest, OffRecordRoomView, OffRecordRoomWitnessRequest,
};

use super::FacadeApiError;
use crate::api::off_record_rooms;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;

fn refusal(error: ApiError) -> MemoryError {
    let revoked = error.code() == crate::error::ErrorCode::Unauthorized;
    let mut refusal = FacadeApiError::from(error).into_memory_error();
    if revoked {
        // MemoryError has no 401 code; a lapsed export proof is still a 4xx.
        refusal.code = MEMORY_CODE_FORBIDDEN.to_owned();
    }
    refusal
}

pub(super) fn off_record_room_admits(auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
    off_record_rooms::door_admits(auth, verb).map_err(refusal)
}

pub(crate) async fn vault_off_record_rooms_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRoomRequest,
) -> MemoryResult<OffRecordRoomView> {
    off_record_rooms::room_status(server, auth, input)
        .await
        .map_err(refusal)
}

pub(crate) async fn vault_off_record_rooms_start(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRoomStartRequest,
) -> MemoryResult<OffRecordRoomView> {
    off_record_rooms::room_start(server, auth, input)
        .await
        .map_err(refusal)
}

pub(crate) async fn vault_off_record_rooms_witness(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRoomWitnessRequest,
) -> MemoryResult<WitnessReceipt> {
    off_record_rooms::room_witness(server, auth, input)
        .await
        .map_err(refusal)
}

pub(crate) async fn vault_off_record_rooms_save(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRoomRequest,
) -> MemoryResult<OffRecordRoomSaved> {
    off_record_rooms::room_save(server, auth, input)
        .await
        .map_err(refusal)
}

pub(crate) async fn vault_off_record_rooms_save_from_here(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRoomRequest,
) -> MemoryResult<OffRecordRoomView> {
    off_record_rooms::room_save_from_here(server, auth, input)
        .await
        .map_err(refusal)
}

pub(crate) async fn vault_off_record_rooms_export(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRoomExportRequest,
) -> MemoryResult<OffRecordRoomExport> {
    off_record_rooms::room_export(server, auth, input)
        .await
        .map_err(refusal)
}

pub(crate) async fn vault_off_record_rooms_suggest_save(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRoomRequest,
) -> MemoryResult<OffRecordRoomView> {
    off_record_rooms::room_suggest_save(server, auth, input)
        .await
        .map_err(refusal)
}

pub(crate) async fn vault_off_record_rooms_confirm_save(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRoomRequest,
) -> MemoryResult<OffRecordRoomSaved> {
    off_record_rooms::room_confirm_save(server, auth, input)
        .await
        .map_err(refusal)
}

pub(crate) async fn vault_off_record_rooms_decline_save(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRoomRequest,
) -> MemoryResult<OffRecordRoomView> {
    off_record_rooms::room_decline_save(server, auth, input)
        .await
        .map_err(refusal)
}
