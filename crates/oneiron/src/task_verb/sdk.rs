//! Shared typed agent-verb inputs and generated transport dispatch.
use super::TaskAskHandle;
use crate::memory::{Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskWaitRequest {
    pub handle: TaskAskHandle,
    pub step_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAnswerRequest {
    pub handle: TaskAskHandle,
    pub result_ref: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomRequest {
    pub room_ref: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomClaimRequest {
    pub room_ref: String,
    pub turn_ref: String,
}

fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> MemoryResult<T> {
    serde_json::from_value(value)
        .map_err(|_| MemoryError::bad_request("invalid typed SDK arguments"))
}
fn encode<T: Serialize>(value: T) -> MemoryResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| MemoryError::bad_request("SDK result encoding failed"))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEntry {
    pub id: String,
    pub room: crate::workspace_roster::ProjectRoom,
}
include!("sdk_generated.rs");
