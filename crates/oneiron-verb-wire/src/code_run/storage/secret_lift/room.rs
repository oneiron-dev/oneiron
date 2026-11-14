//! Moved from `crates/oneiron/src/code_run/storage/secret_lift/room.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Selects an actual room and its named off-record stretch. No body is read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunRoomSecretLiftRequest {
    pub room_ref: String,
    pub session_ref: String,
}
