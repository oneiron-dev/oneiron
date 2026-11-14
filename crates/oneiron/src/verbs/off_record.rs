//! The off-record session rows (DOOR-127, e2e PRIVACY-06): typed calls over
//! the engine's off-record lifecycle (ARCH-0052) that a client reaches
//! through the verb table, as `/v1/owner/off-record` reaches it by hand.
//! `vault.off_record.start`, `.status`, `.witness` and `.discard` enter,
//! read, speak in and close a session; close without a save is the
//! discard. `vault.off_record.recall` reads the room's overlay with base, on
//! the caller's own credential.
//! `vault.off_record.notes.create` and `.claims.upsert` write through the
//! session's handle, so the row lands in the room's overlay and close drops
//! it. `self.off_record.execute` runs one entry of a durable code-mode run
//! bound to the session, so its replay rows and its spilled outputs stay in
//! the room too.
//!
//! A stretch entered alone is managed by the person or agent who entered it,
//! on their own live slip, and by the vault's live owner on their proof
//! (WILL-PLAN L13 row 03, Engine ruling 2026-10-19). A room's stretch keeps
//! its members' bounded status and witness; recall, writes, runs and
//! discard of the whole room answer
//! `OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE`. The session lives on the
//! served host that entered it, which admits its manager on every call, so a
//! bare embedded handle, which binds no session manager, answers each row
//! with [`off_record_host_only`].
//!
//! The owner adapter's shapes have no wire form in the engine, so the
//! inputs and answers are spelled here, field for field as the owner routes
//! read and answer them.

use serde::{Deserialize, Serialize};

use crate::code_run::ProgramStepFeedbackRelease;
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
use crate::off_record::{OffRecordBackendClass, OffRecordMode};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::off_record::{
    OffRecordArtifactSaveRequest, OffRecordArtifactSaved, OffRecordClaimRequest, OffRecordClosed,
    OffRecordEnterMode, OffRecordExecuteRequest, OffRecordExecuted, OffRecordNoteRequest,
    OffRecordRecallRequest, OffRecordRunStatus, OffRecordSessionRequest, OffRecordSessionView,
    OffRecordStartRequest,
};

/// `vault.off_record.witness`'s input, as `POST /v1/owner/off-record/witness`
/// reads it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordWitnessRequest {
    pub session_ref: String,
    /// The turn, as `vault.witness` takes it; leave `conversation_ref` empty
    /// to write into the room's own conversation.
    pub turn: crate::memory::WitnessTurn,
    /// A summary of the turn; it stays in the room with the turn.
    #[serde(default)]
    pub summary: Option<String>,
}

impl From<crate::off_record::PromoteOutcome> for OffRecordArtifactSaved {
    fn from(outcome: crate::off_record::PromoteOutcome) -> Self {
        Self {
            replayed: outcome
                .replayed
                .iter()
                .map(crate::EntityId::to_hex)
                .collect(),
            short_ids: outcome
                .short_id_mapping
                .into_iter()
                .map(
                    |(room, vault)| super::off_record_rooms::OffRecordRoomShortIdPair {
                        room,
                        vault,
                    },
                )
                .collect(),
        }
    }
}

/// A session row on a bare embedded handle: refused, as this handle binds no
/// session manager. The session lives in the served host's RAM, the host
/// that entered it, which admits its manager (its creator or the vault's
/// owner) on every call; the engine's in-process served client reaches that
/// host from the same process, as a remote client reaches a server. No port
/// injects a manager into a bare handle (Engine ruling FIX 4595).
///
/// # Errors
///
/// Always.
pub fn off_record_host_only<I, T>(_memory: &Memory<'_>, verb: &str, _input: &I) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!(
            "{verb} cannot use this bare handle: the session lives in the served host's RAM; this handle binds no session manager"
        ),
        &[super::host::SERVED_CLIENT_HINT],
    ))
}
