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

use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
use crate::off_record::{OffRecordBackendClass, OffRecordMode};

/// How `vault.off_record.start` enters a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordEnterMode {
    /// Turns and writes stay in the room until promoted or dropped at close.
    OffRecord,
    /// No transcript, memory, telemetry or receipt is kept.
    Anonymous,
}

/// `vault.off_record.start`'s input, as `POST /v1/owner/off-record` reads it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordStartRequest {
    /// The caller's own name for the session, 1 to 256 bytes: the owner's
    /// names are the owner's, and every other creator's are their own, so a
    /// name another caller holds is never "taken" (FIX 4597).
    pub session_ref: String,
    pub mode: OffRecordEnterMode,
    /// `local` when inference stays on this device, `remote_provider` when a
    /// model provider sees the turns (and may keep what it saw).
    pub backend: OffRecordBackendClass,
}

/// The one session a row names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordSessionRequest {
    pub session_ref: String,
}

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

/// One live session as its owner sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordSessionView {
    /// What later calls and the session header name it by. A stretch a
    /// creator entered answers its opaque instance handle (FIX 4597); its
    /// creator may name it by their own name for it too. A handle is no
    /// authority: it binds only for its creator, or the owner on their proof.
    pub session_ref: String,
    /// `off_record`, `on_record` or `anonymous`.
    pub mode: OffRecordMode,
    pub backend: OffRecordBackendClass,
    /// RFC 3339, UTC.
    pub entered_at: String,
    /// Turns already saved to the vault, by id; close keeps them.
    pub promoted_turns: Vec<String>,
    pub closing: bool,
}

/// What `vault.off_record.discard` dropped and what it kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordClosed {
    pub session_ref: String,
    pub turns_dropped: usize,
    pub context_receipts_dropped: usize,
    pub emit_receipts_dropped: usize,
    /// Emit receipts recorded after the session went on record.
    pub emit_receipts_kept: usize,
    pub promoted_turns_kept: usize,
}

/// `vault.off_record.recall`'s input: a light recall over the room's
/// overlay and base, at the default scope.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordRecallRequest {
    pub session_ref: String,
    pub query: String,
    /// Items to return, as `vault.recall` counts them.
    pub limit: usize,
}

/// `vault.off_record.notes.create`'s input: one NOTE, as
/// `vault.notes.create` takes it, written into the session's room.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordNoteRequest {
    pub session_ref: String,
    pub note: crate::task_verb::sdk::CreateNoteRequest,
}

/// `vault.off_record.claims.upsert`'s input: one claim, as
/// `vault.claims.upsert` takes it, written into the session's room.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordClaimRequest {
    pub session_ref: String,
    pub claim: crate::memory::ScopedClaimInput,
}

/// `self.off_record.execute`'s input: one entry of the durable code-mode run
/// `run_ref` names in the session. The same `run_ref` in the same live
/// session enters the same run again.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordExecuteRequest {
    pub session_ref: String,
    pub run_ref: String,
    /// The task the run carries out.
    pub task: String,
}

/// Where an entry of a session-bound run left it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordRunStatus {
    /// The run ended.
    Complete,
    /// The run parked on a durable wait.
    Waiting,
    /// The run gave its turn back; enter it again to go on.
    Yielded,
    /// The run's window is full until a swap lands.
    WindowFull,
}

/// `self.off_record.execute`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordExecuted {
    pub run_ref: String,
    /// The run's id in the session, 32 hex.
    pub run_id: String,
    pub status: OffRecordRunStatus,
    /// The step the run goes on from when entered again; `None` once it
    /// ended or parked.
    pub next_step_seq: Option<u64>,
    /// Steps this entry ran.
    pub steps_run: u32,
    /// Bridge calls the run's record holds.
    pub bridge_calls: usize,
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
        &[super::sdk_host::SERVED_CLIENT_HINT],
    ))
}
