//! Moved from `crates/oneiron/src/verbs/off_record.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::type_diagnostics::ProgramStepFeedbackRelease;
use crate::off_record::lifecycle::types::OffRecordBackendClass;
use crate::off_record::lifecycle::types::OffRecordMode;
use serde::Deserialize;
use serde::Serialize;

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
    /// The caller's retrieval filter (FIX 3977): the room's overlay and base
    /// are both read under it.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

/// `vault.off_record.notes.create`'s input: one NOTE, as
/// `vault.notes.create` takes it, written into the session's room.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordNoteRequest {
    pub session_ref: String,
    pub note: crate::memory::session_reads::CreateNoteRequest,
    /// TURN refs the NOTE was written from, kept in its room birth as
    /// supplied (FIX 4281): each the room reads as a TURN is an input; any
    /// other is kept as bookkeeping, and none refuses the NOTE.
    #[serde(default)]
    pub evidence_turn_refs: Vec<String>,
}

/// `vault.off_record.claims.upsert`'s input: one claim, as
/// `vault.claims.upsert` takes it, written into the session's room.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordClaimRequest {
    pub session_ref: String,
    pub claim: crate::memory::claim_admission::ScopedClaimInput,
}

/// Explicitly preserve one selected room NOTE/CLAIM and its complete document.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordArtifactSaveRequest {
    pub session_ref: String,
    /// The room alias or entity id of the selected scratch artifact.
    pub artifact_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordArtifactSaved {
    /// The actual saved closure, including staged subjects needed by the artifact.
    pub replayed: Vec<String>,
    pub short_ids: Vec<super::off_record_rooms::OffRecordRoomShortIdPair>,
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
    /// Each program step's type feedback the run keeps on the session's
    /// route, as it stands, beside the answer and never inside it (FIX
    /// 10389): released whole, or withheld with none of its text when its
    /// own release check holds it for the destination. Its late result is
    /// read by its `check_ref` and this session's ref with
    /// `vault.code.type_diagnostics`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub program_steps: Vec<ProgramStepFeedbackRelease>,
}
