//! Moved from `crates/oneiron/src/memory/merge_queue_doors/check_receipt.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::merge_queue_doors::*;
use crate::merge_queue::check_inputs::QueueCheckHoldReason;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::memory::merge_queue_doors::check_receipt::CodeCheckReceiptRequest;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;

/// One phase command's recorded result: its exit status or the signal
/// that ended it, and the BLAKE3 of its recorded output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCheckCommandResult {
    pub index: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_blake3: String,
    pub stderr_blake3: String,
}

/// One retained receipt of the digest: its generation and attempt, the
/// exact target and plan, what it recorded, and its bound saved verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCheckAttemptView {
    pub generation: u32,
    pub phase: QueueCheckPhase,
    pub commit: String,
    pub tree: String,
    pub plan_digest: String,
    pub inputs_digest: String,
    pub attempt_id: String,
    pub attempt_count: u32,
    /// Whether the inputs agreed before and after the run; `None` when no
    /// run is recorded.
    pub stable_inputs: Option<bool>,
    pub completed: bool,
    /// The saved phase result.
    pub tests_passed: Option<bool>,
    pub commands: Vec<CodeCheckCommandResult>,
    pub hold: Option<QueueCheckHoldReason>,
    pub configuration_keys: Vec<String>,
    pub verdict_ref: Option<String>,
    /// The bound saved verdict's own result; `None` without one.
    pub passes: Option<bool>,
    /// The earlier receipt digest a reused receipt copied its result from.
    pub reused_from: Option<String>,
}

/// Every retained receipt of one inputs reference, in saved order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCheckReceiptView {
    pub repo: EntityId,
    pub work_ref: String,
    pub receipt_ref: String,
    pub receipts: Vec<CodeCheckAttemptView>,
}
