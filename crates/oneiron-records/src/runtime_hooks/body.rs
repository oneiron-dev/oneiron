//! Moved from `crates/oneiron/src/runtime_hooks/body.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use std::time::Instant;

/// A hook run that ended past its `budget_ms` (FIX 8842): a measured fact
/// beside its outcome, never a failure. Its run's state, outcome and pins
/// are what they would be within the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookBudgetOverrun {
    pub budget_ms: u32,
    /// From the run's start to its end.
    pub elapsed_ms: u64,
    /// How far past its deadline the run ended.
    pub overrun_ms: u64,
    /// Time its read and verdict callbacks took, all of them.
    pub callback_ms: u64,
    /// Reads whose callback ended past the deadline.
    pub read_overruns: u32,
    /// Verdicts whose callback ended past the deadline.
    pub verdict_overruns: u32,
}

impl HookBudgetOverrun {
    /// The overrun as a Hook receipt's named fields.
    pub fn receipt_fields(&self) -> [(&'static str, String); 6] {
        [
            ("budget_ms", self.budget_ms.to_string()),
            ("elapsed_ms", self.elapsed_ms.to_string()),
            ("overrun_ms", self.overrun_ms.to_string()),
            ("callback_ms", self.callback_ms.to_string()),
            ("read_overruns", self.read_overruns.to_string()),
            ("verdict_overruns", self.verdict_overruns.to_string()),
        ]
    }
}

/// How a runtime prepared a hook body before it ran it (FIX 9208): the body
/// stays as authored (its `body_hash` names it); a TypeScript body runs as
/// the JavaScript its preparation printed, named here by that
/// preparation's identity. JavaScript runs byte for byte as written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookPreparation {
    /// `javascript` or `typescript`: the language the body ran as.
    pub language: String,
    /// Why a body that is not JavaScript ran as written: the preparation's
    /// typed note code, never a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// A TypeScript body's preparation identity (the Oxc pin, its options,
    /// the executed JavaScript and its position map), lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// One model call a hook's verdict made, as its run settled it (FIX 10075):
/// the run instance and the lease. A hook record names it; nothing settles
/// it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSettledCallRef {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub instance: EntityId,
    pub lease: String,
}
