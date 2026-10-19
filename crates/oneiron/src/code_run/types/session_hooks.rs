//! What each verb hook bound to a read did in an off-record room, as the
//! read's answer says it (WILL L11-01 S01-2c, FIX 5160; CALLS-9
//! `session_hook_meta_shape`).
//!
//! A hook bound to a read runs in a room as it runs on base. Its receipt
//! stages in the room's own store, and its outcome applies whether the room
//! keeps that receipt or not: the read answers either way, and the answer
//! names each hook's disposition, so a hook the room could not keep a record
//! for is never silent. The run's search with no key also answers when the
//! hooks bound to it could not be read, and says so (Engine 10-19 17:1x).
//! Outside a room the list is empty.

use serde::{Deserialize, Serialize};

/// One verb hook's run on a read in a room: the hook, its phase, what came
/// of it and where its receipt is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHookDisposition {
    /// The hook, as `pack/hook`; none for [`SessionHookState::Unread`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    pub phase: SessionHookPhase,
    pub state: SessionHookState,
    pub receipt: SessionHookReceipt,
}

/// Whether the hook ran before the read or after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionHookPhase {
    Pre,
    Post,
}

/// What came of one hook's run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionHookState {
    /// Its outcome applied, as on base: `continue`, `annotate`, `rewrite`,
    /// `skip`, `redact` or `nothing`.
    Applied { outcome: String },
    /// Its outcome was refused, or its run failed or timed out (`refused`,
    /// `failed`, `timed_out`), and why. A blocking hook's `fail_safe` says
    /// what that did to the read (`hidden`), as on base.
    Refused {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fail_safe: Option<String>,
    },
    /// Its outcome needs canonical work a room does not do (CALLS-3
    /// `session_hook_consequence_support`): `reason` is
    /// `session_hook_unavailable`, and `consequence` the work (`ask`,
    /// `add_block`, `propose`, `enqueue`, `effect`). Nothing of it ran; the
    /// read answered.
    Unavailable { reason: String, consequence: String },
    /// The hooks bound to the run's search with no key could not be read
    /// (the bindings, a binding's scope or its grant), and `reason` names
    /// the read that failed: none of them ran in this phase, and the search
    /// answered as it does with no hook bound.
    Unread { reason: String },
}

/// The room's receipt of one hook's run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionHookReceipt {
    /// The room keeps it, under this receipt id (`hook:<run key>`).
    Kept { id: String },
    /// The room keeps none, and why; the hook's outcome applied all the same.
    NotKept { why: SessionHookNotKept },
    /// No hook ran, so there is no receipt ([`SessionHookState::Unread`]).
    NoRun,
}

/// Why a session keeps no receipt of a hook's run (CALLS-2
/// `session_hook_write_target`, CALLS-4 `session_receipt_budget_policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionHookNotKept {
    /// The room's byte budget refused the hook's records: they are ordinary
    /// budgeted bytes.
    BudgetFull,
    /// The side-row wall found a secret in a record, which only a vault's
    /// custody door may mint, and a session holds none.
    Custody,
    /// An anonymous room retains no record.
    NoRetention,
    /// The room is on record but holds unsaved rows: records of a hook that
    /// read them never land in base.
    WithheldFromBase,
}
