//! Moved from `crates/oneiron/src/task_verb/browser_workflow.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_browser::BatchStopCause;
use oneiron_browser::ExpectInput;
use oneiron_browser::ExpectOutput;
use oneiron_browser::LibraryRunOutput;
use oneiron_browser::SecretArg;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The program a try's first lease pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowPin {
    /// The live program the handle led to, and the TASK's arguments for it.
    Active {
        record: EntityId,
        args: BTreeMap<String, String>,
        /// Secret slots' arguments in typed form, as bound (FIX 8348).
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        secret_args: BTreeMap<String, SecretArg>,
        /// The program's secret parameter names at pin time: their values
        /// are masked in the try's receipt (FIX 8348).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        secret_names: Vec<String>,
    },
    /// No program to run, and why.
    Unavailable { cause: TaskWorkflowUnavailable },
}

/// Why a try's first lease pinned no program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowUnavailable {
    /// The handle's lineage ends at `id`, retired for `reason` with no
    /// successor.
    Retired {
        id: EntityId,
        reason: Option<String>,
    },
    /// No program was ever filed under the handle.
    Missing,
    /// The library did not read; `detail` is its error.
    Unreadable { detail: String },
}

/// What a bound try's host found when it ran the pinned program, for
/// [`record_task_workflow_outcome`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowReport {
    /// The strict program ran to its end, and `checks` are the TASK's
    /// browser checks as the host read them on the page it left, in the
    /// pinned done-means' order.
    Ran {
        output: LibraryRunOutput,
        checks: Vec<TaskWorkflowCheck>,
    },
    /// The strict program handed off before its end, for `stop_cause`;
    /// `output` is its run, `None` when the call never ran.
    Program {
        stop_cause: BatchStopCause,
        output: Option<LibraryRunOutput>,
    },
    /// The pin names no program, so nothing ran.
    Unavailable,
    /// The program was started at an earlier entry and its end was never
    /// recorded (FIX 8104): whether it acted on the page is unknown.
    Interrupted,
}

/// One TASK browser check, and what the page showed for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskWorkflowCheck {
    pub expect: ExpectInput,
    pub observed: ExpectOutput,
}
