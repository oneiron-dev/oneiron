//! The input of `vault.runs.read_result` (FIX EXECUTE-CALLER-CODE): a caller's
//! code reads a window of one stored result of one of its own runs. An
//! `execute` result cut at 20,000 characters names the run and the result
//! this reads, so a larger result is read in code rather than through a third
//! MCP tool. The run's own door answers it (the server's code-mode door, which
//! derives the run from the caller's credential); the engine never does.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The most bytes one read returns: the cut an `execute` result is held to.
pub const RUN_RESULT_READ_MAX_BYTES: u64 = 20_000;

/// One window of one stored result of one of the caller's own runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunResultReadRequest {
    /// The run_ref the caller's `execute` call sent or was given.
    pub run_ref: String,
    /// The result to read, as the run names it: a bound name, a handle or a
    /// range ref. An `execute` result past its cut names it.
    pub result_ref: String,
    /// Where the window starts, in bytes of the stored body. Default 0.
    #[serde(default)]
    pub offset: Option<u64>,
    /// How many bytes the window holds. Default and most: 20,000.
    #[serde(default)]
    pub limit: Option<u64>,
}

impl RunResultReadRequest {
    /// The `slice` read this window asks for: `bytes: [offset, offset +
    /// limit]`, the limit held to [`RUN_RESULT_READ_MAX_BYTES`]. The slice
    /// cuts a text view at character boundaries and says where to read on.
    #[must_use]
    pub fn slice_input(&self) -> Value {
        let offset = self.offset.unwrap_or(0);
        let limit = self
            .limit
            .unwrap_or(RUN_RESULT_READ_MAX_BYTES)
            .min(RUN_RESULT_READ_MAX_BYTES);
        json!({ "bytes": [offset, offset.saturating_add(limit)] })
    }
}
