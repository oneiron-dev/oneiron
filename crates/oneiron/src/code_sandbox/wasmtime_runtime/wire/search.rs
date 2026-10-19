//! `vault.search`'s reply body (WILL L11-01 S01-2c): the hits, framed as the
//! row's output, and, in an off-record room, what each verb hook bound to
//! the search did. Projection only.

use serde_json::{Value, json};

use crate::code_run::{MemorySearchHit, MemorySearchOutput, SelfMemorySearchResult};

/// The guest's reply to `result`, before its budget envelope.
pub(super) fn reply(result: &SelfMemorySearchResult) -> Value {
    json!({
        "output": MemorySearchOutput {
            results: result
                .results
                .iter()
                .map(|hit| MemorySearchHit {
                    id: hit.id,
                    score: hit.score,
                })
                .collect(),
            hooks: result.hooks.clone(),
        }
    })
}
