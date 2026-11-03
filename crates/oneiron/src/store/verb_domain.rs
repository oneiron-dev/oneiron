//! Read/write domain of a verb hook boundary.

use serde::{Deserialize, Serialize};

/// What a blocking hook's failure does to the verb (DEC-0006 invariant 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerbDomain {
    /// A failed blocking pre-hook hides the result.
    Read,
    /// A failed blocking pre-hook sends the verb to an ask.
    Write,
}
