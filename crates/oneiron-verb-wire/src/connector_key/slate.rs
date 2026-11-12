//! Moved from `crates/oneiron/src/connector_key/slate.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The owner and holder edges' key for the elicitation row, beside tool
/// names. MCP tool names are `[A-Za-z0-9_.-]`, so no tool can take it, and
/// a slate refuses a tool that tries.
pub const ELICITATION_ROW_KEY: &str = "@elicitation";

/// A slate row's typed identity: one declared tool, or the one MCP client
/// capability ARCH-0072 gives a permission row. Elicitation is never a
/// callable tool; sampling, roots and logging are not rows (DEC-0006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SlateCapability<'a> {
    Tool(&'a str),
    Elicitation,
}

impl<'a> SlateCapability<'a> {
    /// An edge row key: [`ELICITATION_ROW_KEY`] is the elicitation row, any
    /// other key names a tool.
    pub fn parse(key: &'a str) -> Self {
        if key == ELICITATION_ROW_KEY {
            Self::Elicitation
        } else {
            Self::Tool(key)
        }
    }

    /// The key the owner and holder edges name this row by.
    pub fn key(self) -> &'a str {
        match self {
            Self::Tool(name) => name,
            Self::Elicitation => ELICITATION_ROW_KEY,
        }
    }
}

/// Immutable pack identity included in the slate's manifest hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlatePackSource {
    pub source_ref: String,
    pub content_hash: String,
}
