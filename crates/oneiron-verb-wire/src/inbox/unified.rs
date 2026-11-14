//! Moved from `crates/oneiron/src/inbox/unified.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The host's compilation target for a Dreamer answer, as the wire carries
/// it: the [`CompilationTarget`] shape with a schema derive. Present it is
/// authoritative (ARCH-0056).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "text", rename_all = "snake_case")]
pub enum InboxGroupResolveTarget {
    /// Preserve the existing lexical-claim/content-skill-edit chooser.
    Fallback,
    /// Propose a prohibition. Does not install an enforcement rule.
    Ban(String),
    /// Propose an OF-332 style token. Does not supersede an expression head.
    StyleRule(String),
    /// Propose a line for the acting charter. Does not change its authority.
    CharterLine(String),
    /// Propose a brief update. Does not mutate a brief.
    BriefUpdate(String),
}
