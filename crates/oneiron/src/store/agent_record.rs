//! Core half of `store::agent_record`: its store-layer items live in `oneiron_store::agent_record` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::agent_record::*;

use crate::error::{ArtifactError, Error, Result};

/// A versioned reference to a code-mode MCP, patterned on [`SkillDependency`].
///
/// `min_version` is the cheap forward hook for the OF-215 trajectory where MCPs
/// become versioned entities; today it is stored verbatim and never
/// existence-checked at write time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct McpRef {
    pub key: String,
    pub min_version: Option<String>,
}

impl McpRef {
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            min_version: None,
        }
    }

    #[must_use]
    pub fn with_min_version(key: impl Into<String>, min_version: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            min_version: Some(min_version.into()),
        }
    }
}

/// How a resident's own dreaming chooses its model and window.
///
/// `Inherit` shares the vault weaver model and window, never the resident's
/// diary. `Own` uses the resident's model slot (or its talking model when the
/// slot is unset). `Off` disables that resident's dreaming, not the vault weave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamingMode {
    Own,
    Inherit,
    Off,
}

impl DreamingMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::Inherit => "inherit",
            Self::Off => "off",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "own" => Some(Self::Own),
            "inherit" => Some(Self::Inherit),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Resident wake dial. A cadence interval of `None` inherits the vault grain.
/// Surprise and agency are independent signals; a worker never wakes on time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentWakeCadence {
    Companion { every_turns: Option<u64> },
    Leader { every_turns: Option<u64> },
    Worker,
}

/// Optional per-entity-class share of the window budget.
///
/// Absent means the engine default split holds. Every fraction is validated
/// finite and strictly inside `(0.0, 1.0)`, and the four sum to `1.0 ± 1e-6`.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct ContextBudgetSplit {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

impl ContextBudgetSplit {
    #[must_use]
    pub const fn new(claims: f32, turns: f32, summaries: f32, other: f32) -> Self {
        Self {
            claims,
            turns,
            summaries,
            other,
        }
    }
}
