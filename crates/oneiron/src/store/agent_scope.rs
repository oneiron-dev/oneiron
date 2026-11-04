//! The run scope persisted with an agent definition: every world, base
//! reality only, or one world plus base reality.

use crate::entity_id::EntityId;
#[cfg(doc)]
use crate::pipeline::WorldScope;
use crate::store::agent_definition_codec::keys::{SCOPE_ALL, SCOPE_BASE, SCOPE_WORLD};

/// The run scope persisted with an `AgentDefinition`.
///
/// A new persisted descriptor rather than an embedded [`WorldScope`], which is
/// a runtime-only type that does not implement `Serialize`. `World` carries the
/// world's [`EntityId`], hex-encoded into the body. `WorldSet` is deliberately
/// not modelled here — it is a repo-clamp key with no day-1 caller, and a later
/// additive variant per the `#[non_exhaustive]` marker.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentScope {
    /// Span every world (the constructor default; matches `PipelineBuilder`).
    All,
    /// Base-reality only.
    Base,
    /// This world plus base reality.
    World(EntityId),
}

impl AgentScope {
    pub(crate) fn discriminant(&self) -> &'static str {
        match self {
            Self::All => SCOPE_ALL,
            Self::Base => SCOPE_BASE,
            Self::World(_) => SCOPE_WORLD,
        }
    }
}
