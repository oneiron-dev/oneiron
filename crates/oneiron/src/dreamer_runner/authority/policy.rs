//! Dreamer job roster and the boundary for minting a separate agent.
//!
//! A job kind is not an agent identity. The roster only groups shipped job
//! types; additional responsibility contracts in ARCH-0026 are design targets,
//! not synthetic dispatchers. Unknown extension kinds retain their own facet
//! name at the authority-stamping door.

use crate::agent_def::AgentCeiling;
use crate::llm::ModelLocality;

/// The shipped Dreamer job types and their shared authority facets.
/// Generic user agent dispatch is deliberately not part of this roster.
#[must_use]
pub fn dreamer_facet_for_job_type(job_type: &str) -> Option<&'static str> {
    use super::super::{
        DREAMER_PLUGIN_SUGGEST_ATTEMPT_TYPE, DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND,
        DREAMER_VAULT_CLEANUP_ATTEMPT_KIND,
    };
    match job_type {
        "micro" | "meso" | "macro" => Some("dreamer.consolidation"),
        crate::dreamer_consolidation::DREAMER_GAP_SCAN_ATTEMPT_TYPE => {
            Some("dreamer.consolidation")
        }
        crate::dreamer_consolidation::DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE => {
            Some("dreamer.consolidation")
        }
        DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND => Some(DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND),
        DREAMER_VAULT_CLEANUP_ATTEMPT_KIND => Some(DREAMER_VAULT_CLEANUP_ATTEMPT_KIND),
        super::super::maintenance::CURATOR_FACET => Some(super::super::maintenance::CURATOR_FACET),
        super::super::maintenance::HARNESS_FACET => Some(super::super::maintenance::HARNESS_FACET),
        super::super::maintenance::representation::REPRESENTATION_FACET => {
            Some(super::super::maintenance::representation::REPRESENTATION_FACET)
        }
        DREAMER_PLUGIN_SUGGEST_ATTEMPT_TYPE => Some(DREAMER_PLUGIN_SUGGEST_ATTEMPT_TYPE),
        super::super::connector_event::CONNECTOR_EVENT_FACET => {
            Some(super::super::connector_event::CONNECTOR_EVENT_FACET)
        }
        _ => None,
    }
}

/// Only these authority-boundary properties warrant a *new* Dreamer agent.
/// Job kind, skill, model tier, purpose, and project scope remain facets or
/// configuration on the existing principal. This does not limit users' right
/// to define custom agents with their own explicit authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerAgentBoundary<'a> {
    pub soul: &'a str,
    pub access_ceiling: AgentCeiling,
    pub locality: ModelLocality,
}

#[must_use]
pub fn warrants_new_agent(
    current: DreamerAgentBoundary<'_>,
    proposed: DreamerAgentBoundary<'_>,
) -> bool {
    current != proposed
}
