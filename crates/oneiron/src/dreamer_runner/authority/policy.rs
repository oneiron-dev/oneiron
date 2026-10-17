//! The runner's job roster, its two base agents, and the boundary for minting
//! a separate agent.
//!
//! A job kind is not an agent identity. The roster only groups shipped job
//! types; additional responsibility contracts in ARCH-0026 are design targets,
//! not synthetic dispatchers. Unknown extension kinds retain their own facet
//! name at the authority-stamping door.

use crate::agent_def::AgentCeiling;
use crate::llm::ModelLocality;

/// The two base agents on the runner (ARCH-0026 #base-agents). A job that
/// changes what the vault knows is the Dreamer's; one that changes how agents
/// behave is the Coach's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseAgent {
    Dreamer,
    Coach,
}

/// The base agent a stamped facet runs under. SKILL-OPT is the Coach's but
/// keeps its `dreamer.skill_optimize` token: it is a persisted queue kind,
/// payload type and provenance facet.
#[must_use]
pub fn base_agent_for_facet(facet: &str) -> BaseAgent {
    if facet == super::super::DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND || facet.starts_with("coach.") {
        BaseAgent::Coach
    } else {
        BaseAgent::Dreamer
    }
}

/// The shipped runner job types and their shared authority facets.
/// Generic user agent dispatch is deliberately not part of this roster.
#[must_use]
pub fn dreamer_facet_for_job_type(job_type: &str) -> Option<&'static str> {
    use super::super::{
        COACH_HEAL_ATTEMPT_KIND, COACH_RETRIEVAL_TUNE_FACET, DREAMER_NOTE_REVIEW_ATTEMPT_KIND,
        DREAMER_PLUGIN_SUGGEST_ATTEMPT_TYPE, DREAMER_RECIPE_WAKE_ATTEMPT_KIND,
        DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND, DREAMER_VAULT_CLEANUP_ATTEMPT_KIND,
        DREAMER_WEAVE_RECIPE_ATTEMPT_KIND, maintenance::coach,
    };
    match job_type {
        "micro" | "meso" | "macro" => Some("dreamer.consolidation"),
        super::super::maintenance::CONSOLIDATION_STRENGTH_FACET => Some("dreamer.consolidation"),
        crate::dreamer_consolidation::DREAMER_GAP_SCAN_ATTEMPT_TYPE => {
            Some("dreamer.consolidation")
        }
        crate::dreamer_consolidation::DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE => {
            Some("dreamer.consolidation")
        }
        crate::dreamer_consolidation::DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE => {
            Some("dreamer.consolidation")
        }
        crate::dreamer_consolidation::DREAMER_PERSON_ABOUT_ATTEMPT_TYPE => {
            Some("dreamer.consolidation")
        }
        // The review promotes beliefs on the consolidation executor, so it
        // runs as the consolidation facet that executor is built for.
        DREAMER_NOTE_REVIEW_ATTEMPT_KIND => Some("dreamer.consolidation"),
        DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND => Some(DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND),
        DREAMER_VAULT_CLEANUP_ATTEMPT_KIND => Some(DREAMER_VAULT_CLEANUP_ATTEMPT_KIND),
        DREAMER_WEAVE_RECIPE_ATTEMPT_KIND => Some(DREAMER_WEAVE_RECIPE_ATTEMPT_KIND),
        DREAMER_RECIPE_WAKE_ATTEMPT_KIND => Some(DREAMER_RECIPE_WAKE_ATTEMPT_KIND),
        COACH_HEAL_ATTEMPT_KIND => Some(COACH_HEAL_ATTEMPT_KIND),
        COACH_RETRIEVAL_TUNE_FACET => Some(COACH_RETRIEVAL_TUNE_FACET),
        super::super::maintenance::honesty::HONESTY_AUDIT_FACET => {
            Some(super::super::maintenance::honesty::HONESTY_AUDIT_FACET)
        }
        coach::COACH_SKILL_DISTILL_FACET => Some(coach::COACH_SKILL_DISTILL_FACET),
        coach::COACH_SKILL_DISCOVERY_FACET => Some(coach::COACH_SKILL_DISCOVERY_FACET),
        coach::COACH_PERSON_THRESHOLD_FACET => Some(coach::COACH_PERSON_THRESHOLD_FACET),
        coach::COACH_READ_HARDENING_FACET => Some(coach::COACH_READ_HARDENING_FACET),
        coach::COACH_TRIPWIRES_FACET => Some(coach::COACH_TRIPWIRES_FACET),
        coach::COACH_TRADEOFF_ESCALATION_FACET => Some(coach::COACH_TRADEOFF_ESCALATION_FACET),
        coach::COACH_TRAINING_OFFER_FACET => Some(coach::COACH_TRAINING_OFFER_FACET),
        coach::COACH_JUDGE_SWAP_FACET => Some(coach::COACH_JUDGE_SWAP_FACET),
        coach::COACH_TRADEOFF_ROUTE_FACET => Some(coach::COACH_TRADEOFF_ROUTE_FACET),
        coach::COACH_SEAL_CHECKS_FACET => Some(coach::COACH_SEAL_CHECKS_FACET),
        coach::COACH_ATTRIBUTION_AUDITS_FACET => Some(coach::COACH_ATTRIBUTION_AUDITS_FACET),
        coach::COACH_TYPE_TREE_UPKEEP_FACET => Some(coach::COACH_TYPE_TREE_UPKEEP_FACET),
        coach::COACH_ROOM_UPKEEP_FACET => Some(coach::COACH_ROOM_UPKEEP_FACET),
        coach::COACH_OFFER_CHECK_FACET => Some(coach::COACH_OFFER_CHECK_FACET),
        coach::COACH_TRAINING_OFFERS_FACET => Some(coach::COACH_TRAINING_OFFERS_FACET),
        coach::COACH_RESEARCH_SELECT_FACET => Some(coach::COACH_RESEARCH_SELECT_FACET),
        coach::COACH_LEARNING_SWEEP_FACET => Some(coach::COACH_LEARNING_SWEEP_FACET),
        super::super::maintenance::agent_health::COACH_AGENT_HEALTH_FACET => {
            Some(super::super::maintenance::agent_health::COACH_AGENT_HEALTH_FACET)
        }
        super::super::maintenance::agent_health::COACH_AGENT_HEALTH_ASK_FACET => {
            Some(super::super::maintenance::agent_health::COACH_AGENT_HEALTH_ASK_FACET)
        }
        super::super::maintenance::COACH_CALIBRATION_ASKS_FACET => {
            Some(super::super::maintenance::COACH_CALIBRATION_ASKS_FACET)
        }
        coach::COACH_ISSUES_FACET => Some(coach::COACH_ISSUES_FACET),
        coach::COACH_CODE_FIX_FACET => Some(coach::COACH_CODE_FIX_FACET),
        super::super::maintenance::CURATOR_FACET => Some(super::super::maintenance::CURATOR_FACET),
        super::super::maintenance::HARNESS_FACET => Some(super::super::maintenance::HARNESS_FACET),
        super::super::maintenance::action_mode::ACTION_MODE_FACET => {
            Some(super::super::maintenance::action_mode::ACTION_MODE_FACET)
        }
        super::super::maintenance::representation::REPRESENTATION_FACET => {
            Some(super::super::maintenance::representation::REPRESENTATION_FACET)
        }
        super::super::maintenance::stewardship::STEWARDSHIP_FACET => {
            Some(super::super::maintenance::stewardship::STEWARDSHIP_FACET)
        }
        super::super::maintenance::identity::IDENTITY_RECHECK_FACET => {
            Some(super::super::maintenance::identity::IDENTITY_RECHECK_FACET)
        }
        crate::consult_ladder::DREAMER_MAGISTRATE_ATTEMPT_TYPE => {
            Some(crate::consult_ladder::DREAMER_MAGISTRATE_ATTEMPT_TYPE)
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
