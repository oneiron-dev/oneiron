//! The owner's proof, the Coach and a project goal, for integration tests
//! (untangle 6.6: the Coach's `engine.controls` grant and GOAL-PRIVACY).

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::grant_scope;
use crate::vault::Vault;
use crate::workspace_roster::{GoalAxis, GoalExplorationBudget, GoalPreference, GoalRecord};

/// The four Steward verbs that let their holder tune the engine's stored
/// knobs, one per class of knob.
pub const ENGINE_CONTROLS_VERBS: [&str; 4] = grant_scope::ENGINE_CONTROLS_VERBS;

/// The work-budget class verb alone.
pub const ENGINE_CONTROLS_WORK_BUDGET_VERB: &str = grant_scope::ENGINE_CONTROLS_WORK_BUDGET_VERB;

/// The Coach's default verbs: `read` and the four `engine.controls` classes.
#[must_use]
pub fn read_and_engine_controls() -> Vec<&'static str> {
    let mut verbs = vec![grant_scope::STEWARD_READ_VERB];
    verbs.extend(grant_scope::ENGINE_CONTROLS_VERBS);
    verbs
}

/// The Coach's actor id.
///
/// # Errors
///
/// The vault's.
pub fn coach(vault: &Vault) -> Result<EntityId> {
    Ok(vault.coach_authority()?.entity_ref())
}

fn axis(name: &str, measure: &str, bound: &str) -> GoalAxis {
    GoalAxis {
        name: name.into(),
        measure: measure.into(),
        bound: bound.into(),
    }
}

/// Writes one goal into the root project from an owner's intake; the
/// project.
///
/// # Errors
///
/// The vault's.
pub fn write_root_goal(vault: &Vault, owner: &AuthenticatedOwner) -> Result<EntityId> {
    let project = vault.root_project()?;
    let goal = GoalRecord {
        goal: "Answer customer requests correctly".into(),
        why: "Reduce repeat support tickets".into(),
        primary_axes: vec![axis(
            "confirmed_answers",
            "resolved requests per week from receipts",
            ">= 90",
        )],
        floor_axes: vec![axis(
            "unsafe_answers",
            "held-out unsafe answer count",
            "= 0",
        )],
        // A goal's cost axes name the human's minutes (GoalRecord::validate).
        cost_axes: vec![
            axis("tokens", "token spend per week", "<= 10000"),
            axis("human_minutes", "owner minutes per week", "<= 20"),
        ],
        preferences: vec![GoalPreference {
            prefer: "lower cost".into(),
            over: "faster response".into(),
            reason: "The human chose cost on this tradeoff".into(),
        }],
        exploration_budget: GoalExplorationBudget {
            max_spend: 1000,
            exploration_slice: 100,
            unit: crate::run_budget::LeaseUnit::tokens(),
            human_minutes: 20,
        },
    };
    vault.write_project_goal_from_intake(owner, project, &goal, 2)?;
    Ok(project)
}

/// Writes a minimal human-authored agent definition, as the owner's own
/// agent; its id.
///
/// # Errors
///
/// The vault's.
pub fn define_agent(vault: &Vault) -> Result<EntityId> {
    use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    let definition = AgentDefinition::new(
        "oneiron.agent.free-time-fixture",
        "Free-time fixture agent",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    );
    let id = EntityId::now();
    vault.put_agent_definition(
        &id,
        &definition,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
    )?;
    Ok(id)
}
