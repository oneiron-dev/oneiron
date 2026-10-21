//! `[models.roles.browser_planner]`: the mid planner a browser subgoal's
//! next code-mode step runs on (CUA E5, DESIGN-2 §4), on the Local-vision
//! pattern: a role of its own, written like any DETAILED role (`model` and
//! an optional `prompt`, or `rungs`), with no model chosen for it.
//!
//! Only DETAILED binds it. HIGH and MID fill [`super::SHORTHAND_ROLES`]
//! alone, so with no `[models.roles.browser_planner]` every code-mode step
//! stays on `generative_reasoner`. It is not `[models.planner]`, which picks
//! a leased agent's spawn shapes.
//!
//! In code mode (`ai_host/browser_planner.rs`) a batch or library run that
//! ends `NEEDS_AGENT` makes its subgoal active and sends that subgoal's
//! next step here. From its [`NEEDS_AGENT_BEFORE_CHAT`]th miss, at once on a
//! `no_progress` stop, or while no rung serves the role, the step takes
//! `generative_reasoner`, which keeps the subgoal until it ends. That is an
//! escalation, never a refusal: no count refuses or caps a run, and both
//! roles spend on the run's own meter.
use oneiron::llm::manifest::ModelRole;

/// The browser planner's role.
pub const BROWSER_PLANNER_ROLE: ModelRole = ModelRole::BrowserPlanner;

/// The `NEEDS_AGENT` answers one browser subgoal takes before the chat role
/// takes its steps: the second sends it there (DESIGN-2 §4, ruled).
pub const NEEDS_AGENT_BEFORE_CHAT: u32 = 2;

/// Whether a model manifest with no row for `role` leaves the role
/// unseated, as a server with no rung for it does (`NoSeat`), rather than
/// refusing its call: the browser planner's alone (Engine, 10-22), so its
/// steps take the chat role. Every other role's missing row still refuses.
#[must_use]
pub const fn unbound_row_is_no_seat(role: ModelRole) -> bool {
    matches!(role, ModelRole::BrowserPlanner)
}
