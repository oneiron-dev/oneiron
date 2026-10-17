//! Coordination patterns as skills, and the team receipt contract (OF-540,
//! ARCH-0079).
//!
//! Inside a project the CEO picks how its agents work together. A pattern
//! (CEO decides, committee, vote, market, optional rotation) is a workflow
//! skill, scored and revised like any skill; converge versus diverge is a
//! separate setting. Every team run leaves one [`TeamReceipt`]; the payoff
//! table and the planner card are views over those receipts and the pattern
//! skills' `learning.reliability`. The host binds each start and measures
//! the members itself; the owner's verdict on a bound deliverable settles the
//! team. The market pattern keeps a central ledger with a referee signed
//! before the work. Patterns are compared at equal budget, in Phase 2;
//! nothing here adds a runtime task kind.

pub mod market;
pub mod observations;
pub mod owner_outcome;
pub mod pattern;
pub mod payoff;
pub mod receipt;
pub mod run;
pub mod run_binding;
pub mod stack;

pub use market::{
    LedgerEntry, LedgerKind, Market, MarketMode, MarketResult, Participant, RefereeKind,
    SignedReferee, Submission, close_market, halving_round, market, open_market, peek_island,
    referee_scores, spend_share, submit,
};
pub use observations::{TeamRunObservations, team_run_observations};
pub(crate) use owner_outcome::settle_team_owner_verdict_in_txn;
pub use owner_outcome::{
    DeliverableReview, TeamDeliverableBinding, bind_team_deliverable, bind_team_deliverable_in_txn,
};
pub use pattern::{
    PAYOFF_AXIS, PatternSkill, TeamAxis, TeamPattern, model_mix, pattern_cell, pattern_skill,
    pattern_skills, register_pattern_skill,
};
pub use payoff::{PatternCardEntry, PayoffRow, PlannerCard, payoff_table, planner_card};
pub use receipt::{
    Coverage, DecidedBy, PatternSkillRef, TeamOutcome, TeamReceipt, TeamShape, record_team_receipt,
    settle_team_outcome, team_receipt, team_receipts,
};
pub use run::{
    SelfTeamCall, TeamCoverageInput, TeamDecisionInput, TeamMemberAnswer, TeamMemberInput,
    TeamRecordInput, TeamRunAnswer, TeamStartInput,
};
pub use run_binding::{
    TeamRunBinding, record_team_start, record_team_start_in_txn, team_run_binding,
    team_run_binding_in_txn, team_spawn_context_for_attempt, team_spawn_context_for_attempt_in_txn,
};
pub use stack::{BranchResult, NodeComparison, compare_at_equal_budget};
