//! Coordination patterns as skills, and the team receipt contract (OF-540,
//! ARCH-0079).
//!
//! Inside a project the CEO picks how its agents work together. A pattern
//! (CEO decides, committee, vote, market, optional rotation) is a workflow
//! skill, scored and revised like any skill; converge versus diverge is a
//! separate setting. Every team run leaves one [`TeamReceipt`]; the payoff
//! table and the planner card are views over those receipts and the pattern
//! skills' `learning.reliability`. The market pattern keeps a central ledger
//! with a referee signed before the work. Patterns are compared at equal
//! budget, in Phase 2; nothing here adds a runtime task kind.

pub mod market;
pub mod pattern;
pub mod payoff;
pub mod receipt;
pub mod run;
pub mod stack;

pub use market::{
    LedgerEntry, LedgerKind, Market, MarketMode, MarketResult, Participant, RefereeKind,
    SignedReferee, Submission, close_market, halving_round, market, open_market, peek_island,
    referee_scores, spend_share, submit,
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
pub use stack::{BranchResult, NodeComparison, compare_at_equal_budget};
