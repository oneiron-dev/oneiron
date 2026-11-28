//! Moved from `crates/oneiron/src/team/run.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::team::pattern::TeamPattern;
pub use oneiron_verb_wire::team::run::TeamCoverageInput;
pub use oneiron_verb_wire::team::run::TeamDecisionInput;
pub use oneiron_verb_wire::team::run::TeamMarketOutcome;
pub use oneiron_verb_wire::team::run::TeamMarketSeat;
pub use oneiron_verb_wire::team::run::TeamMarketSeatSource;
pub use oneiron_verb_wire::team::run::TeamMarketSubmissionView;
pub use oneiron_verb_wire::team::run::TeamMarketSubmitInput;
pub use oneiron_verb_wire::team::run::TeamMarketVerdictInput;
pub use oneiron_verb_wire::team::run::TeamMarketVerdictOutcome;
pub use oneiron_verb_wire::team::run::TeamMemberInput;
pub use oneiron_verb_wire::team::run::TeamRecordInput;
pub use oneiron_verb_wire::team::run::TeamStartInput;
pub use oneiron_verb_wire::team::run::TeamVoteInput;
use serde::Deserialize;
use serde::Serialize;

/// One `self.team.*` call. The leader comes from the host binding, never
/// from the guest.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum SelfTeamCall {
    Start(TeamStartInput),
    Record(TeamRecordInput),
    Vote(TeamVoteInput),
    MarketSubmit(TeamMarketSubmitInput),
    MarketVerdict(TeamMarketVerdictInput),
}

/// What a `self.team.*` call answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum TeamRunAnswer {
    #[serde(rename_all = "camelCase")]
    Started {
        team_ref: String,
        pattern: TeamPattern,
        members: Vec<TeamMemberAnswer>,
    },
    /// A start whose every member asked a widening: none launched, so no
    /// team runs yet. Each member answers its proposal.
    #[serde(rename_all = "camelCase")]
    ProposedWiden {
        team_ref: String,
        pattern: TeamPattern,
        members: Vec<TeamMemberAnswer>,
    },
    /// The bound participant's own choice, not a team result or tally.
    #[serde(rename_all = "camelCase")]
    Voted { team_ref: String, choice: String },
    #[serde(rename_all = "camelCase")]
    Recorded {
        team_ref: String,
        pattern: TeamPattern,
        width: u32,
        /// The team ran with fewer agents than its pattern needs to mean
        /// anything; the receipt records what ran.
        below_floor: bool,
        models: Vec<String>,
        /// The loaded pattern skill the receipt names, hex.
        pattern_skill: Option<String>,
        /// Whether the receipt was already written.
        replay: bool,
        /// A market team's result: the referee's, with any CEO override
        /// beside it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        market: Option<TeamMarketOutcome>,
    },
    /// The calling member's submission, under the member key the host
    /// queued it as.
    #[serde(rename_all = "camelCase")]
    MarketSubmitted {
        team_ref: String,
        submission_ref: String,
        participant: String,
        at: u64,
        /// The seat behind the candidate, frozen at its first accepted
        /// submit; none when unknown.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seat: Option<TeamMarketSeat>,
        /// Whether the same submission was already recorded.
        replay: bool,
    },
    /// What a relayed referee verdict did to its submission.
    #[serde(rename_all = "camelCase")]
    MarketVerdict {
        team_ref: String,
        submission_ref: String,
        outcome: TeamMarketVerdictOutcome,
        /// Whether the same verdict was already recorded.
        replay: bool,
    },
}

/// One spawned member: its queued attempt, or the widening its spawn asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemberAnswer {
    pub agent: String,
    pub attempt_ref: Option<String>,
    pub proposal_ref: Option<String>,
}
