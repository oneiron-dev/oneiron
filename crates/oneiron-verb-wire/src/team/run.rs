//! Moved from `crates/oneiron/src/team/run.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::team::pattern::TeamAxis;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// `self.team.start`: a team run under `pattern`, its members spawned into it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamStartInput {
    /// The coordination pattern: `ceo_decides`, `committee`, `vote`,
    /// `market` or `rotation`. `solo` is no team, and is refused.
    pub pattern: String,
    /// The start's own key, 1..=64 bytes: the same key opens the same team.
    pub intent_key: String,
    /// The members, at least one, each spawned into the team as a child of
    /// the run. No count caps them (ARCH-0079); spend caps bound the work.
    pub members: Vec<TeamMemberInput>,
    /// An autoreason tournament's run id: the id, as hex, of the campaign
    /// experiment the tournament runs as, which the leader must be or work
    /// under. Set, the members are its authors, in its market; the pattern
    /// must be `market`.
    pub tournament: Option<String>,
    /// A `market` start's referee and ledger terms, recorded before any
    /// member spawns (ARCH-0079 #market). Required on a market start that is
    /// not a tournament's, and refused on any other start.
    #[serde(default)]
    pub market: Option<TeamMarketInput>,
}

/// A market start's terms. The host records them with the leader as the
/// referee's setter and the vault's time, before any member spawns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamMarketInput {
    /// The scoring rule that decides the market, set before the work.
    pub referee: TeamRefereeInput,
    /// How the market runs.
    pub mode: TeamMarketModeInput,
    /// The run's lease entering the market, in units.
    pub pool: u64,
    /// The share of the pool held back as the bounty, in [0, 1). Absent,
    /// one fifth.
    #[serde(default)]
    pub bounty_share: Option<f64>,
    /// Members, by their `intentKey`, that a halving round keeps first as
    /// its wildcard (protected exploration).
    #[serde(default)]
    pub protected: Vec<String>,
}

/// The referee a market start records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamRefereeInput {
    pub kind: TeamRefereeKindInput,
    /// The suite, holdout or judge revision the rule names, 1..=256 bytes.
    pub rule: String,
    /// The rule's digest, 1..=256 bytes. Every score must carry it.
    pub digest: String,
}

/// What kind of rule referees a market.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TeamRefereeKindInput {
    TestSuite,
    Holdout,
    PinnedJudge,
}

/// How a market runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TeamMarketModeInput {
    /// One bounty to the first submission that passes the rule.
    Bounty,
    /// Each round keeps the top half, plus `wildcardSlots` kept for
    /// exploration (at least one).
    HalvingWildcard {
        #[serde(rename = "wildcardSlots")]
        wildcard_slots: u32,
    },
    /// Members work in `islands` and may pay `peekPrice` to read another
    /// island's submissions.
    Islands {
        islands: u32,
        #[serde(rename = "peekPrice")]
        peek_price: u64,
    },
}

/// One member a start spawns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamMemberInput {
    /// The member's AGENT_DEF id, hex.
    pub agent: String,
    /// The member's key within the team, 1..=64 bytes.
    pub intent_key: String,
    /// What the member is asked to do.
    pub briefing: Option<String>,
}

/// `self.team.record`: the receipt of a team this run started.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamRecordInput {
    /// The team's reference, as its start returned it.
    pub team_ref: String,
    /// Members the receipt covers beyond those the host saw its start spawn,
    /// such as an approved widening's: their attempt refs, hex. Each must
    /// carry the team's stamp. A start the host did not record needs them all.
    pub members: Vec<String>,
    /// Whether the team converged on one answer or diverged into many. A
    /// planned team's receipt takes the axis its pattern froze instead.
    pub axis: TeamAxis,
    /// Who decided the team's result. The pattern fixes its kind. A market's
    /// receipt names the referee its start recorded; the rule named here is
    /// not used for a market.
    pub decided_by: TeamDecisionInput,
    /// Role name to head count, summing to the leader plus its members.
    /// Absent, the leader leads and the rest are members.
    pub roles: Option<BTreeMap<String, u32>>,
    /// How much of the campaign's cell grid the outputs covered.
    pub coverage: Option<TeamCoverageInput>,
}

/// `self.team.vote`: the calling participant's own choice in its team.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamVoteInput {
    pub team_ref: String,
    pub choice: String,
}

/// Who decided. A leader or a chair is the calling agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TeamDecisionInput {
    Leader,
    Chair,
    Vote {
        tally: BTreeMap<String, u32>,
    },
    /// A rule signed before the work: a test suite, a holdout, a pinned judge.
    Referee {
        rule: String,
        #[serde(rename = "signedAt")]
        signed_at: u64,
    },
}

/// Cells filled of the grid's total.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamCoverageInput {
    pub cells_filled: u32,
    pub cells_total: u32,
}
