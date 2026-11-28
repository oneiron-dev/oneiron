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

/// A market's terms, on a start or a planned ask. The host records them
/// before any member spawns, with the vault's time and, as the referee's
/// setter, the start's leader or the planned ask's asker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamMarketInput {
    /// The scoring rule that decides the market, set before the work.
    pub referee: TeamRefereeInput,
    /// How the market runs.
    pub mode: TeamMarketModeInput,
    /// The run's lease entering the market, in `unit`.
    pub pool: u64,
    /// The unit the pool, every share and the peek price count in. Absent,
    /// GPU seconds, the market's only unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<TeamLeaseUnit>,
    /// The share of the pool held back as the bounty, in [0, 1). Absent,
    /// one fifth.
    #[serde(default)]
    pub bounty_share: Option<f64>,
    /// Members that a halving round keeps first as its wildcard (protected
    /// exploration): by their `intentKey` on a start, and as `member:<n>`,
    /// the n-th member in launch order from 0, on a planned ask.
    #[serde(default)]
    pub protected: Vec<String>,
}

/// The unit a market's lease counts in (FIX MARKET-SEAT-LEASE-UNIT): one
/// unit the engine meters the same on every harness, so seats on
/// subscriptions and seats the engine prices meet at equal lease (ARCH-0079
/// #market). A seat's own time is not metered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TeamLeaseUnit {
    /// GPU seconds: each verdict spends, from its submitting member's
    /// share, the seconds the referee run's machine-signed end charged.
    GpuSeconds,
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
    /// The referee's contract: a sealed NOTE, hex, whose text hashes to
    /// `digest` (SHA-256, lower hex) and pins the comparator, the sealed
    /// cohort, the screens' development cohorts, the harness and the bar
    /// (`oneiron.market_referee_contract.v1`). Only a market with one takes
    /// `self.team.market.verdict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
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
    /// A market's CEO override: the submission the team adopts in place of
    /// the referee's winner. It is logged on the ledger with its own
    /// receipt; the referee's result and award stand.
    #[serde(default, rename = "override", skip_serializing_if = "Option::is_none")]
    pub referee_override: Option<TeamOverrideInput>,
}

/// The submission a CEO adopts over the referee's winner, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamOverrideInput {
    pub submission_ref: String,
    /// 1..=2048 bytes.
    pub reason: String,
}

/// `self.team.market.submit`: the calling member's candidate, for its
/// market's referee. The member is named by the host, never here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamMarketSubmitInput {
    pub team_ref: String,
    /// The submission's name in the market, 1..=256 bytes.
    pub submission_ref: String,
    /// SHA-256 of the candidate, lower hex. The referee's verdict must name
    /// it, and no other submission of the market may.
    pub candidate_sha256: String,
}

/// `self.team.market.verdict`: one referee run's output for one
/// submission, checked against the run's machine-signed end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamMarketVerdictInput {
    pub team_ref: String,
    pub submission_ref: String,
    /// The arm unit the referee ran as.
    pub claim: TeamMarketClaimInput,
    /// The bytes of the referee's verdict output, UTF-8 JSON
    /// (`oneiron.market_referee_verdict.v1`).
    pub verdict: String,
}

/// An arm unit claim, by its logical attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamMarketClaimInput {
    /// The arm's id, hex.
    pub arm: String,
    pub rung: u8,
    pub unit_key: String,
    pub attempt: u16,
}

/// What a relayed verdict did to its submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TeamMarketVerdictOutcome {
    /// The sealed referee scored it. `unknown`: fewer tasks than the bar
    /// needs, which is not a pass.
    Scored {
        score: f64,
        passed: bool,
        unknown: bool,
        /// The seat behind the scored candidate, as its submission froze
        /// it; none when unknown.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seat: Option<TeamMarketSeat>,
    },
    /// A development-cohort screen: never a score or a pass.
    Screened { score: f64 },
    /// The evidence did not hold: no score, never a loss.
    Invalid { reason: String },
}

/// What a verdict spent from its submitting member's share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamMarketSpend {
    pub unit: TeamLeaseUnit,
    /// What the referee run's machine-signed end charged.
    pub charged: u64,
    /// What the member's share has left after it.
    pub left: u64,
}

/// The seat behind a submission: the harness its member ran in and the
/// model behind it, frozen when the member submitted (FIX
/// MARKET-SEAT-MODEL-STAMP). It names no credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeamMarketSeat {
    pub harness: String,
    pub model: String,
    pub source: TeamMarketSeatSource,
}

/// Who named a submission's seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TeamMarketSeatSource {
    /// The owner, on the pairing link of the credential that submitted: the
    /// engine records that declaration and never observes the model.
    OwnerPaired,
    /// The engine's own seat receipt for the member's run.
    HostSeat,
}

/// A market team's result: the referee's, and the CEO's override beside it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamMarketOutcome {
    /// The referee's winner, by member key; none when nothing won.
    pub winner: Option<String>,
    pub winning_submission: Option<String>,
    /// The bounty the referee's winner was paid, in lease units.
    pub bounty: u64,
    pub closed_at: u64,
    #[serde(rename = "override")]
    pub referee_override: Option<TeamOverrideView>,
    /// Every submission with its seat beside its score, in submission
    /// order, so a comparison groups results per model (ARCH-0079).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub submissions: Vec<TeamMarketSubmissionView>,
    /// The unit the pool and every share count in; none for a market opened
    /// before the unit was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<TeamLeaseUnit>,
    /// Each member's share, what it spent and what it has left, in member
    /// key order, so a comparison reads each seat's lease beside its score.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lease: Vec<TeamMarketLeaseView>,
}

/// One member's lease in a closed market, in the market's unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamMarketLeaseView {
    /// The member key.
    pub participant: String,
    pub share: u64,
    pub spent: u64,
    /// Peek income and the bounty, if it won.
    pub earned: u64,
    pub left: u64,
}

/// One submission of a closed market, as the team's result shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamMarketSubmissionView {
    pub submission_ref: String,
    /// The member key it was submitted under.
    pub participant: String,
    /// None: unknown (a credential paired without a seat, or a run the
    /// engine did not seat).
    pub seat: Option<TeamMarketSeat>,
    pub score: Option<f64>,
    pub passed: Option<bool>,
    /// Its sealed run had fewer tasks than the bar needs.
    pub unknown: bool,
}

/// A CEO override, as its receipt records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamOverrideView {
    /// The submission the team adopts.
    pub chosen: String,
    pub reason: String,
    /// The CEO's AGENT_DEF, hex.
    pub by: String,
    pub at: u64,
    /// The ledger line that logs it.
    pub ledger_seq: u64,
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
