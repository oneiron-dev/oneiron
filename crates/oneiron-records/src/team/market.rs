//! Moved from `crates/oneiron/src/team/market.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What kind of rule referees the market.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefereeKind {
    TestSuite,
    Holdout,
    PinnedJudge,
}

/// The referee, signed before any work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReferee {
    pub kind: RefereeKind,
    /// The suite, holdout or judge revision it names.
    pub rule_ref: String,
    /// The digest of the rule as signed; every score must carry it.
    pub digest: String,
    pub signed_by: EntityId,
    pub signed_at: u64,
}

/// How the market runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MarketMode {
    /// M1: one bounty to the first submission that passes the signed rule.
    Bounty,
    /// M2: each round keeps the top half, plus `wildcard_slots` kept for
    /// exploration (at least one).
    HalvingWildcard { wildcard_slots: u32 },
    /// M3: agents work in islands and may pay `peek_price` to read another
    /// island's submissions.
    Islands { islands: u32, peek_price: u64 },
}

/// One agent's run-local lease share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub share: u64,
    pub spent: u64,
    pub earned: u64,
    pub island: Option<u32>,
    /// Still in the market; a halving round retires the rest.
    pub active: bool,
    /// Protected exploration: a halving round keeps it as a wildcard first.
    pub protected: bool,
}

/// What one ledger line records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerKind {
    /// The run's lease entering the market.
    Mint,
    /// A share granted to an agent.
    Grant,
    /// An agent spending from its share.
    Spend,
    /// An agent paying to peek at an island.
    PeekPaid { island: u32 },
    /// An island member earning from a peek.
    PeekEarned,
    /// A retired agent's unspent share returning to the bounty.
    Return,
    /// The bounty paid to the winner.
    Award,
    /// The CEO adopting `submission_ref` over the referee's winner; the
    /// award stays the referee's (ARCH-0079 #market: "A CEO who overrides
    /// the referee writes a logged entry with its own receipt").
    Override {
        submission_ref: String,
        by: EntityId,
    },
}

/// One central-ledger line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub seq: u64,
    pub at: u64,
    pub agent: Option<String>,
    pub entry: LedgerKind,
    pub units: u64,
}

/// One submission and, once refereed, its score and the signed rule's
/// pass verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Submission {
    pub agent: String,
    pub submission_ref: String,
    pub at: u64,
    pub score: Option<f64>,
    /// Whether the submission passed the signed rule; `None` until refereed.
    pub passed: Option<bool>,
    /// SHA-256 of the candidate its member submitted, lower hex: the
    /// referee's verdict must name it.
    #[serde(default)]
    pub candidate_sha256: Option<String>,
    /// The sealed referee run behind `score` and `passed`.
    #[serde(default)]
    pub evidence: Option<VerdictEvidence>,
    /// The latest development-cohort screen: never a score, never a pass.
    #[serde(default)]
    pub screen: Option<ScreenScore>,
    /// Why the latest verdict relayed for it did not count. A valid sealed
    /// verdict clears it.
    #[serde(default)]
    pub invalid: Option<InvalidVerdict>,
}

/// The referee's contract, pinned from its sealed NOTE before the work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RefereeContract {
    /// The sealed NOTE whose text is the contract.
    pub note: EntityId,
    /// SHA-256 of that text, lower hex: the referee's digest.
    pub sha256: String,
    /// What each candidate is paired against.
    pub comparator: ContractComparator,
    /// SHA-256 of the sealed prompt cohort: only the referee runs it.
    pub cohort_sha256: String,
    /// The development cohorts screens run on, disjoint from the sealed one.
    pub screens: Vec<String>,
    /// The harness revision: the code commit, 40 lower hex.
    pub harness_commit: String,
    /// The approved workload digest the referee runs (pass 33 `JOB_WORKLOAD`).
    pub harness_workload: String,
    /// The output of the referee's run that holds its verdict.
    pub verdict_output: String,
    pub bar: ContractBar,
}

/// The incumbent a candidate is paired against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractComparator {
    pub name: String,
    pub sha256: String,
}

/// The paired release bar (NOT-WORSE = A): a candidate passes when the low
/// end of its paired interval against the comparator stays above
/// `-margin`, on at least `min_tasks` tasks; fewer tasks are unknown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractBar {
    pub metric: String,
    pub margin: f64,
    pub min_tasks: u64,
}

/// The sealed referee run a score rests on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerdictEvidence {
    /// The unit claim, also its job's id.
    pub claim: EntityId,
    pub workload: String,
    /// SHA-256 of the verdict output, as the machine hashed it.
    pub output_sha256: String,
    pub tasks: u64,
    pub paired_low: f64,
    /// Fewer tasks than the bar needs: not a pass.
    pub unknown: bool,
    pub at: u64,
}

/// One screen on a development cohort.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScreenScore {
    pub score: f64,
    pub cohort_sha256: String,
    pub claim: EntityId,
    pub output_sha256: String,
    pub at: u64,
}

/// A relayed verdict whose evidence did not hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidVerdict {
    pub reason: String,
    /// The unit claim it named; none when no such claim exists.
    pub claim: Option<EntityId>,
    pub at: u64,
}

/// How a market closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketResult {
    pub winner: Option<String>,
    pub winning_submission: Option<String>,
    pub bounty: u64,
    pub closed_at: u64,
}
