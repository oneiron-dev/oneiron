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
}

/// How a market closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketResult {
    pub winner: Option<String>,
    pub winning_submission: Option<String>,
    pub bounty: u64,
    pub closed_at: u64,
}
