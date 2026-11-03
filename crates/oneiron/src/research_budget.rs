//! Research-loop budget configuration, settlement, and refusal values.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Loop purpose, kept separate from ordinary interactive LLM budget rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RsiSpendPurpose {
    Experiment,
    Judge,
    HeldOut,
}

/// A share is advisory unless the owner pins its cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiBudgetShare {
    pub units: u64,
    pub pinned: bool,
}

/// Independent vault lines: loop spend is token-denominated, exploration is exposure-denominated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RsiBudgetConfig {
    pub limit: u64,
    pub exploration_exposure_limit: u64,
    pub shares: BTreeMap<String, RsiBudgetShare>,
}

/// One exact limiting line, raised by `units`. A top-up never lowers a line,
/// never touches receipts or spend, and never resumes held work by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "line")]
pub enum RsiTopUp {
    /// The token-denominated loop line's limit.
    Tokens { units: u64 },
    /// The exposure-denominated exploration line's limit.
    Exploration { units: u64 },
    /// One named share's allocation, soft or pinned.
    Share { share: String, units: u64 },
}

/// Token-denominated loop accounting, including reservations that survive reopen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiBudgetRead {
    pub limit: u64,
    pub spent: u64,
    pub reserved: u64,
    pub suspended: bool,
}

/// Exposure-denominated exploration accounting, independent of token spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiExplorationRead {
    pub exposure_limit: u64,
    pub spent_exposure: u64,
    pub reserved_exposure: u64,
    pub suspended: bool,
}

/// The stamped token-share overflow admitted from the unallocated token pool.
/// Units record reservation-time overdraft, even if it settles for less.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiOverdraftReceipt {
    pub share: String,
    pub units: u64,
}

/// The durable receipt of one reservation's terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RsiSettlement {
    Spent(u64),
    Exposure(u64),
    Refunded,
}

/// Fail-closed ledger refusals. Nothing is spent or reserved on a refusal.
#[derive(Debug, thiserror::Error)]
pub enum RsiBudgetError {
    #[error("RSI budget is not configured")]
    Unconfigured,
    #[error("RSI budget configuration is invalid or already set")]
    InvalidConfig,
    #[error("RSI reservation already exists")]
    DuplicateReservation,
    #[error("RSI spend requires an open reservation")]
    ReservationRequired,
    #[error("RSI settlement uses the wrong budget line")]
    WrongLine,
    #[error("RSI budget capacity exceeded")]
    Exhausted,
    #[error("RSI work is suspended")]
    Suspended,
    #[error(transparent)]
    Engine(#[from] crate::Error),
}
