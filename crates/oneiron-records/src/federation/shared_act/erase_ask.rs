//! Moved from `crates/oneiron/src/federation/shared_act/erase_ask.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Where an ask stands. Only an Owner closes one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EraseAskStatus {
    Open,
    /// The Owner `by` erased the record; `act` names the `erase` act it
    /// started where the veto window applied.
    Erased {
        by: String,
        act: Option<String>,
    },
    Declined {
        by: String,
    },
}
