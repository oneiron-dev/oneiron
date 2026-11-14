//! Moved from `crates/oneiron/src/connector_key/record/budgets.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// A call's declared price (FIX 8689): what one call of a verb costs, in a
/// Spend row's denomination (an ISO-4217 code in minor units, or a provider
/// unit as an opaque integer). It is read only where `unit` is the row's own
/// unit; nothing converts between units.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSpendEstimate {
    pub unit: String,
    pub minor_units: u64,
}
