//! Original host allocation delivery, shared by startup and authenticated ctl.
//! This is a host's input, not proof of a debit, settlement or backing release.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationReference {
    pub id: String,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationRate {
    pub unit: String,
    pub per: u64,
    pub cost: u64,
}

/// One immutable original descriptor. Rate order and the opaque usage producer
/// owner survive delivery unchanged. Neither is derived from a current balance,
/// account, vault name or hosting mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationDelivery {
    pub vault_id: String,
    pub usage_owner: String,
    pub allocation: AllocationReference,
    pub units: u64,
    pub unit: String,
    pub rates: Vec<AllocationRate>,
    pub issued_at: u64,
}
