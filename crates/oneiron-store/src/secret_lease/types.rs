//! Lease/registration/receipt row types, VaultInstant clock, key prefixes.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::secret_record::types::CustodyTier;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

// ---------------------------------------------------------------------------
// Lease status & rows
// ---------------------------------------------------------------------------

pub use oneiron_contracts::secret_lease::SecretLeaseStatus;

/// A taint reference for SECRET-04 (ONE-1922): declared here (layer 2)
/// because door/lease returns carry it; SECRET-04 consumes and invalidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretTaintRef {
    /// The secret name.
    pub secret_ref: String,
    /// The record's rotation generation the value was read at.
    pub generation: u32,
}
