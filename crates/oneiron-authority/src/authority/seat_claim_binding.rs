//! FIX 10624: the seat claim a seat-child slip carries, signed in its claims
//! beside `grant_ref` and `trusted_contact`.
//!
//! An official CLI a seat host runs for one claimed BYOA attempt gets a
//! holder-bound slip that names that claim: the attempt, the lease owner and
//! the lease generation. The slip stands only while that exact claim holds,
//! so a lost, expired or retried lease ends it at once. Its holder is a
//! per-claim Agent PERSON; the CLI proves possession with the existing holder
//! proof. No new transport, identity or crypto.

use oneiron_contracts::error::Result;
use serde::{Deserialize, Serialize};

use super::invalid_authority;

/// The longest lease owner a seat claim names.
pub const SEAT_CLAIM_LEASE_OWNER_MAX_BYTES: usize = 256;

/// The signed binding of one seat-child slip (FIX 10624): the claimed
/// attempt and the lease that claims it. The holder is the claims'
/// `holder_ref`; the vault and lifetime are the claims' own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatClaimSlipBinding {
    /// The claimed attempt's id bytes.
    pub attempt: [u8; 16],
    /// The lease owner that holds the claim.
    pub lease_owner: String,
    /// The lease generation the claim was taken at: a claim counts from 1.
    pub attempt_count: u32,
}

impl SeatClaimSlipBinding {
    /// The binding's own shape: a non-nil attempt, a bounded lease owner and
    /// a taken lease. The holder and the claim's kind checks are the mint's
    /// own validation ([`super::SlipClaims::validate`]).
    pub fn validate(&self) -> Result<()> {
        if self.attempt == [0; 16]
            || self.lease_owner.is_empty()
            || self.lease_owner.len() > SEAT_CLAIM_LEASE_OWNER_MAX_BYTES
            || self.attempt_count == 0
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}
