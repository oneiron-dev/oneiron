//! Doors for `tests/archive_judge.rs`: how many output-archive producer
//! records the engine holds, so a test sees that a refused judgment
//! recorded nothing.

use crate::{Result, Vault};

/// How many placement, score and axes producer records `vault` holds.
///
/// # Errors
///
/// Storage errors.
pub fn archive_producer_records(vault: &Vault) -> Result<usize> {
    crate::autoreason_campaign::archive::producer_record_count(vault)
}
