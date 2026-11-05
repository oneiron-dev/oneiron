//! Lease-owner validation for queued-work storage ports.

use oneiron_base::error::{ArtifactError, Error, Result};

const MAX_LEASE_OWNER_LEN: usize = 128;

const ERR_LEASE_OWNER_EMPTY: &str = "lease owner must not be empty";

const ERR_LEASE_OWNER_TOO_LONG: &str = "lease owner exceeds 128 bytes";

pub fn validate_lease_owner(lease_owner: &str) -> Result<()> {
    if lease_owner.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_LEASE_OWNER_EMPTY,
        )));
    }
    if lease_owner.len() > MAX_LEASE_OWNER_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_LEASE_OWNER_TOO_LONG,
        )));
    }
    Ok(())
}
