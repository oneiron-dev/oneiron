//! Typed facade calls over the engine's peer-relative federation burst doors.
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult, MEMORY_CODE_INVALID_STATE};
use crate::sync::federation_burst::*;
use crate::Vault;

pub fn federation_burst_baseline_as_owner(
    vault: &Vault, owner: &AuthenticatedOwner, input: FederationBurstPeerRequest,
) -> MemoryResult<FederationBurstBaselineState> {
    Ok(vault.federation_burst_baseline(owner, &input.authorize(vault)?)?)
}

pub fn federation_burst_policy_as_owner(
    vault: &Vault, owner: &AuthenticatedOwner, input: FederationBurstPeerRequest,
) -> MemoryResult<FederationBurstPolicy> {
    Ok(vault.federation_burst_policy(owner, &input.authorize(vault)?)?)
}

pub fn set_federation_burst_policy_as_owner(
    vault: &Vault, owner: &AuthenticatedOwner, input: FederationBurstPolicySetRequest,
) -> MemoryResult<FederationBurstPolicy> {
    Ok(vault.set_federation_burst_policy(owner, &input.peer.authorize(vault)?, input.policy)?)
}

pub fn federation_burst_reviews_as_owner(
    vault: &Vault, owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<FederationBurstReviewBundle>> {
    Ok(vault.federation_burst_reviews_as_owner(owner)?)
}

pub fn release_federation_burst_review_as_owner(
    vault: &Vault, owner: &AuthenticatedOwner, input: FederationBurstReviewRequest,
) -> MemoryResult<FederationBurstReviewReceipt> {
    Ok(vault.release_federation_burst_review(owner, &input.bundle_ref)?)
}

pub fn reject_federation_burst_review_as_owner(
    vault: &Vault, owner: &AuthenticatedOwner, input: FederationBurstReviewRequest,
) -> MemoryResult<FederationBurstReviewReceipt> {
    Ok(vault.reject_federation_burst_review(owner, &input.bundle_ref)?)
}

/// Embedded handles have no peer-host signer or served window manager.
pub fn federation_burst_host_only<T, I>(
    memory: &Memory<'_>, verb: &str, _input: &I,
) -> MemoryResult<T> {
    let _owner = memory.embedded_owner(verb)?;
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} requires the serving host's signed Connect ingress and window manager"),
        &[super::sdk_host::SERVED_CLIENT_HINT],
    ))
}
