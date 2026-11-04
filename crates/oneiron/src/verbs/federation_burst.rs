//! Typed facade calls over the engine's peer-relative federation burst doors.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::sync::federation_burst::*;

pub fn federation_burst_baseline_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FederationBurstPeerRequest,
) -> MemoryResult<FederationBurstBaselineState> {
    Ok(vault.federation_burst_baseline(owner, &input.authorize(vault)?)?)
}

pub fn federation_burst_policy_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FederationBurstPeerRequest,
) -> MemoryResult<FederationBurstPolicy> {
    Ok(vault.federation_burst_policy(owner, &input.authorize(vault)?)?)
}

pub fn set_federation_burst_policy_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FederationBurstPolicySetRequest,
) -> MemoryResult<FederationBurstPolicy> {
    Ok(vault.set_federation_burst_policy(owner, &input.peer.authorize(vault)?, input.policy)?)
}

pub fn federation_burst_reviews_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<FederationBurstReviewBundle>> {
    Ok(vault.federation_burst_reviews_as_owner(owner)?)
}

pub fn release_federation_burst_review_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FederationBurstReviewRequest,
) -> MemoryResult<FederationBurstReviewReceipt> {
    Ok(vault.release_federation_burst_review(owner, &input.bundle_ref)?)
}

pub fn reject_federation_burst_review_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FederationBurstReviewRequest,
) -> MemoryResult<FederationBurstReviewReceipt> {
    Ok(vault.reject_federation_burst_review(owner, &input.bundle_ref)?)
}

/// Embedded handles have no peer-host signer or served window manager.
pub fn federation_burst_host_only<T, I>(
    memory: &Memory<'_>,
    verb: &str,
    _input: &I,
) -> MemoryResult<T> {
    let _owner = memory.embedded_owner(verb)?;
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} requires the serving host's signed Connect ingress and window manager"),
        &[super::host::SERVED_CLIENT_HINT],
    ))
}

/// `vault.sync.retained_work.wait.set`'s input: one retained-work queue and
/// its new wait. `None` (or an absent `secs`) resets that queue to its
/// existing default; no cap or default is invented here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetainedWorkWaitSetRequest {
    pub queue: RetainedWorkQueue,
    #[serde(default)]
    pub secs: Option<u64>,
}

/// `vault.sync.retained_work.wait.set`: the owner sets one retained-work
/// queue's wait in seconds, or resets it to its existing default, and
/// receives the effective wait. The engine writer owns the side-table row;
/// this door only exposes that act through the typed owner surface.
pub fn set_retained_work_wait_secs_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RetainedWorkWaitSetRequest,
) -> MemoryResult<u64> {
    Ok(vault.set_retained_work_wait_secs(owner, input.queue, input.secs)?)
}
