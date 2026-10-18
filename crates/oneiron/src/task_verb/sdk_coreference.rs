//! Typed cross-vault identity links. Identity never pools claims or grants reads.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::federation::CoreferenceStatus;
use crate::memory::{MemoryError, MemoryResult};
use crate::temporal::TimeRange;
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

/// `vault.federation.coreference.link`: atomically write the link and its status.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreferenceLinkRequest {
    pub local_person: EntityId,
    pub other_person: EntityId,
    pub status: CoreferenceStatus,
}

/// The link whose owner confirms or removes it. Endpoint order is immaterial.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreferencePairRequest {
    pub local_person: EntityId,
    pub other_person: EntityId,
}

/// A link/status receipt, not a read grant or permission to export the link.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreferenceLinkReceipt {
    pub local_person: EntityId,
    pub other_person: EntityId,
    pub status: CoreferenceStatus,
    pub status_claim: EntityId,
}

/// Consent to export an existing link into exactly one pact, not every pact.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreferenceShareConsentRequest {
    pub local_person: EntityId,
    pub other_person: EntityId,
    /// One pact id, as 64 lowercase hex characters.
    pub pact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreferenceShareConsentReceipt {
    pub local_person: EntityId,
    pub other_person: EntityId,
    pub pact: String,
    pub consent_claim: EntityId,
}

/// Only link metadata is retracted. Neither person's original claims change.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreferenceUnlinkReceipt {
    pub local_person: EntityId,
    pub other_person: EntityId,
    pub unlinked: bool,
    pub retracted_claims: Vec<EntityId>,
    pub original_claims_retained: bool,
}

impl CoreferenceShareConsentRequest {
    /// The exact pact this consent names; no wildcard or list is accepted.
    pub fn pact_id(&self) -> MemoryResult<[u8; 32]> {
        if self
            .pact
            .bytes()
            .any(|c| !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c))
        {
            return Err(MemoryError::bad_request(
                "pact must be 64 lowercase hex characters",
            ));
        }
        super::brief::decode_hex(&self.pact)
            .ok_or_else(|| MemoryError::bad_request("pact must be 64 lowercase hex characters"))
    }
}

/// The caller's own owner proof supplies the actor; requests never name one.
fn owner_actor(vault: &Vault, owner: &AuthenticatedOwner) -> MemoryResult<WriteActor> {
    Ok(WriteActor::new(
        owner.revalidate(vault)?,
        EdgeActorClass::Human,
    ))
}

/// The engine's owning atomic link/status write, under the caller's owner proof.
pub fn link_coreference_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CoreferenceLinkRequest,
) -> MemoryResult<CoreferenceLinkReceipt> {
    let actor = owner_actor(vault, owner)?;
    let now = vault.now_recorded_at();
    let status_claim = crate::federation::put_coreference_link(
        vault,
        &actor,
        input.local_person,
        input.other_person,
        input.status,
        TimeRange {
            start: now,
            end: u64::MAX,
        },
        now,
    )?;
    Ok(CoreferenceLinkReceipt {
        local_person: input.local_person,
        other_person: input.other_person,
        status: input.status,
        status_claim,
    })
}

/// Confirm identity through the same atomic link/status write as a confirmed link.
pub fn confirm_coreference_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CoreferencePairRequest,
) -> MemoryResult<CoreferenceLinkReceipt> {
    link_coreference_as_owner(
        vault,
        owner,
        CoreferenceLinkRequest {
            local_person: input.local_person,
            other_person: input.other_person,
            status: CoreferenceStatus::Confirmed,
        },
    )
}

/// The engine's existing per-pact consent door; a link is still not a read grant.
pub fn share_coreference_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CoreferenceShareConsentRequest,
) -> MemoryResult<CoreferenceShareConsentReceipt> {
    let actor = owner_actor(vault, owner)?;
    let pact = input.pact_id()?;
    let now = vault.now_recorded_at();
    let consent_claim = crate::federation::coreference_share_consent(
        vault,
        &actor,
        input.local_person,
        input.other_person,
        &pact,
        TimeRange {
            start: now,
            end: u64::MAX,
        },
        now,
    )?;
    Ok(CoreferenceShareConsentReceipt {
        local_person: input.local_person,
        other_person: input.other_person,
        pact: input.pact,
        consent_claim,
    })
}

/// The owning engine unlink retracts metadata and removes both link orientations.
pub fn unlink_coreference_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CoreferencePairRequest,
) -> MemoryResult<CoreferenceUnlinkReceipt> {
    let retracted_claims = crate::federation::unlink_coreference_link(
        vault,
        owner,
        input.local_person,
        input.other_person,
    )?;
    Ok(CoreferenceUnlinkReceipt {
        local_person: input.local_person,
        other_person: input.other_person,
        unlinked: true,
        retracted_claims,
        original_claims_retained: true,
    })
}
