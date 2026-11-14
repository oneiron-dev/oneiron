//! Typed cross-vault identity links. Identity never pools claims or grants reads.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::federation::CoreferenceStatus;
use crate::memory::{MemoryError, MemoryResult};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

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
    /// Another asker's approved check-in for this exact consent, 32 hex: the
    /// owner applies it on their own proof, and the consent's writer spends
    /// it (ROLES-CHECKIN 2k8). Omitted: the owner's own consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreferenceShareConsentReceipt {
    pub local_person: EntityId,
    pub other_person: EntityId,
    pub pact: String,
    pub consent_claim: EntityId,
    /// The decision the consent ran on: the owner's own proof, naming the
    /// asker's approved check-in it applied (ROLES-CHECKIN 2k8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<crate::check_in::CheckInDecision>,
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
        crate::task_verb::decode_hex(&self.pact)
            .ok_or_else(|| MemoryError::bad_request("pact must be 64 lowercase hex characters"))
    }
}

/// The engine's owning atomic link/status write, under the caller's owner
/// proof: it supplies the actor (requests never name one) and is rechecked in
/// the writer (FIX 5950).
pub fn link_coreference_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CoreferenceLinkRequest,
) -> MemoryResult<CoreferenceLinkReceipt> {
    let now = vault.now_recorded_at();
    let status_claim = crate::federation::put_coreference_link_as_owner(
        vault,
        owner,
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
/// The consent widens what the pact's peer reads: the owner's own consent
/// goes on their own proof, never gated, and the answer records that
/// decision (`check_in`). With `check_in_ref` the owner applies another
/// asker's approved check-in for this exact consent, spent in the consent's
/// writer (ROLES-CHECKIN 2k8; Engine RULING P25-SHAPE Q1 = A).
///
/// # Errors
///
/// `BAD_REQUEST` for a malformed `check_in_ref` or pact; the consent's
/// refusals; a check-in that is not an approved ask for this consent.
pub fn share_coreference_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CoreferenceShareConsentRequest,
) -> MemoryResult<CoreferenceShareConsentReceipt> {
    let pact = input.pact_id()?;
    let applied = match super::shared::check_in_ref(input.check_in_ref.as_deref())? {
        Some(id) => Some(crate::check_in::AppliedCheckIn {
            id,
            verb: "vault.federation.coreference.share_consent",
            effect_digest: coreference_share_consent_effect_digest(&input)?,
        }),
        None => None,
    };
    let (consent_claim, decision) = crate::federation::coreference_share_consent_as_owner(
        vault,
        owner,
        input.local_person,
        input.other_person,
        &pact,
        vault.now_recorded_at(),
        applied.as_ref(),
    )?;
    Ok(CoreferenceShareConsentReceipt {
        local_person: input.local_person,
        other_person: input.other_person,
        pact: input.pact,
        consent_claim,
        check_in: Some(decision),
    })
}

/// The digest of the owner's share consent `request`: the effect an asker's
/// `vault.check_in.open` names for
/// `vault.federation.coreference.share_consent`, and the one the owner's
/// consent spends (2k8; P25-SHAPE Q1 = A). BLAKE3, key derived from
/// `oneiron check_in coreference share consent v1`, over the request's
/// MessagePack encoding with field names, without its `check_in_ref`: the
/// two people and the pact.
///
/// # Errors
///
/// The request does not encode.
pub fn coreference_share_consent_effect_digest(
    request: &CoreferenceShareConsentRequest,
) -> MemoryResult<[u8; 32]> {
    let consent = CoreferenceShareConsentRequest {
        check_in_ref: None,
        ..request.clone()
    };
    let encoded = rmp_serde::to_vec_named(&consent)
        .map_err(|_| crate::error::Error::InvariantViolation("coreference share consent encode"))?;
    let mut hasher =
        blake3::Hasher::new_derive_key("oneiron check_in coreference share consent v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

/// The owning engine unlink retracts metadata and removes both link orientations.
/// A link between two CLAIMs is a Dreamer's consolidated SameAs (FIX 8363, L13
/// 03:00) and goes through its own unlink; every other pair, as before.
pub fn unlink_coreference_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CoreferencePairRequest,
) -> MemoryResult<CoreferenceUnlinkReceipt> {
    let claim = crate::registry::ENTITY_TYPE_CLAIM;
    let consolidated = vault.get_entity_type(&input.local_person)? == Some(claim)
        && vault.get_entity_type(&input.other_person)? == Some(claim);
    let retracted_claims = if consolidated {
        crate::federation::unlink_consolidated_same_as(
            vault,
            owner,
            input.local_person,
            input.other_person,
        )?
    } else {
        crate::federation::unlink_coreference_link(
            vault,
            owner,
            input.local_person,
            input.other_person,
        )?
    };
    Ok(CoreferenceUnlinkReceipt {
        local_person: input.local_person,
        other_person: input.other_person,
        unlinked: true,
        retracted_claims,
        original_claims_retained: true,
    })
}
