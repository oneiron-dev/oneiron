//! Typed public consent lifecycle calls. The wire bounds carry no authority:
//! only the existing owner-authenticated consent doors mint or revoke grants.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::memory::{MemoryError, MemoryResult};

use super::support::normalized_ref;
use super::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, AuthenticatedOwner,
    ConsentReceipt, ConsentRegistry, ConsentRegistryQuery, DisclosureClass,
    DisclosureEnvelope, EffectDigest, GrantBound,
};

/// Approve the exact engine-emitted effect digest, never a caller's description.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveOnceRequest {
    pub effect_digest: String,
}

/// Deny the exact effect the engine emitted, with the same digest grammar as approval.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DenyConsentRequest {
    pub effect_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateStandingGrantRequest {
    pub bound: StandingGrantBound,
}

/// Action and disclosure bounds are disjoint, including on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum StandingGrantBound {
    Action(ActionBoundRequest),
    Disclosure(DisclosureBoundRequest),
}

/// Actor (a lineage for stop-asking), action class and bounded envelope.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionBoundRequest {
    pub actor: String,
    pub class: String,
    pub envelope: ActionEnvelopeRequest,
}

/// Project and audience selectors, pinned to that project, with a per-use cap.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionEnvelopeRequest {
    pub project: String,
    pub audience: Vec<String>,
    /// A reviewed batch's count; absent for a standing no-press grant.
    /// Zero leaves every send needing the person's press.
    #[serde(default)]
    pub budget: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureBoundRequest {
    pub audience: Vec<String>,
    pub class: String,
    pub envelope: DisclosureEnvelopeRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureEnvelopeRequest {
    pub selectors: Vec<String>,
}

impl StandingGrantBound {
    fn into_bound(self) -> crate::Result<GrantBound> {
        match self {
            Self::Action(bound) => {
                let project = normalized_ref("project", bound.envelope.project)?;
                let mut selectors = vec![format!("project:{project}")];
                for member in bound.envelope.audience {
                    let member = normalized_ref("action audience member", member)?;
                    selectors.push(format!("audience:{member}"));
                }
                let mut envelope = ActionEnvelope::new(selectors)?.with_target(project)?;
                if let Some(budget) = bound.envelope.budget {
                    envelope = envelope.with_budget(budget);
                }
                GrantBound::action(
                    ActorBound::new(bound.actor)?,
                    ActionClass::new(bound.class)?,
                    envelope,
                )
            }
            Self::Disclosure(bound) => GrantBound::disclosure(
                AudienceBound::new(bound.audience)?,
                DisclosureClass::new(bound.class)?,
                DisclosureEnvelope::new(bound.envelope.selectors)?,
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeGrantRequest {
    /// The standing grant's bound digest, as emitted by its receipt or registry.
    pub grant: String,
}

/// The existing Gate receipt, not a second settlement ledger.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentActReceipt {
    pub decision_ref: String,
    pub outcome: String,
    pub reason_code: String,
    pub grant_ref: Option<String>,
    /// The Gate receipt's exact effect/bound handle bytes.
    pub diff_handle: Vec<u8>,
}

impl From<ConsentReceipt> for ConsentActReceipt {
    fn from(receipt: ConsentReceipt) -> Self {
        Self {
            decision_ref: receipt.decision_id().to_hex(),
            outcome: receipt.gate_outcome().to_owned(),
            reason_code: receipt.reason_code().to_owned(),
            grant_ref: receipt.grant_ref(),
            diff_handle: receipt.diff_handle(),
        }
    }
}

pub fn approve_once(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ApproveOnceRequest,
) -> MemoryResult<ConsentActReceipt> {
    let digest = parse_digest(&input.effect_digest, "effect_digest")?;
    Ok(vault.approve_once(owner, digest)?.into())
}

pub fn deny(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: DenyConsentRequest,
) -> MemoryResult<ConsentActReceipt> {
    let digest = parse_digest(&input.effect_digest, "effect_digest")?;
    Ok(vault.deny_consent(owner, digest)?.into())
}

pub fn create_standing_grant(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CreateStandingGrantRequest,
) -> MemoryResult<ConsentActReceipt> {
    Ok(vault.create_standing_grant(owner, input.bound.into_bound()?)?.into())
}

pub fn registry(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ConsentRegistryQuery,
) -> MemoryResult<ConsentRegistry> {
    vault.recheck_owner(owner)?;
    Ok(vault.consent_registry(input)?)
}

pub fn revoke(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RevokeGrantRequest,
) -> MemoryResult<ConsentActReceipt> {
    let grant = parse_digest(&input.grant, "grant")?.to_hex();
    Ok(vault.revoke_consent_grant(owner, &grant)?.into())
}

fn parse_digest(value: &str, field: &str) -> MemoryResult<EffectDigest> {
    let refused = || MemoryError::bad_request(format!("{field} must be a 64-hex digest"));
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(refused());
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| refused())?;
    }
    Ok(EffectDigest::from_bytes(bytes))
}
