//! Typed public consent lifecycle calls. The wire bounds carry no authority:
//! only the existing owner-authenticated consent doors mint grants; revoke is the owner's, or the
//! Grant's own grantee dropping that Grant.
use serde::{Deserialize, Serialize};

use crate::{EdgeActorClass, EntityId, Vault};
use oneiron_contracts::memory::{MemoryError, MemoryResult};

use super::support::normalized_ref;
use super::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, AuthenticatedOwner, ConsentReceipt,
    ConsentRegistry, ConsentRegistryQuery, DisclosureClass, DisclosureEnvelope, EffectDigest,
    GrantBound,
};
/// The owner's auto-weave Grant door (FIX 3433), at this public path for the
/// generated SDK and server callers; it lives with the gate's weave Grant.
pub use crate::gate::weave_grant::{
    AutoWeaveGrantRequest, AutoWeaveWriterClass, mint_auto_weave_grant,
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
    /// Another asker's approved check-in for this exact grant, 32 hex: the
    /// owner applies it on their own proof, and the mint's writer spends it
    /// (ROLES-CHECKIN 2k8). Omitted: the owner's own mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
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
    /// The Gate decision of the receipt. Absent only on a repeat revoke whose grant was revoked without a
    /// consent receipt (a graduation demotion, an office-edit erase or an owner-less pack update).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_ref: Option<String>,
    pub outcome: String,
    pub reason_code: String,
    pub grant_ref: Option<String>,
    /// The Gate receipt's exact effect/bound handle bytes.
    pub diff_handle: Vec<u8>,
    /// A revoke of a grant that was already revoked: nothing was written, and this is the original revoke
    /// receipt (a repeat revoke is idempotent). Absent on every other act.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub already_revoked: bool,
    /// What revoked the grant, when the receipt alone does not name it: on a repeat revoke with no
    /// consent receipt to return, the record that revoked the grant where that path writes one (a
    /// graduation demotion's receipt id). On the grantee path always the renouncing grantee's actor
    /// ref, even beside a receipt. Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    /// The check-in decision of the Owner's own act on a catastrophe row: a
    /// bypass grant's creation goes on the Owner's own proof and records it
    /// (2k4; P25-SHAPE Q1 = A; owner-own-acts). Absent on every other act.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<crate::check_in::CheckInDecision>,
}

impl From<ConsentReceipt> for ConsentActReceipt {
    fn from(receipt: ConsentReceipt) -> Self {
        Self {
            decision_ref: Some(receipt.decision_id().to_hex()),
            outcome: receipt.gate_outcome().to_owned(),
            reason_code: receipt.reason_code().to_owned(),
            grant_ref: crate::consent::consent_receipt_grant_ref(&receipt),
            diff_handle: crate::consent::consent_receipt_diff_handle(&receipt),
            already_revoked: false,
            revoked_by: None,
            check_in: None,
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

/// `vault.consent.create_standing_grant`: the owner's own mint widens
/// another's grant (ARCH-0082 #act-table "Widen another's grant"). It goes
/// on their own proof, never gated, and the receipt records that decision
/// (`check_in`). With `check_in_ref` the owner applies another asker's
/// approved check-in for this exact grant: the mint's writer spends it after
/// every check of the mint, so a refusal leaves it eligible and stands no
/// grant (ROLES-CHECKIN 2k8; Engine RULING P25-SHAPE Q1 = A).
///
/// # Errors
///
/// `BAD_REQUEST` for a malformed `check_in_ref`; the bound's and the mint's
/// refusals; a check-in that is not an approved ask for this grant.
pub fn create_standing_grant(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CreateStandingGrantRequest,
) -> MemoryResult<ConsentActReceipt> {
    let bound = input.bound.into_bound()?;
    let applied = crate::verbs::check_in_ref(input.check_in_ref.as_deref())?.map(|id| {
        crate::check_in::AppliedCheckIn {
            id,
            verb: "vault.consent.create_standing_grant",
            effect_digest: crate::check_in::standing_grant_effect_digest(&bound),
        }
    });
    Ok(vault.with_write_txn_grouped(|wtxn| {
        create_standing_grant_with_decision_in_txn(vault, wtxn, owner, bound, applied.as_ref())
    })?)
}

/// The owner's standing grant over `bound`, minted in `wtxn` on their own
/// proof, with the decision it ran on in its receipt: with `applied`,
/// another asker's approved check-in for it, spent after every check of the
/// mint (ROLES-CHECKIN 2k8; P25-SHAPE Q1 = A). Each owner door that mints a
/// standing grant mints it here.
pub(crate) fn create_standing_grant_with_decision_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    bound: GrantBound,
    applied: Option<&crate::check_in::AppliedCheckIn<'_>>,
) -> crate::Result<ConsentActReceipt> {
    let receipt = vault.create_standing_grant_in_txn(wtxn, owner, bound)?;
    let decision = crate::check_in::owner_act_decision_in_txn(
        vault,
        wtxn,
        crate::check_in::ActClass::GrantWiden,
        applied,
    )?;
    Ok(ConsentActReceipt {
        check_in: Some(decision),
        ..receipt.into()
    })
}

/// The digest of the owner's standing grant `request`: the effect an
/// asker's `vault.check_in.open` names for
/// `vault.consent.create_standing_grant`, and the one the owner's mint
/// spends (2k8; P25-SHAPE Q1 = A). It is
/// [`crate::check_in::standing_grant_effect_digest`] over the bound the
/// request normalizes to, the one the grant stores.
///
/// # Errors
///
/// A bound the mint would refuse as malformed.
pub fn create_standing_grant_effect_digest(
    request: &CreateStandingGrantRequest,
) -> MemoryResult<[u8; 32]> {
    let bound = request.bound.clone().into_bound()?;
    Ok(crate::check_in::standing_grant_effect_digest(&bound))
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
    let revocation = vault.consent_revocation(owner, &grant)?;
    Ok(match revocation.receipt {
        Some(receipt) => ConsentActReceipt {
            already_revoked: revocation.already_revoked,
            ..receipt.into()
        },
        // Revoked without a consent receipt: the act's revoke outcome and the row it names (a revoke
        // receipt's handle is its grant ref), with no Gate decision to name.
        None => ConsentActReceipt {
            decision_ref: None,
            outcome: "revoked".to_owned(),
            reason_code: crate::consent::CONSENT_REASON_REVOKED.to_owned(),
            diff_handle: grant.as_bytes().to_vec(),
            grant_ref: Some(grant),
            already_revoked: revocation.already_revoked,
            revoked_by: revocation.revoked_by,
            check_in: None,
        },
    })
}

/// A Grant's own grantee drops that Grant (P-GATE-010, DEC-0006): the caller is the Grant's bound
/// actor on that Grant only, never a 202 ask. The request names exactly one Grant. Unknown and
/// not-held Grants answer the same 403 a non-owner's owner-path call gets, so existence does not
/// leak. `revoked_by` always names the grantee; the owner path is unchanged.
pub fn revoke_as_grantee(
    vault: &Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
    input: RevokeGrantRequest,
) -> MemoryResult<ConsentActReceipt> {
    let grant = parse_digest(&input.grant, "grant")?.to_hex();
    let revocation = vault.consent_revocation_as_grantee(actor, actor_class, &grant)?;
    Ok(match revocation.receipt {
        Some(receipt) => ConsentActReceipt {
            already_revoked: revocation.already_revoked,
            revoked_by: revocation.revoked_by,
            ..receipt.into()
        },
        // Same fallback shape as the owner path; on this path `revoked_by` names the grantee.
        None => ConsentActReceipt {
            decision_ref: None,
            outcome: "revoked".to_owned(),
            reason_code: crate::consent::CONSENT_REASON_REVOKED.to_owned(),
            diff_handle: grant.as_bytes().to_vec(),
            grant_ref: Some(grant),
            already_revoked: revocation.already_revoked,
            revoked_by: revocation.revoked_by,
            check_in: None,
        },
    })
}

pub(super) fn parse_digest(value: &str, field: &str) -> MemoryResult<EffectDigest> {
    let refused = || MemoryError::bad_request(format!("{field} must be a 64-hex digest"));
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(refused());
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| refused())?;
    }
    Ok(EffectDigest::from_bytes(bytes))
}
