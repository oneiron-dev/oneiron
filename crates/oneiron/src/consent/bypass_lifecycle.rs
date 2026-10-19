//! Typed owner doors for the scoped catastrophe bypass (DEC-0006 #bypass-grant).
//! A class list creates one existing consent row per class, atomically. The
//! warning is an explicit acknowledgement, not a credential or an effect verdict.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, GateError};
use crate::memory::{MemoryError, MemoryResult};

use super::codec::GRANTS;
use super::lifecycle::{ConsentActReceipt, parse_digest};
use super::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, BoundEnvelope, BypassGrantWarning,
    BypassScope, CONSENT_CONTENT_KIND, CONSENT_REASON_BYPASSED, CatastropheClass, EffectDigest,
    GrantBound,
};

/// The actor and catastrophe classes, inside exactly one project or thread.
/// The action envelope retains every engine restriction; scope does not erase it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassGrantBoundRequest {
    pub actor: String,
    #[serde(default)]
    pub actor_class: Option<String>,
    pub classes: Vec<CatastropheClass>,
    pub scope: BypassScope,
    pub envelope: BypassActionEnvelopeRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassActionEnvelopeRequest {
    pub selectors: Vec<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub budget: Option<u64>,
    #[serde(default)]
    pub receipt_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassGrantWarningRequest {
    pub bound: BypassGrantBoundRequest,
}

/// What the owner acknowledges: their identity, the complete bound, the
/// versioned floor and the exact engine-computed per-class bound digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassGrantWarningView {
    pub owner: String,
    pub bound: BypassGrantBoundRequest,
    pub floor_version: u16,
    pub bound_digests: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateBypassGrantRequest {
    /// Pass the warning returned by bypass_grant_warning unchanged.
    pub warning: BypassGrantWarningView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveBypassGrantsRequest {}

/// One live engine row. Revoking `grant` through vault.consent.revoke ends
/// it; a multi-class creation returns a separate reference for every class.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassActiveState {
    pub active: bool,
    pub grant: String,
    pub bound: BypassGrantBoundRequest,
    pub floor_version: u16,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassedEffectReceiptsRequest {
    /// The reference emitted by creation, active state or the registry.
    pub grant: String,
}

/// A projection of an existing Gate receipt, never a caller-authored effect.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassedEffectReceipt {
    pub decision_ref: String,
    pub grant_ref: String,
    pub effect_digest: String,
    pub reason_code: String,
    pub created_at: u64,
}

impl BypassGrantBoundRequest {
    fn grant_bounds(&self) -> MemoryResult<Vec<GrantBound>> {
        if self.classes.is_empty() {
            return Err(MemoryError::bad_request(
                "a bypass names at least one catastrophe class",
            ));
        }
        let mut actor = ActorBound::new(self.actor.clone())?;
        if let Some(class) = &self.actor_class {
            actor = actor.with_actor_class(class.clone())?;
        }
        let mut envelope = ActionEnvelope::new(self.envelope.selectors.clone())?;
        if let Some(target) = &self.envelope.target {
            envelope = envelope.with_target(target.clone())?;
        }
        if let Some(budget) = self.envelope.budget {
            envelope = envelope.with_budget(budget);
        }
        envelope = envelope.with_receipt_required(self.envelope.receipt_required);
        let mut bounds = Vec::new();
        for (index, class) in self.classes.iter().enumerate() {
            if self.classes[..index].contains(class) {
                return Err(MemoryError::bad_request(
                    "a bypass class may appear only once",
                ));
            }
            bounds.push(GrantBound::action(
                actor.clone(),
                ActionClass::new(class.as_str())?,
                envelope.clone(),
            )?);
        }
        Ok(bounds)
    }
}

fn prepare_warning(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    bound: BypassGrantBoundRequest,
) -> MemoryResult<(BypassGrantWarningView, Vec<BypassGrantWarning>)> {
    let bounds = bound.grant_bounds()?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let actor = owner.revalidate_in_txn(vault, &txn)?;
    let warnings = bounds
        .into_iter()
        .map(|grant| vault.check_bypass_request_in_txn(&txn, owner, grant, bound.scope))
        .collect::<crate::Result<Vec<_>>>()?;
    let view = BypassGrantWarningView {
        owner: actor.to_hex(),
        bound,
        floor_version: warnings[0].floor_version(),
        bound_digests: warnings
            .iter()
            .map(|warning| warning.bound().digest().to_hex())
            .collect(),
    };
    Ok((view, warnings))
}

pub fn bypass_grant_warning(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: BypassGrantWarningRequest,
) -> MemoryResult<BypassGrantWarningView> {
    Ok(prepare_warning(vault, owner, input.bound)?.0)
}

pub fn create_bypass_grant(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CreateBypassGrantRequest,
) -> MemoryResult<Vec<ConsentActReceipt>> {
    let (current, warnings) = prepare_warning(vault, owner, input.warning.bound.clone())?;
    if current != input.warning {
        return Err(MemoryError::bad_request(
            "acknowledge the current bypass warning unchanged",
        ));
    }
    Ok(vault
        .with_write_txn_grouped(|txn| {
            warnings
                .iter()
                .map(|warning| vault.create_bypass_grant_in_txn(txn, owner, warning))
                .collect::<crate::Result<Vec<_>>>()
        })?
        .into_iter()
        .map(ConsentActReceipt::from)
        .collect())
}

pub fn active_bypass_grants(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: ActiveBypassGrantsRequest,
) -> MemoryResult<Vec<BypassActiveState>> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    vault
        .active_bypass_grants_in_txn(&txn)?
        .into_iter()
        .map(|(active, bound)| {
            let actor = bound
                .actor()
                .ok_or(Error::CorruptedIndex("consent bypass grant subject"))?;
            let BoundEnvelope::Action(envelope) = bound.envelope() else {
                return Err(Error::CorruptedIndex("consent bypass grant envelope").into());
            };
            Ok(BypassActiveState {
                active: true,
                grant: active.grant_ref,
                bound: BypassGrantBoundRequest {
                    actor: actor.actor_ref().to_owned(),
                    actor_class: actor.actor_class().map(str::to_owned),
                    classes: vec![active.allows],
                    scope: active.scope,
                    envelope: BypassActionEnvelopeRequest {
                        selectors: envelope.selectors().to_vec(),
                        target: envelope.target().map(str::to_owned),
                        budget: envelope.budget(),
                        receipt_required: envelope.receipt_required(),
                    },
                },
                floor_version: active.floor_version,
                created_at: active.created_at,
            })
        })
        .collect()
}

pub fn bypassed_effect_receipts(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: BypassedEffectReceiptsRequest,
) -> MemoryResult<Vec<BypassedEffectReceipt>> {
    let grant = parse_digest(&input.grant, "grant")?.to_hex();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    if !GRANTS
        .get(&vault.store, &txn, &grant)?
        .is_some_and(|row| row.bypass.is_some())
    {
        return Err(Error::Gate(GateError::ConsentGrantNotFound).into());
    }
    drop(txn);
    vault
        .store
        .gate_decisions_for_grant_ref(&grant)?
        .into_iter()
        .filter(|record| {
            record.content_kind == CONSENT_CONTENT_KIND
                && record
                    .reason_codes
                    .iter()
                    .any(|reason| reason == CONSENT_REASON_BYPASSED)
        })
        .map(|record| {
            let digest = record
                .diff_handle
                .as_slice()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("consent bypass effect digest"))?;
            Ok(BypassedEffectReceipt {
                decision_ref: record.decision_id.to_hex(),
                grant_ref: grant.clone(),
                effect_digest: EffectDigest::from_bytes(digest).to_hex(),
                reason_code: CONSENT_REASON_BYPASSED.to_owned(),
                created_at: record.created_at,
            })
        })
        .collect()
}
