//! Typed owner doors for the scoped catastrophe bypass (DEC-0006 #bypass-grant).
//! A class list creates one existing consent row per class, atomically. The
//! warning is an explicit acknowledgement, not a credential or an effect verdict.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, GateError};
use oneiron_contracts::memory::{MemoryError, MemoryResult};

use super::codec::GRANTS;
use super::lifecycle::{ConsentActReceipt, parse_digest};
use super::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, BoundEnvelope, BypassGrantWarning,
    BypassScope, CONSENT_CONTENT_KIND, CONSENT_REASON_BYPASSED, CatastropheClass, EffectDigest,
    GrantBound,
};

#[doc(hidden)]
pub use oneiron_verb_wire::consent::bypass_lifecycle::{
    ActiveBypassGrantsRequest, BypassActionEnvelopeRequest, BypassActiveState,
    BypassGrantBoundRequest, BypassGrantWarningRequest, BypassGrantWarningView,
    BypassedEffectReceipt, BypassedEffectReceiptsRequest, CreateBypassGrantRequest,
};

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
