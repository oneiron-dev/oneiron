//! Standing-grant resolution plus scoped-MCP channel check and grant touch.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::input::ExternalEffectGateInput;
use crate::gate::resolution::PolicyManifestResolution;
use crate::outbound_consent::{ScopedMcpConsentDecision, evaluate_scoped_mcp_call};
use crate::outbound_grant::{
    StandingOutboundGrant, decode_standing_outbound_grant_body,
    encode_standing_outbound_grant_body, standing_outbound_grant_principal_index_entity_id,
    standing_outbound_grant_principal_index_prefix,
};
use crate::registry::ENTITY_TYPE_OUTBOUND_GRANT;
use crate::store::Store;

pub(super) fn standing_outbound_grant_for_effect(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    required_grant_id: Option<EntityId>,
) -> Result<Option<(EntityId, StandingOutboundGrant)>> {
    let current_policy_floor = policy.read_frontier_hash()?;
    let mut candidate_ids = if let Some(required_grant_id) = required_grant_id {
        vec![required_grant_id]
    } else {
        Vec::new()
    };
    if candidate_ids.is_empty() {
        let candidate_principals = if effect.scoped_mcp_call.is_some() {
            verified_standing_outbound_grant_principal(effect)
                .into_iter()
                .collect()
        } else {
            standing_outbound_grant_candidate_principals(effect)
        };
        for principal_ref in candidate_principals {
            let prefix = standing_outbound_grant_principal_index_prefix(&principal_ref)?;
            for entry in store.vault_meta.prefix_iter(txn, &prefix)? {
                let (key, _) = entry?;
                let id = standing_outbound_grant_principal_index_entity_id(&key, &principal_ref)?;
                if !candidate_ids.contains(&id) {
                    candidate_ids.push(id);
                }
            }
        }
    }
    for id in candidate_ids {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            if required_grant_id == Some(id) {
                return Ok(None);
            }
            return Err(Error::CorruptedIndex("outbound grant entity row"));
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("outbound grant entity header"));
        };
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            if required_grant_id == Some(id) {
                return Ok(None);
            }
            return Err(Error::CorruptedIndex("outbound grant entity type"));
        }
        let grant = decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if !grant.is_active_under_policy(&current_policy_floor) {
            continue;
        }
        if !standing_outbound_grant_actor_matches(&grant, effect) {
            continue;
        }
        if let Some(call) = effect.scoped_mcp_call.as_ref() {
            if !is_mcp_effect_channel(&effect.channel) {
                continue;
            }
            if let Some(scoped_grant) = grant.scope.scoped_mcp_grant()
                && evaluate_scoped_mcp_call(scoped_grant, call.as_call())
                    == ScopedMcpConsentDecision::AutoFire
            {
                return Ok(Some((id, grant)));
            }
            continue;
        }
        if grant.scope.matches_effect(
            &effect.verb,
            &effect.channel,
            effect.counterparty.as_deref(),
            effect.brief_ref.as_deref(),
        ) {
            return Ok(Some((id, grant)));
        }
    }
    Ok(None)
}

pub(super) fn is_mcp_effect_channel(channel: &str) -> bool {
    channel
        .trim()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mcp:"))
}

fn standing_outbound_grant_candidate_principals(effect: &ExternalEffectGateInput) -> Vec<String> {
    let mut principals = Vec::with_capacity(2);
    if let Some(actor_ref) = effect.actor.actor_ref.as_deref()
        && !actor_ref.trim().is_empty()
    {
        principals.push(actor_ref.trim().to_owned());
    }
    if let Some(actor_entity_ref) = effect.provenance.actor_entity_ref {
        let actor_entity_ref = actor_entity_ref.to_hex();
        if !principals
            .iter()
            .any(|principal| principal == &actor_entity_ref)
        {
            principals.push(actor_entity_ref);
        }
    }
    principals
}

fn verified_standing_outbound_grant_principal(effect: &ExternalEffectGateInput) -> Option<String> {
    let actor_ref = effect
        .actor
        .actor_ref
        .as_deref()
        .map(str::trim)
        .filter(|actor_ref| !actor_ref.is_empty());
    match (actor_ref, effect.provenance.actor_entity_ref) {
        (Some(actor_ref), Some(actor_entity_ref)) => EntityId::from_hex(actor_ref)
            .ok()
            .filter(|actor_ref| *actor_ref == actor_entity_ref)
            .map(|_| actor_entity_ref.to_hex()),
        (Some(actor_ref), None) => Some(actor_ref.to_owned()),
        (None, Some(actor_entity_ref)) => Some(actor_entity_ref.to_hex()),
        (None, None) => None,
    }
}

fn standing_outbound_grant_actor_matches(
    grant: &StandingOutboundGrant,
    effect: &ExternalEffectGateInput,
) -> bool {
    effect
        .actor
        .actor_ref
        .as_deref()
        .is_some_and(|actor_ref| actor_ref == grant.principal_ref)
        || effect
            .provenance
            .actor_entity_ref
            .is_some_and(|actor_entity_ref| actor_entity_ref.to_hex() == grant.principal_ref)
}

pub(super) fn touch_standing_outbound_grant_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    grant: StandingOutboundGrant,
    used_at: u64,
) -> Result<()> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("outbound grant entity header"));
    };
    if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
        return Err(Error::CorruptedIndex("outbound grant entity type"));
    }
    let touched = grant.touched(used_at)?;
    let body = encode_standing_outbound_grant_body(&touched)?;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    payload.push(ENTITY_TYPE_OUTBOUND_GRANT);
    payload.extend_from_slice(&header.occurred_start.to_be_bytes());
    payload.extend_from_slice(&header.occurred_end.to_be_bytes());
    payload.extend_from_slice(&header.learned_at.to_be_bytes());
    payload.extend_from_slice(&body);
    store.entities.put(wtxn, id.as_bytes(), &payload)?;
    Ok(())
}
