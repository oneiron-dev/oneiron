//! Standing-grant resolution plus scoped-MCP channel check and grant touch.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::input::ExternalEffectGateInput;
use crate::gate::resolution::PolicyManifestResolution;
use crate::outbound_consent::{ScopedMcpConsentDecision, evaluate_scoped_mcp_call};
use crate::outbound_grant::{
    StandingOutboundGrant, decode_standing_outbound_grant_body,
    standing_outbound_grant_ids_for_principal,
};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_OUTBOUND_GRANT;
use crate::store::Store;

pub(super) fn standing_outbound_grant_for_effect(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    required_grant_id: Option<EntityId>,
    prepared: Option<&crate::outbound_consent::tool_call::PreparedToolCall>,
) -> Result<Option<(EntityId, StandingOutboundGrant)>> {
    let current_policy_floor = policy.read_frontier_hash()?;
    let mut candidate_ids = if let Some(required_grant_id) = required_grant_id {
        vec![required_grant_id]
    } else {
        Vec::new()
    };
    // A scoped MCP call is decided by its required grant alone. Any other
    // required grant is a booking-page grant the dispatch door bound to this
    // invite: it narrows which page grant may match, never the actor's others.
    if candidate_ids.is_empty() || effect.scoped_mcp_call.is_none() {
        let candidate_principals = if effect.scoped_mcp_call.is_some() {
            verified_standing_outbound_grant_principal(effect)
                .into_iter()
                .collect()
        } else {
            standing_outbound_grant_candidate_principals(effect)
        };
        for principal_ref in candidate_principals {
            for id in standing_outbound_grant_ids_for_principal(store, txn, &principal_ref)? {
                if !candidate_ids.contains(&id) {
                    candidate_ids.push(id);
                }
            }
        }
    }
    for id in candidate_ids {
        let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
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
                && prepared.map_or_else(
                    || evaluate_scoped_mcp_call(scoped_grant, call.as_call()),
                    |prepared| {
                        if prepared.call() == call {
                            prepared.decision(scoped_grant)
                        } else {
                            ScopedMcpConsentDecision::Escalate(
                                crate::outbound_consent::ScopedMcpEscalationReason::InvalidGrant,
                            )
                        }
                    },
                ) == ScopedMcpConsentDecision::AutoFire
            {
                return Ok(Some((id, grant)));
            }
            continue;
        }
        // A booking-page grant covers only the invite the dispatch door's
        // calendar admission bound to it and named here, never a verb.
        if matches!(
            grant.scope,
            crate::outbound_grant::StandingOutboundGrantScope::BookingPageInvites { .. }
        ) {
            if required_grant_id == Some(id)
                && effect.verb.trim() == crate::calendar::CALENDAR_INVITE_VERB
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
    crate::ports::EntityStoreMaintenance::port_outbound_grant_touch(store, wtxn, id, grant, used_at)
}

/// OF-374: the envelope slot an `email/send` would spend when its sender row's
/// autonomy resolves `AutonomousWithinEnvelope`, proven on the Gate's writer
/// snapshot and not yet written. `effect_key` is the canonical mail digest an
/// owner press would bind, so an exact replay of one send finds its own slot.
///
/// The Gate input carries no relationship context or counterparty class, so
/// only an unambiguous envelope admits: exactly one context on this row at
/// that rung, with no counterparty-class pin, bound to the effect's own actor.
/// Anything else is `None` and the send keeps its press.
pub(super) fn channel_identity_envelope_reservation_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    effect_key: [u8; 32],
    now: u64,
) -> Result<Option<crate::outbound_grant::ChannelIdentityGrantReservation>> {
    use crate::channel_identity_autonomy::{
        AutonomyReader, ChannelIdentityAutonomyRung, ChannelIdentityEffectCandidate,
    };
    use crate::error::GateError;

    if effect.channel != "email" || effect.verb != "send" {
        return Ok(None);
    }
    let (Some(identity), Some(actor)) = (
        effect.channel_identity_ref,
        effect.provenance.actor_entity_ref,
    ) else {
        return Ok(None);
    };
    let reader = AutonomyReader { store };
    match reader.autonomy_identity_actor(txn, identity) {
        Ok(bound) if bound == actor => {}
        Ok(_) | Err(Error::Gate(GateError::InvalidConsentBound(_))) => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut autonomous = None;
    for context in crate::channel_identity_selection::RelationshipContext::ALL {
        let mode = match reader.autonomy_mode_in_txn(txn, identity, context, now, now) {
            Ok(mode) => mode,
            Err(Error::Gate(GateError::InvalidConsentBound(_))) => continue,
            Err(error) => return Err(error),
        };
        if mode.rung == ChannelIdentityAutonomyRung::AutonomousWithinEnvelope
            && autonomous.replace(mode).is_some()
        {
            return Ok(None);
        }
    }
    let Some(mode) = autonomous else {
        return Ok(None);
    };
    let Some(grant_ref) = mode.action_grant_ref else {
        return Ok(None);
    };
    let candidate = ChannelIdentityEffectCandidate {
        identity_ref: identity,
        relationship_context: mode.relationship_context,
        verb_class: "mail.send".to_owned(),
        counterparty_class: None,
        effect_key,
    };
    crate::outbound_grant::reserve_channel_identity_grant_in_txn(
        store, txn, &grant_ref, &candidate, now,
    )
}
