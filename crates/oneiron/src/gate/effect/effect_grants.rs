//! Standing-grant resolution plus scoped-MCP channel check and grant use receipt.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::input::ExternalEffectGateInput;
use crate::gate::resolution::PolicyManifestResolution;
use crate::outbound_consent::{ScopedMcpConsentDecision, evaluate_scoped_mcp_call};
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, standing_outbound_grant_in_txn,
    standing_outbound_grants_for_principal_in_txn,
};
use crate::store::Store;

/// The standing outbound grant live on this writer that covers `effect`:
/// its row active under the current policy frontier, its principal the
/// effect's actor, and its bound containing the effect
/// ([`StandingOutboundGrant::covers_effect`]). A scoped MCP call is decided
/// by its payload-aware check, and a booking page's invite by the page
/// grant its dispatch door named.
pub(super) fn standing_outbound_grant_for_effect(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    required_grant_id: Option<EntityId>,
    prepared: Option<&crate::outbound_consent::tool_call::PreparedToolCall>,
) -> Result<Option<StandingOutboundGrant>> {
    let current_policy_floor = policy.read_frontier_hash()?;
    let mut candidates = Vec::new();
    if let Some(required_grant_id) = required_grant_id {
        let Some(required) = standing_outbound_grant_in_txn(store, txn, &required_grant_id)? else {
            return Ok(None);
        };
        candidates.push(required);
    }
    // A scoped MCP call is decided by its required grant alone. Any other
    // required grant is a booking-page grant the dispatch door bound to this
    // invite: it narrows which page grant may match, never the actor's others.
    if candidates.is_empty() || effect.scoped_mcp_call.is_none() {
        let candidate_principals = if effect.scoped_mcp_call.is_some() {
            verified_standing_outbound_grant_principal(effect)
                .into_iter()
                .collect()
        } else {
            standing_outbound_grant_candidate_principals(effect)
        };
        for principal_ref in candidate_principals {
            for grant in standing_outbound_grants_for_principal_in_txn(store, txn, &principal_ref)?
            {
                if !candidates
                    .iter()
                    .any(|held: &StandingOutboundGrant| held.grant_ref() == grant.grant_ref())
                {
                    candidates.push(grant);
                }
            }
        }
    }
    for grant in candidates {
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
                return Ok(Some(grant));
            }
            continue;
        }
        // A booking-page grant covers only the invite the dispatch door's
        // calendar admission bound to it and named here, never a verb.
        if matches!(
            grant.scope,
            StandingOutboundGrantScope::BookingPageInvites { .. }
        ) {
            if required_grant_id == Some(grant.id)
                && effect.verb.trim() == crate::calendar::CALENDAR_INVITE_VERB
            {
                return Ok(Some(grant));
            }
            continue;
        }
        if grant.covers_effect(
            &effect.verb,
            &effect.channel,
            effect.counterparty.as_deref(),
            effect.brief_ref.as_deref(),
        ) {
            return Ok(Some(grant));
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

/// Writes the quiet use receipt of the standing outbound grant that covered
/// an admitted effect, beside the Gate's Allow, naming the effect by the
/// Allow's own diff handle: the grant's row carries no last use, so its Used
/// receipts are where its uses read.
pub(super) fn record_standing_outbound_grant_use_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: &StandingOutboundGrant,
    diff_handle: &[u8],
) -> Result<()> {
    let digest =
        <[u8; 32]>::try_from(diff_handle).unwrap_or_else(|_| *blake3::hash(diff_handle).as_bytes());
    crate::consent::record_standing_grant_use_for_store_in_txn(
        store,
        wtxn,
        &grant.grant_ref(),
        crate::consent::EffectDigest::from_bytes(digest),
    )?;
    Ok(())
}

/// OF-374: what an `email/send` meets at its sender row's envelope when that
/// row's autonomy resolves `AutonomousWithinEnvelope`, proven on the Gate's
/// writer snapshot and not yet written: the slot it would spend, or (FIX
/// 7948) its place in the line of a full window. `effect_key` is the
/// canonical mail digest an owner press would bind, so an exact replay of
/// one send finds its own slot and a send that comes back finds its place.
///
/// FIX 1158: a send whose host supplied its relationship context (and
/// counterparty class) reads only that context's autonomy row, so a
/// multi-context row releases on the send's own context and a class-pinned
/// envelope matches a send of that class. With no context supplied, only an
/// unambiguous envelope admits: exactly one context on this row at that rung,
/// with no counterparty-class pin. Either way it is bound to the effect's own
/// actor. Anything else is `None`, and a grant that refuses is a denial:
/// either way the send keeps its press.
pub(super) fn channel_identity_envelope_admission_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    effect_key: [u8; 32],
    now: u64,
) -> Result<Option<crate::outbound_grant::ChannelIdentityGrantAdmission>> {
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
    let (mode, counterparty_class) = if let Some(send) = effect.send_autonomy.as_ref() {
        let mode = match reader.autonomy_mode_in_txn(txn, identity, send.relationship, now, now) {
            Ok(mode) => mode,
            Err(Error::Gate(GateError::InvalidConsentBound(_))) => return Ok(None),
            Err(error) => return Err(error),
        };
        if mode.rung != ChannelIdentityAutonomyRung::AutonomousWithinEnvelope {
            return Ok(None);
        }
        (mode, send.counterparty_class.clone())
    } else {
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
        (mode, None)
    };
    let Some(grant_ref) = mode.action_grant_ref else {
        return Ok(None);
    };
    let candidate = ChannelIdentityEffectCandidate {
        identity_ref: identity,
        relationship_context: mode.relationship_context,
        verb_class: "mail.send".to_owned(),
        counterparty_class,
        effect_key,
    };
    crate::outbound_grant::admit_channel_identity_grant_in_txn(
        store, txn, &grant_ref, &candidate, now,
    )
    .map(Some)
}

/// FIX 5238 (L02 seam): the Grant live on THIS writer that covers `effect`,
/// read as [`super::evaluate_external_effect_policy`] reads its coverage: a
/// standing outbound grant active under the current policy frontier whose
/// actor matches and whose bound contains the effect, a budget-free
/// policy-scoped grant the four-axis matcher accepts, or an active DEC-0006
/// standing consent grant whose bound covers the effect. It records,
/// charges and spends nothing, and an approve-once press is no Grant.
/// `None`: no live Grant covers it.
pub(crate) fn live_grant_covering_effect_in_txn(
    store: &Store,
    wtxn: &heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
) -> Result<Option<String>> {
    let (hydrated, _, _) = super::hydrate_external_effect_contact(store, wtxn, effect, policy)?;
    if let Some(grant) =
        standing_outbound_grant_for_effect(store, wtxn, &hydrated, policy, None, None)?
    {
        return Ok(Some(grant.grant_ref()));
    }
    let provisional = hydrated.gate_input(None, None);
    if let Some(context) = provisional.external_effect.as_ref()
        && policy.scoped_grants().iter().any(|grant| {
            grant.budget.is_none()
                && crate::gate::grants::external_effect_grant_matches(
                    grant,
                    &provisional.actor,
                    context,
                )
        })
    {
        return Ok(Some("policy".to_owned()));
    }
    let grants = crate::consent::load_active_standing_grants(store, wtxn)?;
    let covered = super::external_effect_consent_context(&hydrated, None, &grants)
        .is_some_and(|context| matches!(context.decision, crate::consent::ConsentDecision::Auto));
    Ok(covered.then(|| "consent".to_owned()))
}
