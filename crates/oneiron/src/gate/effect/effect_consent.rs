//! Pure DEC-0006 consent constructors over gate input.

use crate::gate::input::{ConsentGateContext, ExternalEffectGateInput};

/// Composes the DEC-0006 consent context for one external effect.
///
/// This is how the ONE production external-effect door
/// ([`evaluate_external_effect_policy`]) opts onto the unified consent path:
/// it maps the engine-observed effect facts into a [`crate::consent::ComposedEffect`]
/// and runs the ONE evaluator, so no caller re-implements the ladder or
/// smuggles a caller-chosen `reversible` verdict in (invariant 6 — every fact
/// here is host-observed: an outbound send is irreversible-in-effect by
/// construction, with external observers on the channel).
///
/// Returns `None` when the effect facts cannot be normalized into an honest
/// requirement pair (a verb or channel that fails the bound-ref rules) — the
/// door then keeps its pre-DEC-0006 criticality behaviour rather than
/// fabricate a bound no grant could ever cover or could always cover.
pub(in crate::gate) fn external_effect_composed_effect(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::ComposedEffect> {
    let facts = external_effect_facts(effect);
    let requirement = external_effect_action_requirement(effect)?;
    crate::consent::ComposedEffect::new(facts)
        .with_action_requirement(requirement)
        .ok()
}

/// One native-mail cold send has a distinct approve-once digest for its
/// sending identity, canonical recipient and logical send reference. Ordinary
/// standing grants still use the existing `send` action requirement; only the
/// one-shot digest changes, so approved send A cannot release send B.
pub(in crate::gate) fn native_mail_cold_composed_effect(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::ComposedEffect> {
    let identity = effect.channel_identity_ref?;
    let recipient = effect.counterparty.as_deref()?;
    let send = effect.send_ref.as_deref()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.native_mail.cold_send.approve_once.v1");
    let id_hex = identity.to_hex();
    let content = effect.provenance.mail_content_ref.as_deref();
    for part in [id_hex.as_str(), recipient, send] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    match content {
        Some(content) => {
            hasher.update(&[1]);
            hasher.update(&(content.len() as u64).to_le_bytes());
            hasher.update(content.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    let mut facts = external_effect_facts(effect);
    facts.operation_kind = format!("external:email:send:once:{}", hasher.finalize().to_hex());
    crate::consent::ComposedEffect::new(facts)
        .with_action_requirement(external_effect_action_requirement(effect)?)
        .ok()
}

pub(in crate::gate) fn external_effect_consent_context(
    effect: &ExternalEffectGateInput,
    approve_once: Option<&crate::consent::ApproveOnceAuthorization>,
    grants: &[crate::consent::StandingConsentGrant],
) -> Option<ConsentGateContext> {
    let composed = external_effect_composed_effect(effect)?;
    Some(ConsentGateContext::evaluate(
        &composed,
        approve_once,
        grants,
    ))
}

/// The host-observed fact set for one external effect, in the consent
/// evaluator's vocabulary. An external send/deploy is irreversible-in-effect
/// and externally observable by definition; nothing here is caller-asserted.
fn external_effect_facts(effect: &ExternalEffectGateInput) -> crate::consent::EffectFacts {
    let operation_kind = if effect.verb.trim().is_empty() {
        format!("external:{}", effect.channel.trim())
    } else {
        format!("external:{}:{}", effect.channel.trim(), effect.verb.trim())
    };
    crate::consent::EffectFacts {
        operation_kind,
        // An outbound effect rides the transport's send hook chain.
        fires_hooks: true,
        // A dispatch leaves this vault: it is published to (observed by) the
        // channel's counterparties, so undo cannot retract it.
        triggers_publish: true,
        external_observers: true,
        undo_fidelity: crate::consent::UndoFidelity::None,
        blast_radius: 1,
        catastrophe: None,
    }
}

/// The action requirement one external effect must be covered by: acting actor
/// × its verb class × an envelope naming the verb selector.
///
/// The selector vocabulary mirrors the canonical
/// [`crate::consent::action_grant_from_standing_outbound_grant`] adapter
/// (`verb:<class>` / `channel:<channel>` / `contact:<ref>` / `brief:<ref>`),
/// so a legacy grant scope-matched onto this effect reads as consent-COVERING
/// it — the fold that closes the write-side residual without minting a second
/// rememberable lane. An effect whose verb class is not named by a grant's
/// dial is envelope-uncovered on the same axis, so it still asks (the DEC-0006
/// bound-exceeded path). The actor is NOT class-narrowed and the envelope is
/// NOT target-pinned: the adapter mints grants on `principal_ref` alone, and
/// the door's scope matcher already verified the channel/contact/brief axes on
/// this txn before this fold runs.
pub(in crate::gate) fn external_effect_action_requirement(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::GrantBound> {
    let actor_ref = effect
        .actor
        .actor_ref
        .clone()
        .or_else(|| effect.provenance.actor_entity_ref.map(|id| id.to_hex()))?;
    let verb_class = if effect.verb.trim().is_empty() {
        effect.channel.trim()
    } else {
        effect.verb.trim()
    };
    // The envelope's selectors name the verb axis exactly as the legacy
    // adapter mints it (`verb:<class>`), so a scope-matched grant's fold reads
    // as containing the effect. The channel axis rides the TARGET pin instead
    // of the selector set — the selectors must stay verb-shaped or a
    // verb-class grant (selector `[verb:send]`) would fail subset-containment
    // against a candidate that also names its channel. Target-pinning to the
    // channel mirrors the `Channel` dial's target arm, so `Channel{email}`
    // contains an email-send while a `BriefVerbClass{brief}` grant covers only
    // its own brief; a verb-class grant with NO target pin covers both.
    let mut envelope = crate::consent::ActionEnvelope::new([format!("verb:{verb_class}")]).ok()?;
    let target = effect
        .brief_ref
        .as_deref()
        .unwrap_or_else(|| effect.channel.trim());
    if !target.is_empty() {
        envelope = envelope.with_target(target).ok()?;
    }
    crate::consent::GrantBound::action(
        crate::consent::ActorBound::new(actor_ref).ok()?,
        crate::consent::ActionClass::new(verb_class).ok()?,
        envelope,
    )
    .ok()
}
