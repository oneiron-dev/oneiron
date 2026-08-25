use rmpv::Value;

use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use crate::disclosure::{DisclosureScope, DisclosureScopeStatus};
use crate::error::Result;
use crate::gate::PolicyScopedGrant;
use crate::outbound_grant::{StandingOutboundGrant, StandingOutboundGrantScope};

use super::bound::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, DisclosureClass, DisclosureEnvelope,
    GrantBound,
};
use super::grant::{ActionGrant, DisclosureGrant};
use super::support::invalid_bound;

// ---------------------------------------------------------------------------
// Adapters — fold existing shapes, never migrate them
// ---------------------------------------------------------------------------

/// Projects an [`AccessGrant`] into a [`DisclosureGrant`].
///
/// `principal_ref` becomes the singleton audience, `AccessGrantCapability`
/// becomes the disclosure class, and `AccessGrantScope` becomes the data
/// envelope. The source record's bytes, status vocabulary, and codec are
/// untouched — a revoked grant simply projects into a bound the caller will
/// not treat as live.
pub fn disclosure_grant_from_access_grant(grant: &AccessGrant) -> Result<DisclosureGrant> {
    let audience = AudienceBound::singleton(grant.principal_ref.to_hex())?;
    let class = DisclosureClass::new(grant.capability.as_str())?;
    let envelope = DisclosureEnvelope::new(access_grant_scope_selectors(grant.scope))?;
    DisclosureGrant::new(GrantBound::disclosure(audience, class, envelope)?)
}

fn access_grant_scope_selectors(scope: AccessGrantScope) -> Vec<String> {
    match scope {
        AccessGrantScope::CompanionProfile {
            person_ref,
            persona_ref,
        } => vec![
            format!("person:{}", person_ref.to_hex()),
            format!("persona:{}", persona_ref.to_hex()),
        ],
        AccessGrantScope::Calendar { calendar_ref, rung } => vec![
            format!("calendar:{}", calendar_ref.to_hex()),
            format!("rung:{}", rung.as_str()),
        ],
    }
}

/// Whether an [`AccessGrant`] projection is currently live.
#[must_use]
pub fn access_grant_projection_is_active(grant: &AccessGrant) -> bool {
    grant.status == AccessGrantStatus::Active
        && matches!(
            grant.capability,
            AccessGrantCapability::CompanionProfileRead
                | AccessGrantCapability::CalendarDisclosureRead
        )
}

/// Projects a [`StandingOutboundGrant`] into an [`ActionGrant`].
///
/// `principal_ref` becomes the actor subject and must still match
/// `ExternalEffectGateInput.actor` / `provenance.actor_entity_ref` at the send
/// door — this adapter supplies the bound, it does not relax that check. The
/// verb class plus the contact/channel/brief/scoped-MCP target constraints
/// become the class and envelope; the origin component/action/receipt fields
/// stay receipt provenance on the source record and are NOT folded into the
/// bound.
pub fn action_grant_from_standing_outbound_grant(
    grant: &StandingOutboundGrant,
) -> Result<ActionGrant> {
    let actor = ActorBound::new(grant.principal_ref.as_str())?;
    let (class, selectors, target) = outbound_scope_axes(&grant.scope);
    let mut envelope = ActionEnvelope::new(selectors)?;
    if let Some(target) = target {
        envelope = envelope.with_target(target)?;
    }
    ActionGrant::new(GrantBound::action(
        actor,
        ActionClass::new(class)?,
        envelope,
    )?)
}

/// The outbound verb class used when a scope dial names a channel or contact
/// rather than a verb: those dials are send-class by construction.
const OUTBOUND_SEND_VERB_CLASS: &str = "send";

pub(super) fn outbound_scope_axes(
    scope: &StandingOutboundGrantScope,
) -> (String, Vec<String>, Option<String>) {
    match scope {
        StandingOutboundGrantScope::Contact { contact_ref } => (
            OUTBOUND_SEND_VERB_CLASS.to_owned(),
            vec![format!("contact:{contact_ref}")],
            Some(contact_ref.clone()),
        ),
        StandingOutboundGrantScope::VerbClass { verb_class } => {
            (verb_class.clone(), vec![format!("verb:{verb_class}")], None)
        }
        StandingOutboundGrantScope::Channel { channel } => (
            OUTBOUND_SEND_VERB_CLASS.to_owned(),
            vec![format!("channel:{channel}")],
            Some(channel.clone()),
        ),
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref,
            verb_class,
        } => (
            verb_class.clone(),
            vec![format!("brief:{brief_ref}")],
            Some(brief_ref.clone()),
        ),
        StandingOutboundGrantScope::ScopedMcp {
            server,
            tool,
            data_class_ceiling,
            endpoint_allowlist,
        } => {
            let mut selectors = vec![
                format!("server:{server}"),
                format!("tool:{tool}"),
                format!("data_class_ceiling:{}", data_class_ceiling.as_str()),
            ];
            selectors.extend(
                endpoint_allowlist
                    .iter()
                    .map(|endpoint| format!("endpoint:{endpoint}")),
            );
            (
                format!("{server}.{tool}"),
                selectors,
                Some(format!("{server}/{tool}")),
            )
        }
    }
}

/// Projects a [`PolicyScopedGrant`] into an [`ActionGrant`].
///
/// `actor_ref`/`actor_class` become the [`ActorBound`], `effector` becomes the
/// action class, and `scope` + `budget` become the normalized envelope.
///
/// `receipt_required` rides the envelope as an OBLIGATION only: it can
/// restrict a covered use by demanding a receipt, and is never consulted to
/// authorize one. A grant with no `actor_ref` names no subject and therefore
/// cannot become a bound at all.
// Crate-private because `PolicyScopedGrant` is crate-private (gate.rs). The
// production consumer is the GOV belt's gate.rs work, which lands behind this
// contract; until then the adapter's callers are its conformance tests.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn action_grant_from_policy_scoped_grant(
    grant: &PolicyScopedGrant,
) -> Result<ActionGrant> {
    let actor_ref = grant.actor_ref.as_deref().ok_or_else(|| {
        invalid_bound("policy scoped grant names no actor; a bound needs a subject")
    })?;
    let mut actor = ActorBound::new(actor_ref)?;
    if let Some(actor_class) = grant.actor_class.as_deref() {
        actor = actor.with_actor_class(actor_class)?;
    }
    let mut envelope = ActionEnvelope::new(policy_value_selectors("scope", grant.scope.as_ref()))?;
    if let Some(budget) = grant.budget.as_ref().and_then(rmpv::Value::as_u64) {
        envelope = envelope.with_budget(budget);
    }
    ActionGrant::new(GrantBound::action(
        actor,
        ActionClass::new(grant.effector.as_str())?,
        envelope.with_receipt_required(grant.receipt_required),
    )?)
}

#[cfg_attr(not(test), allow(dead_code))]
fn policy_value_selectors(label: &str, value: Option<&Value>) -> Vec<String> {
    let Some(Value::Map(entries)) = value else {
        return vec![format!("{label}:*")];
    };
    let mut selectors: Vec<String> = entries
        .iter()
        .filter_map(|(key, value)| {
            let key = key.as_str()?;
            let value = value.as_str()?;
            Some(format!("{label}.{key}:{value}"))
        })
        .collect();
    if selectors.is_empty() {
        selectors.push(format!("{label}:*"));
    }
    selectors
}

/// Projects a [`DisclosureScope`] into a [`DisclosureGrant`] for one resolved
/// interlocutor.
///
/// The resolved interlocutor/contact is the audience; entity/topic/purpose
/// selectors are the envelope. A missing or malformed scope remains HIDE:
/// callers with no scope must not call this at all, and a scope that fails
/// validation returns an error rather than an empty-but-permissive bound.
pub fn disclosure_grant_from_disclosure_scope(
    scope: &DisclosureScope,
    interlocutor_ref: &str,
    class: &str,
) -> Result<DisclosureGrant> {
    scope.validate()?;
    if scope.status != DisclosureScopeStatus::Active {
        return Err(invalid_bound(
            "revoked disclosure scope projects to no bound; the fail-safe is hide",
        ));
    }
    let audience = AudienceBound::singleton(interlocutor_ref)?;
    let mut selectors: Vec<String> = scope
        .entities
        .iter()
        .map(|entity| format!("entity:{}", entity.to_hex()))
        .collect();
    selectors.extend(scope.topics.iter().map(|topic| format!("topic:{topic}")));
    selectors.push(format!("purpose:{}", scope.purpose));
    DisclosureGrant::new(GrantBound::disclosure(
        audience,
        DisclosureClass::new(class)?,
        DisclosureEnvelope::new(selectors)?,
    )?)
}
