use rmpv::Value;

use crate::access_grant::{AccessGrant, AccessGrantCapability, AccessGrantScope};
use crate::disclosure::{DisclosureScope, DisclosureScopeStatus};
use crate::error::Result;
use crate::gate::PolicyScopedGrant;

use super::bound::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, DisclosureClass, DisclosureEnvelope,
    GrantBound,
};
use super::grant::{ActionGrant, DisclosureGrant};
use super::support::invalid_bound;

// ---------------------------------------------------------------------------
// Adapters — fold existing shapes, never migrate them
// ---------------------------------------------------------------------------

/// Projects a legacy [`AccessGrant`] into a [`DisclosureGrant`].
///
/// `principal_ref` becomes the singleton audience, `AccessGrantCapability`
/// becomes the disclosure class, and `AccessGrantScope` becomes the data
/// envelope. The source record's bytes, status vocabulary, and codec are
/// untouched — a revoked legacy grant simply projects into a bound the caller
/// will not treat as live.
///
/// Shared brief scopes and capabilities are rejected, even when active. Their
/// view authority must resolve only through [`crate::Vault::resolve_share_for_view`],
/// which rereads grant status and current recipient/claim scope for each view.
/// A static disclosure bound cannot enforce that live redaction boundary.
pub fn disclosure_grant_from_access_grant(grant: &AccessGrant) -> Result<DisclosureGrant> {
    if !crate::federation::grant_scope::admits_preset(&grant.authority_scope, "read") {
        return Err(invalid_bound("record-aware Scope evaluation required"));
    }
    // Reject the capability too: an unvalidated legacy scope must not project
    // a shared-brief read class that bypasses the live resolver.
    if grant.capability == AccessGrantCapability::SharedBriefRead {
        return Err(invalid_bound(
            "shared brief reads require Vault::resolve_share_for_view",
        ));
    }
    let audience = AudienceBound::singleton(grant.principal_ref.to_hex())?;
    let class = DisclosureClass::new(grant.capability.as_str())?;
    let envelope = DisclosureEnvelope::new(access_grant_scope_selectors(&grant.scope)?)?;
    DisclosureGrant::new(GrantBound::disclosure(audience, class, envelope)?)
}

fn access_grant_scope_selectors(scope: &AccessGrantScope) -> Result<Vec<String>> {
    match scope {
        AccessGrantScope::Messages { space_ref }
        | AccessGrantScope::Summaries { space_ref }
        | AccessGrantScope::RelationshipClaims { space_ref } => {
            Ok(vec![format!("space:{}", space_ref.to_hex())])
        }
        AccessGrantScope::ConversationMessages { conversation_ref } => {
            Ok(vec![format!("conversation:{}", conversation_ref.to_hex())])
        }
        AccessGrantScope::CompanionProfile {
            person_ref,
            facet_ref,
        } => Ok(std::iter::once(format!("person:{}", person_ref.to_hex()))
            .chain(facet_ref.map(|facet_ref| format!("facet:{}", facet_ref.to_hex())))
            .collect()),
        AccessGrantScope::Calendar { calendar_ref, rung } => Ok(vec![
            format!("calendar:{}", calendar_ref.to_hex()),
            format!("rung:{}", rung.as_str()),
        ]),
        AccessGrantScope::ChannelIdentity { .. } => Err(invalid_bound(
            "channel identity reads require the live mailbox envelope door",
        )),
        AccessGrantScope::SharedBrief { .. } => Err(invalid_bound(
            "shared brief scopes require Vault::resolve_share_for_view",
        )),
        AccessGrantScope::DiaryCoreference { .. } => Err(invalid_bound(
            "diary coreference requires both resident grants at the scoped read door",
        )),
    }
}

/// Whether a legacy [`AccessGrant`] projection is currently live.
///
/// `SharedBriefRead` is deliberately excluded even for an active record:
/// only [`crate::Vault::resolve_share_for_view`] can resolve its live view authority.
#[must_use]
pub fn access_grant_projection_is_active(grant: &AccessGrant, now: u64) -> bool {
    crate::federation::grant_scope::admits_preset(&grant.authority_scope, "read")
        && grant.effective_status_at(now) == crate::access_grant::AccessGrantStatus::Active
        && matches!(
            grant.capability,
            AccessGrantCapability::MessagesRead
                | AccessGrantCapability::SummariesRead
                | AccessGrantCapability::RelationshipClaimsRead
                | AccessGrantCapability::CompanionProfileRead
                | AccessGrantCapability::CalendarDisclosureRead
        )
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
pub(super) fn action_grant_from_policy_scoped_grant(
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

/// Projects an active contact clearance into a typed Scope-valued bound.
/// An empty or revoked Scope cannot project a reusable disclosure grant.
pub fn disclosure_grant_from_disclosure_scope(
    clearance: &DisclosureScope,
    interlocutor_ref: &str,
    class: &str,
) -> Result<DisclosureGrant> {
    clearance.validate()?;
    if clearance.status != DisclosureScopeStatus::Active {
        return Err(invalid_bound(
            "revoked contact clearance projects to no bound",
        ));
    }
    let audience = AudienceBound::singleton(interlocutor_ref)?;
    DisclosureGrant::new(GrantBound::disclosure(
        audience,
        DisclosureClass::new(class)?,
        DisclosureEnvelope::from_scope(clearance.scope.clone())?,
    )?)
}
