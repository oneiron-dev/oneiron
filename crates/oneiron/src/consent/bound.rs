use super::effect::ComposedEffect;
use super::grant::StandingConsentGrant;

pub(super) use crate::store::consent_bound::DOMAIN_ACTION;
pub use crate::store::consent_bound::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, BoundClass, BoundEnvelope,
    BoundSubject, ConsentDomain, DisclosureClass, DisclosureEnvelope, GrantBound,
    MAX_CONSENT_REF_LEN,
};

pub(super) fn covers(grants: &[StandingConsentGrant], required: &GrantBound) -> bool {
    grants.iter().any(|grant| grant.bound().contains(required))
}

/// Whether an uncovered requirement is an EXCEEDED bound rather than an absent
/// one — i.e. a grant already names this subject and class, but its envelope
/// does not reach this candidate.
///
/// The distinction IS invariant 3: an absent grant makes a first ask, while an
/// exceeded one is a scope-exceed escalation whose approve-and-stop-asking
/// mints a NEW, wider row. Both ask; the pending reason is what tells the
/// surface which conversation to have.
pub(crate) fn bound_exceeded(effect: &ComposedEffect, grants: &[StandingConsentGrant]) -> bool {
    [effect.disclosure_requirement(), effect.action_requirement()]
        .into_iter()
        .flatten()
        .any(|required| {
            !covers(grants, required)
                && grants.iter().any(|grant| {
                    let bound = grant.bound();
                    bound.domain() == required.domain()
                        && bound.subject.contains(&required.subject)
                        && bound.class.matches(&required.class)
                })
        })
}
