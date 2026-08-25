use crate::error::Result;

use super::effect::{ComposedEffect, ConsentDecision, EffectDigest};
use super::grant::StandingConsentGrant;
use super::support::{
    SUBJECT_KIND_ACTOR, SUBJECT_KIND_AUDIENCE, hash_field, invalid_bound, normalized_ref,
    normalized_selectors, selectors_contain,
};

const DOMAIN_DISCLOSURE: &str = "disclosure";
pub(super) const DOMAIN_ACTION: &str = "action";

/// Domain-separated BLAKE3 label for a normalized bound digest.
const BOUND_DIGEST_DOMAIN: &[u8] = b"oneiron.consent.bound_digest.v1\0";

/// Upper bound on selectors in one envelope. A bound is a bound, not a
/// standing blanket assembled out of thousands of clauses.
pub const MAX_ENVELOPE_SELECTORS: usize = 256;
/// Upper bound on the byte length of any single ref/selector string.
pub const MAX_CONSENT_REF_LEN: usize = 512;
/// Upper bound on audience members in a disclosure bound.
pub const MAX_AUDIENCE_MEMBERS: usize = 256;

// ---------------------------------------------------------------------------
// The bound — invariant 3
// ---------------------------------------------------------------------------

/// An actor subject: WHO runs the effect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActorBound {
    pub(super) actor_ref: String,
    pub(super) actor_class: Option<String>,
}

impl ActorBound {
    /// Builds an actor subject, rejecting an empty or oversized reference.
    pub fn new(actor_ref: impl Into<String>) -> Result<Self> {
        Ok(Self {
            actor_ref: normalized_ref("actor_ref", actor_ref.into())?,
            actor_class: None,
        })
    }

    /// Narrows the subject to one actor class as well as one reference.
    pub fn with_actor_class(mut self, actor_class: impl Into<String>) -> Result<Self> {
        self.actor_class = Some(normalized_ref("actor_class", actor_class.into())?);
        Ok(self)
    }

    /// The bound actor reference.
    #[must_use]
    pub fn actor_ref(&self) -> &str {
        &self.actor_ref
    }

    /// The bound actor class, when the subject is class-narrowed.
    #[must_use]
    pub fn actor_class(&self) -> Option<&str> {
        self.actor_class.as_deref()
    }

    /// Subject containment: a candidate is inside this subject when it names
    /// the same actor and is no wider on the class axis.
    #[must_use]
    fn contains(&self, candidate: &Self) -> bool {
        if self.actor_ref != candidate.actor_ref {
            return false;
        }
        match (&self.actor_class, &candidate.actor_class) {
            // The grant is class-agnostic: any class of that actor is inside.
            (None, _) => true,
            // The grant pins a class; the candidate must pin the same one. An
            // unpinned candidate is WIDER than the grant, so it is outside.
            (Some(bound), Some(candidate)) => bound == candidate,
            (Some(_), None) => false,
        }
    }
}

/// An audience subject: WHO may hear the disclosure.
///
/// The membership list is the "room". It is sorted and deduped so containment
/// is deterministic, and an empty room is rejected — a disclosure grant to
/// nobody is a bug, not a permissive default.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AudienceBound {
    pub(super) members: Vec<String>,
}

impl AudienceBound {
    /// Builds an audience subject from its members.
    pub fn new(members: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut members = members
            .into_iter()
            .map(|member| normalized_ref("audience member", member))
            .collect::<Result<Vec<_>>>()?;
        members.sort_unstable();
        members.dedup();
        if members.is_empty() {
            return Err(invalid_bound("audience bound has no members"));
        }
        if members.len() > MAX_AUDIENCE_MEMBERS {
            return Err(invalid_bound("audience bound exceeds the member cap"));
        }
        Ok(Self { members })
    }

    /// Builds the singleton-audience case (one principal).
    pub fn singleton(member: impl Into<String>) -> Result<Self> {
        Self::new([member.into()])
    }

    /// The sorted, deduped audience members.
    #[must_use]
    pub fn members(&self) -> &[String] {
        &self.members
    }

    /// Subject containment: every candidate member must already be in the
    /// bound room. A new joiner shrinks the disclosable set — it never
    /// silently rides an existing grant.
    #[must_use]
    fn contains(&self, candidate: &Self) -> bool {
        candidate
            .members
            .iter()
            .all(|member| self.members.binary_search(member).is_ok())
    }
}

/// The subject axis of a bound.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BoundSubject {
    /// An action bound's actor.
    Actor(ActorBound),
    /// A disclosure bound's audience.
    Audience(AudienceBound),
}

impl BoundSubject {
    fn domain(&self) -> ConsentDomain {
        match self {
            Self::Actor(_) => ConsentDomain::Action,
            Self::Audience(_) => ConsentDomain::Disclosure,
        }
    }

    fn contains(&self, candidate: &Self) -> bool {
        match (self, candidate) {
            (Self::Actor(bound), Self::Actor(candidate)) => bound.contains(candidate),
            (Self::Audience(bound), Self::Audience(candidate)) => bound.contains(candidate),
            // Crossed domains never contain each other. Reaching this arm means
            // a caller assembled a mismatched pair upstream of the constructor.
            _ => false,
        }
    }
}

/// The class of data a disclosure bound covers (e.g. `health`, `roleplay`).
///
/// A doctor cleared for health is not cleared for roleplay: the class is part
/// of the bound, never a blanket "trusts this person".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DisclosureClass {
    value: String,
}

impl DisclosureClass {
    /// Builds a disclosure class from its pinned string.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self {
            value: normalized_ref("disclosure class", value.into())?,
        })
    }

    /// The pinned class string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

/// The class of action a bound covers — a verb CLASS, never a raw verb alone.
///
/// Invariant 3 forbids a bare verb from constituting a bound, which is why an
/// [`ActionClass`] is only usable inside a [`GrantBound`] alongside a subject
/// and an envelope; it can never authorize on its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionClass {
    value: String,
}

impl ActionClass {
    /// Builds an action (verb) class from its pinned string.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self {
            value: normalized_ref("action class", value.into())?,
        })
    }

    /// The pinned class string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

/// The class axis of a bound.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BoundClass {
    /// A disclosure data class.
    Disclosure(DisclosureClass),
    /// An action verb class.
    Action(ActionClass),
}

impl BoundClass {
    fn domain(&self) -> ConsentDomain {
        match self {
            Self::Disclosure(_) => ConsentDomain::Disclosure,
            Self::Action(_) => ConsentDomain::Action,
        }
    }

    fn matches(&self, candidate: &Self) -> bool {
        match (self, candidate) {
            (Self::Disclosure(bound), Self::Disclosure(candidate)) => bound == candidate,
            (Self::Action(bound), Self::Action(candidate)) => bound == candidate,
            _ => false,
        }
    }

    pub(super) fn as_str(&self) -> &str {
        match self {
            Self::Disclosure(class) => class.as_str(),
            Self::Action(class) => class.as_str(),
        }
    }
}

/// The data envelope of a disclosure bound: WHICH entities/topics/purposes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DisclosureEnvelope {
    pub(super) selectors: Vec<String>,
}

impl DisclosureEnvelope {
    /// Builds a data envelope from its selectors.
    pub fn new(selectors: impl IntoIterator<Item = String>) -> Result<Self> {
        let selectors = normalized_selectors(selectors)?;
        Ok(Self { selectors })
    }

    /// The sorted, deduped selectors.
    #[must_use]
    pub fn selectors(&self) -> &[String] {
        &self.selectors
    }

    /// Envelope containment: every candidate selector must be inside the
    /// bound's selector set.
    #[must_use]
    fn contains(&self, candidate: &Self) -> bool {
        selectors_contain(&self.selectors, &candidate.selectors)
    }
}

/// The target envelope of an action bound: WHICH targets, under WHICH budget.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionEnvelope {
    pub(super) selectors: Vec<String>,
    pub(super) target: Option<String>,
    pub(super) budget: Option<u64>,
    pub(super) receipt_required: bool,
}

impl ActionEnvelope {
    /// Builds a target envelope from its selectors.
    pub fn new(selectors: impl IntoIterator<Item = String>) -> Result<Self> {
        Ok(Self {
            selectors: normalized_selectors(selectors)?,
            target: None,
            budget: None,
            receipt_required: false,
        })
    }

    /// Narrows the envelope to one exact target reference.
    pub fn with_target(mut self, target: impl Into<String>) -> Result<Self> {
        self.target = Some(normalized_ref("action target", target.into())?);
        Ok(self)
    }

    /// Caps the envelope with a numeric budget.
    #[must_use]
    pub const fn with_budget(mut self, budget: u64) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Requires a receipt on every use inside this envelope.
    ///
    /// `receipt_required` can only RESTRICT: it is never consulted to
    /// authorize, only to add an obligation to an already-covered use.
    #[must_use]
    pub const fn with_receipt_required(mut self, receipt_required: bool) -> Self {
        self.receipt_required = receipt_required;
        self
    }

    /// The sorted, deduped selectors.
    #[must_use]
    pub fn selectors(&self) -> &[String] {
        &self.selectors
    }

    /// The exact target reference, when the envelope is target-narrowed.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// The numeric budget cap, when present.
    #[must_use]
    pub const fn budget(&self) -> Option<u64> {
        self.budget
    }

    /// Whether every use inside this envelope must emit a receipt.
    #[must_use]
    pub const fn receipt_required(&self) -> bool {
        self.receipt_required
    }

    /// Envelope containment: selectors contain, target is equal-or-wider on
    /// the bound side, and the candidate's budget draw fits under the cap.
    #[must_use]
    fn contains(&self, candidate: &Self) -> bool {
        if !selectors_contain(&self.selectors, &candidate.selectors) {
            return false;
        }
        match (&self.target, &candidate.target) {
            (None, _) => {}
            (Some(bound), Some(candidate)) if bound == candidate => {}
            // A target-pinned grant does not cover an unpinned (wider)
            // candidate or a different target.
            (Some(_), _) => return false,
        }
        match (self.budget, candidate.budget) {
            (None, _) => true,
            (Some(cap), Some(draw)) => draw <= cap,
            // A budgeted grant does not cover an unbudgeted candidate.
            (Some(_), None) => false,
        }
    }
}

/// The envelope axis of a bound.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BoundEnvelope {
    /// A disclosure data envelope.
    Disclosure(DisclosureEnvelope),
    /// An action target envelope.
    Action(ActionEnvelope),
}

impl BoundEnvelope {
    fn domain(&self) -> ConsentDomain {
        match self {
            Self::Disclosure(_) => ConsentDomain::Disclosure,
            Self::Action(_) => ConsentDomain::Action,
        }
    }

    fn contains(&self, candidate: &Self) -> bool {
        match (self, candidate) {
            (Self::Disclosure(bound), Self::Disclosure(candidate)) => bound.contains(candidate),
            (Self::Action(bound), Self::Action(candidate)) => bound.contains(candidate),
            _ => false,
        }
    }
}

/// Which of the two disjoint consent domains a shape belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsentDomain {
    /// Data → audience.
    Disclosure,
    /// Actor → verb-class → target.
    Action,
}

impl ConsentDomain {
    /// The pinned on-disk / receipt string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disclosure => DOMAIN_DISCLOSURE,
            Self::Action => DOMAIN_ACTION,
        }
    }

    /// Parses a pinned domain string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            DOMAIN_DISCLOSURE => Some(Self::Disclosure),
            DOMAIN_ACTION => Some(Self::Action),
            _ => None,
        }
    }

    /// The domain-specific fail-safe direction — invariant 8. Disclosure fails
    /// safe by HIDING; writes fail safe by ASKING.
    #[must_use]
    pub const fn fail_safe(self) -> ConsentDecision {
        match self {
            Self::Disclosure => ConsentDecision::Hide,
            Self::Action => ConsentDecision::Ask,
        }
    }
}

/// A bound: `(actor/audience × class × envelope)`.
///
/// The constructor is the enforcement point for invariant 4: the three axes
/// must agree on domain. Disclosure means audience → data class → data
/// envelope; action means actor → verb class → target envelope. A crossed
/// triple is rejected, so a caller cannot reinterpret one domain as the other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantBound {
    subject: BoundSubject,
    class: BoundClass,
    envelope: BoundEnvelope,
}

impl GrantBound {
    /// Builds a bound from matching domain triples.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConsentBound`] when the subject, class, and
    /// envelope do not all name the same domain.
    ///
    /// [`Error::InvalidConsentBound`]: crate::error::Error::InvalidConsentBound
    pub fn new(subject: BoundSubject, class: BoundClass, envelope: BoundEnvelope) -> Result<Self> {
        let domain = subject.domain();
        if class.domain() != domain || envelope.domain() != domain {
            return Err(invalid_bound(
                "grant bound mixes disclosure and action axes; the triple must name one domain",
            ));
        }
        Ok(Self {
            subject,
            class,
            envelope,
        })
    }

    /// Builds a disclosure bound: audience → data class → data envelope.
    pub fn disclosure(
        audience: AudienceBound,
        class: DisclosureClass,
        envelope: DisclosureEnvelope,
    ) -> Result<Self> {
        Self::new(
            BoundSubject::Audience(audience),
            BoundClass::Disclosure(class),
            BoundEnvelope::Disclosure(envelope),
        )
    }

    /// Builds an action bound: actor → verb class → target envelope.
    pub fn action(actor: ActorBound, class: ActionClass, envelope: ActionEnvelope) -> Result<Self> {
        Self::new(
            BoundSubject::Actor(actor),
            BoundClass::Action(class),
            BoundEnvelope::Action(envelope),
        )
    }

    /// The subject axis.
    #[must_use]
    pub const fn subject(&self) -> &BoundSubject {
        &self.subject
    }

    /// The class axis.
    #[must_use]
    pub const fn class(&self) -> &BoundClass {
        &self.class
    }

    /// The envelope axis.
    #[must_use]
    pub const fn envelope(&self) -> &BoundEnvelope {
        &self.envelope
    }

    /// The domain this bound belongs to.
    #[must_use]
    pub fn domain(&self) -> ConsentDomain {
        self.subject.domain()
    }

    /// Deterministic, monotone containment — invariant 3.
    ///
    /// Same domain **and** same subject-containment **and** same class **and**
    /// envelope containment. Anything that exceeds the bound is not contained,
    /// so it becomes a fresh ask rather than silent reuse. Containment never
    /// mutates either side: widening is a separate owner decision.
    #[must_use]
    pub fn contains(&self, candidate: &Self) -> bool {
        self.domain() == candidate.domain()
            && self.subject.contains(&candidate.subject)
            && self.class.matches(&candidate.class)
            && self.envelope.contains(&candidate.envelope)
    }

    /// Engine-computed digest over the normalized bound, used as the
    /// `diff_handle` of a standing-grant receipt.
    #[must_use]
    pub fn digest(&self) -> EffectDigest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BOUND_DIGEST_DOMAIN);
        hasher.update(self.domain().as_str().as_bytes());
        match &self.subject {
            BoundSubject::Actor(actor) => {
                hash_field(&mut hasher, SUBJECT_KIND_ACTOR.as_bytes());
                hash_field(&mut hasher, actor.actor_ref.as_bytes());
                hash_field(
                    &mut hasher,
                    actor.actor_class.as_deref().unwrap_or_default().as_bytes(),
                );
            }
            BoundSubject::Audience(audience) => {
                hash_field(&mut hasher, SUBJECT_KIND_AUDIENCE.as_bytes());
                for member in &audience.members {
                    hash_field(&mut hasher, member.as_bytes());
                }
            }
        }
        hash_field(&mut hasher, self.class.as_str().as_bytes());
        match &self.envelope {
            BoundEnvelope::Disclosure(envelope) => {
                for selector in &envelope.selectors {
                    hash_field(&mut hasher, selector.as_bytes());
                }
            }
            BoundEnvelope::Action(envelope) => {
                for selector in &envelope.selectors {
                    hash_field(&mut hasher, selector.as_bytes());
                }
                hash_field(
                    &mut hasher,
                    envelope.target.as_deref().unwrap_or_default().as_bytes(),
                );
                hasher.update(&envelope.budget.unwrap_or(0).to_be_bytes());
                hasher.update(&[u8::from(envelope.receipt_required)]);
            }
        }
        EffectDigest(*hasher.finalize().as_bytes())
    }
}

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
