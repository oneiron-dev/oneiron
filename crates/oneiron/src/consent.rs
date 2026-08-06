//! DEC-0006 unified consent-mode — bounded standing grants.
//!
//! One consent primitive spans BOTH surfaces the owner experiences:
//! **disclosure** (what the companion reveals about them, data → audience)
//! and **action** (what an agent runs from the sandbox, actor → verb →
//! target). The nine DEC-0006 invariants are the acceptance authority and
//! are implemented here exactly, not illustratively.
//!
//! # Axes
//!
//! Two axes stay orthogonal and are never collapsed:
//!
//! * **Lifetime** — [`ConsentGrant`] is either [`ConsentGrant::ApproveOnce`]
//!   (this op, now, keyed by the exact [`EffectDigest`]) or
//!   [`ConsentGrant::Standing`] (a remembered bound).
//! * **Domain** — [`StandingConsentGrant`] is the DISJOINT
//!   [`StandingConsentGrant::Disclosure`] or [`StandingConsentGrant::Action`].
//!   A mixed operation (a `channel_send` of private content) carries TWO
//!   requirements and the evaluator applies logical AND — invariant 4.
//!
//! # What this module owns and does not own
//!
//! * It owns the canonical standing-grant rows, persisted as strict versioned
//!   MessagePack under the [`CONSENT_GRANT_KEY_PREFIX`] `vault_meta` prefix,
//!   written atomically with the Gate receipt. **No entity type and no type
//!   byte are allocated** — existing entity codecs are left intact.
//! * It owns the [`CATASTROPHE_FLOOR_V1`] closed set and its version pin.
//! * It owns host-side reversibility classification over an engine-built
//!   [`EffectFacts`]. No caller-supplied `reversible` verdict exists anywhere
//!   in this module's public surface — invariant 6.
//! * It does NOT mint a second receipt ledger: [`ConsentReceipt`] projects
//!   into the existing Gate receipt family via
//!   [`crate::store::GateDecisionRecord`] (`diff_handle` carries the
//!   effect/bound digest, `grant_ref` joins standing use).
//! * It stores **no key material, bearer token, credential, or hosting
//!   posture**, and no general duration/expiry field. The one named duration
//!   exception in canon is a mint-time field on the ARCH-0071 delegation
//!   record, which lives outside this module and is neither duplicated nor
//!   turned into an ask option here.
//!
//! # Folding existing shapes
//!
//! Four grant-shaped records predate this contract. They fold through
//! ADAPTERS ([`disclosure_grant_from_access_grant`],
//! [`action_grant_from_standing_outbound_grant`],
//! [`action_grant_from_policy_scoped_grant`],
//! [`disclosure_grant_from_disclosure_scope`]) — never a migration, a
//! rewrite, or a byte/status/codec change to the source record.

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use crate::disclosure::{DisclosureScope, DisclosureScopeStatus};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::PolicyScopedGrant;
use crate::outbound_grant::{StandingOutboundGrant, StandingOutboundGrantScope};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};

// ---------------------------------------------------------------------------
// Storage identity — no entity type, no type byte
// ---------------------------------------------------------------------------

/// `vault_meta` key prefix for canonical standing consent-grant rows. Owned by
/// this module; suffix is the 16-byte grant id.
pub(crate) const CONSENT_GRANT_KEY_PREFIX: &[u8] = b"consent.grant.v1:";

/// `vault_meta` key prefix for approve-once state. Owned by this module;
/// suffix is the 32-byte effect digest. Minting writes an available marker in
/// the same transaction as its receipt. Delivery atomically changes that marker
/// to spent in the transaction that authorizes the effect. Presence therefore
/// rejects a duplicate mint, while the state distinguishes the one live tap
/// from a replay (DEC-0006 invariant 2).
pub(crate) const CONSENT_APPROVE_ONCE_KEY_PREFIX: &[u8] = b"consent.once.v1:";

const CONSENT_APPROVE_ONCE_MARKER_VERSION: u8 = 1;
const CONSENT_APPROVE_ONCE_AVAILABLE: u8 = 0;
const CONSENT_APPROVE_ONCE_SPENT: u8 = 1;
const CONSENT_APPROVE_ONCE_MARKER_LEN: usize = 18;

/// Body schema version of a persisted standing consent-grant row.
pub const CONSENT_GRANT_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for standing consent-grant rows.
///
/// There is deliberately **no** `expires_at`, `duration`, `ttl`, or any other
/// lifetime field: invariant 9 replaces expiry-guessing with the registry.
pub const CONSENT_GRANT_BODY_KEYS: [&str; 8] = [
    "schema_version",
    "domain",
    "subject",
    "class",
    "envelope",
    "status",
    "owner_stamp",
    "created_at",
];

const KEY_SCHEMA_VERSION: &str = CONSENT_GRANT_BODY_KEYS[0];
const KEY_DOMAIN: &str = CONSENT_GRANT_BODY_KEYS[1];
const KEY_SUBJECT: &str = CONSENT_GRANT_BODY_KEYS[2];
const KEY_CLASS: &str = CONSENT_GRANT_BODY_KEYS[3];
const KEY_ENVELOPE: &str = CONSENT_GRANT_BODY_KEYS[4];
const KEY_STATUS: &str = CONSENT_GRANT_BODY_KEYS[5];
const KEY_OWNER_STAMP: &str = CONSENT_GRANT_BODY_KEYS[6];
const KEY_CREATED_AT: &str = CONSENT_GRANT_BODY_KEYS[7];

const OWNER_STAMP_KEYS: [&str; 3] = ["actor", "principal_ref", "decision_id"];
const SUBJECT_KEYS: [&str; 2] = ["kind", "refs"];
const ENVELOPE_KEYS: [&str; 4] = ["selectors", "target", "budget", "receipt_required"];

const DOMAIN_DISCLOSURE: &str = "disclosure";
const DOMAIN_ACTION: &str = "action";
const SUBJECT_KIND_ACTOR: &str = "actor";
const SUBJECT_KIND_AUDIENCE: &str = "audience";

/// Domain-separated BLAKE3 label for [`EffectDigest`].
const EFFECT_DIGEST_DOMAIN: &[u8] = b"oneiron.consent.effect_digest.v1\0";
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
// Catastrophe floor — invariant 7
// ---------------------------------------------------------------------------

/// Members of the closed catastrophe floor.
///
/// This set is engine-owned and **non-rememberable**: it is evaluated before
/// trust and grants, always Asks, and is rejected from standing-grant minting.
/// It is not an owner-overridable deny — the owner may still approve the op in
/// the moment, but may never make it automatic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatastropheClass {
    /// An actor raising its own ceiling.
    WidenOwnAuthority,
    /// Key rotation or recovery-path change.
    KeyRecovery,
    /// Mass or whole-vault deletion.
    VaultWideDestruction,
    /// Turning off a guard or gate.
    SecurityControlDisable,
    /// Bulk export of secrets or private scoped content.
    MassSecretExport,
}

impl CatastropheClass {
    /// The pinned stable string for receipts and reason codes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WidenOwnAuthority => "widen_own_authority",
            Self::KeyRecovery => "key_recovery",
            Self::VaultWideDestruction => "vault_wide_destruction",
            Self::SecurityControlDisable => "security_control_disable",
            Self::MassSecretExport => "mass_secret_export",
        }
    }

    /// Parses a pinned catastrophe-class string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "widen_own_authority" => Some(Self::WidenOwnAuthority),
            "key_recovery" => Some(Self::KeyRecovery),
            "vault_wide_destruction" => Some(Self::VaultWideDestruction),
            "security_control_disable" => Some(Self::SecurityControlDisable),
            "mass_secret_export" => Some(Self::MassSecretExport),
            _ => None,
        }
    }
}

// CONTRACT-EDGE: `CATASTROPHE_FLOOR_V1` is a versioned public contract
// imported across the GOV belt — adding, removing, or reordering members bumps
// `CATASTROPHE_FLOOR_VERSION` and lands as a reviewed contract change in
// consent.rs alone; the floor itself survives unchanged (catastrophe verbs sit
// outside every ⊤ per OF-453 L9).
/// Version of the closed catastrophe floor.
pub const CATASTROPHE_FLOOR_VERSION: u16 = 1;

/// The closed catastrophe floor, version 1 — the only always-gate.
pub const CATASTROPHE_FLOOR_V1: [CatastropheClass; 5] = [
    CatastropheClass::WidenOwnAuthority,
    CatastropheClass::KeyRecovery,
    CatastropheClass::VaultWideDestruction,
    CatastropheClass::SecurityControlDisable,
    CatastropheClass::MassSecretExport,
];

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/// Engine-computed digest of one composed effect.
///
/// There is no public constructor from caller bytes on the ask path: a digest
/// is derived by [`ComposedEffect::digest`] over engine-owned facts, so a
/// caller cannot forge the identity of the op an approve-once receipt covers.
/// [`EffectDigest::from_bytes`] exists only to rehydrate a digest the engine
/// already emitted (e.g. from a receipt row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EffectDigest([u8; 32]);

impl EffectDigest {
    /// Rehydrates a previously engine-emitted digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding, used in receipts and registry rows.
    #[must_use]
    pub fn to_hex(&self) -> String {
        crate::entity_id::bytes_to_hex_lower(&self.0)
    }
}

/// Store-attested proof that one approve-once marker is available to spend.
///
/// Fields are private: raw caller input cannot construct this proof. The only
/// constructor reads the marker on the write transaction that will either
/// authorize and spend the effect or abort without consuming the tap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApproveOnceAuthorization {
    effect_digest: EffectDigest,
}

// ---------------------------------------------------------------------------
// The bound — invariant 3
// ---------------------------------------------------------------------------

/// An actor subject: WHO runs the effect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActorBound {
    actor_ref: String,
    actor_class: Option<String>,
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
    members: Vec<String>,
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

    fn as_str(&self) -> &str {
        match self {
            Self::Disclosure(class) => class.as_str(),
            Self::Action(class) => class.as_str(),
        }
    }
}

/// The data envelope of a disclosure bound: WHICH entities/topics/purposes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DisclosureEnvelope {
    selectors: Vec<String>,
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
    selectors: Vec<String>,
    target: Option<String>,
    budget: Option<u64>,
    receipt_required: bool,
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

// ---------------------------------------------------------------------------
// The two domain grant types — disjoint by construction (invariant 4)
// ---------------------------------------------------------------------------

/// A standing disclosure grant: data → audience.
///
/// The inner bound is private and only constructible through
/// [`DisclosureGrant::new`], which re-checks the domain. There is no
/// conversion from an [`ActionGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DisclosureGrant {
    bound: GrantBound,
}

impl DisclosureGrant {
    /// Wraps a disclosure-domain bound.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConsentBound`] when the bound is an action bound.
    pub fn new(bound: GrantBound) -> Result<Self> {
        if bound.domain() != ConsentDomain::Disclosure {
            return Err(invalid_bound(
                "disclosure grant requires an audience/class/data-envelope bound",
            ));
        }
        Ok(Self { bound })
    }

    /// The wrapped bound.
    #[must_use]
    pub const fn bound(&self) -> &GrantBound {
        &self.bound
    }
}

/// A standing action grant: actor → verb-class → target.
///
/// The inner bound is private and only constructible through
/// [`ActionGrant::new`]. There is no conversion from a [`DisclosureGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionGrant {
    bound: GrantBound,
}

impl ActionGrant {
    /// Wraps an action-domain bound.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConsentBound`] when the bound is a disclosure
    /// bound.
    pub fn new(bound: GrantBound) -> Result<Self> {
        if bound.domain() != ConsentDomain::Action {
            return Err(invalid_bound(
                "action grant requires an actor/verb-class/target-envelope bound",
            ));
        }
        Ok(Self { bound })
    }

    /// The wrapped bound.
    #[must_use]
    pub const fn bound(&self) -> &GrantBound {
        &self.bound
    }
}

/// The domain axis of a remembered grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StandingConsentGrant {
    /// A remembered disclosure grant.
    Disclosure(DisclosureGrant),
    /// A remembered action grant.
    Action(ActionGrant),
}

impl StandingConsentGrant {
    /// Builds the standing grant matching this bound's domain.
    pub fn from_bound(bound: GrantBound) -> Result<Self> {
        match bound.domain() {
            ConsentDomain::Disclosure => Ok(Self::Disclosure(DisclosureGrant::new(bound)?)),
            ConsentDomain::Action => Ok(Self::Action(ActionGrant::new(bound)?)),
        }
    }

    /// The wrapped bound.
    #[must_use]
    pub const fn bound(&self) -> &GrantBound {
        match self {
            Self::Disclosure(grant) => grant.bound(),
            Self::Action(grant) => grant.bound(),
        }
    }

    /// The domain this grant covers.
    #[must_use]
    pub fn domain(&self) -> ConsentDomain {
        self.bound().domain()
    }
}

/// The lifetime axis: this op now, or a remembered bound.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConsentGrant {
    /// Authorizes exactly one op, identified by its engine-computed digest.
    ApproveOnce(EffectDigest),
    /// A remembered bound.
    Standing(StandingConsentGrant),
}

// ---------------------------------------------------------------------------
// Lifecycle + the persisted row
// ---------------------------------------------------------------------------

/// Lifecycle state of a persisted standing grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsentGrantStatus {
    /// Live: in-bound reuse is Auto.
    Active,
    /// Revoked: immediately fails closed on every axis.
    Revoked,
}

impl ConsentGrantStatus {
    /// The pinned on-disk status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// Parses a pinned on-disk status string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// The owner stamp carried by every persisted grant row.
///
/// It records WHICH authenticated owner decision minted the row so the
/// registry can show provenance. It holds references only — never key
/// material, a bearer token, or a credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConsentOwnerStamp {
    /// The store-truth human actor entity.
    pub actor: EntityId,
    /// The GenUI principal reference that authenticated.
    pub principal_ref: String,
    /// The Gate decision this stamp was minted under.
    pub decision_id: GateDecisionId,
}

/// One canonical standing consent-grant row.
///
/// Deliberately carries no expiry/duration field (invariant 9) and no
/// credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrantRow {
    /// The normalized bound.
    pub grant: StandingConsentGrant,
    /// Lifecycle state.
    pub status: ConsentGrantStatus,
    /// The authenticated-owner decision that minted this row.
    pub owner_stamp: ConsentOwnerStamp,
    /// Creation time in Unix seconds.
    pub created_at: u64,
}

impl ConsentGrantRow {
    /// Whether this row can authorize anything right now.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, ConsentGrantStatus::Active)
    }

    /// The stable registry reference for this row (the bound digest hex).
    #[must_use]
    pub fn grant_ref(&self) -> String {
        self.grant.bound().digest().to_hex()
    }
}

// ---------------------------------------------------------------------------
// Owner authentication — invariant 2
// ---------------------------------------------------------------------------

/// Proof that the current human owner authenticated for one decision.
///
/// Fields are private and there is no public constructor from parts: the only
/// door is [`Vault::authenticate_owner`], which requires BOTH the store-truth
/// human-actor check and the GenUI principal-authentication result. A guard, a
/// preference, a claim, or a transcript line cannot produce one, which is what
/// makes "created ONLY by the authenticated owner" a type-level fact rather
/// than a review-time promise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedOwner {
    actor: EntityId,
    principal_ref: String,
    decision_id: GateDecisionId,
}

impl AuthenticatedOwner {
    /// The authenticated human actor.
    #[must_use]
    pub const fn actor(&self) -> EntityId {
        self.actor
    }

    /// The authenticated principal reference.
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// The Gate decision this AUTHENTICATION is bound to.
    ///
    /// This is the authentication's own decision, not the decision of any act
    /// performed under it: each consent act mints its own [`GateDecisionId`]
    /// (the ledger rejects a duplicate), and the authentication id rides the
    /// grant row's owner stamp as provenance for WHICH authentication the
    /// owner acted under.
    #[must_use]
    pub const fn decision_id(&self) -> GateDecisionId {
        self.decision_id
    }

    fn stamp(&self) -> ConsentOwnerStamp {
        ConsentOwnerStamp {
            actor: self.actor,
            principal_ref: self.principal_ref.clone(),
            decision_id: self.decision_id,
        }
    }
}

// ---------------------------------------------------------------------------
// The receipt — invariant 2 ("one receipt")
// ---------------------------------------------------------------------------

/// The single receipt enum covering every consent outcome.
///
/// Approve-once and standing-grant creation/widening both land in
/// [`ConsentReceipt::Approved`], distinguished by the `grant` arm — widening is
/// a NEW owner decision minting a new `Approved`, never an edit of an existing
/// row. [`ConsentReceipt::Used`] records quiet in-bound standing reuse and
/// joins the grant row via `grant_ref` plus the exact effect digest. All four
/// project into [`GateDecisionRecord`]; there is no second receipt ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentReceipt {
    /// The owner approved: once, or by minting/widening a standing grant.
    Approved {
        decision_id: GateDecisionId,
        grant: ConsentGrant,
    },
    /// A standing grant was reused inside its bound.
    Used {
        decision_id: GateDecisionId,
        grant_ref: String,
        effect_digest: EffectDigest,
    },
    /// The owner denied this op.
    Denied {
        decision_id: GateDecisionId,
        effect_digest: EffectDigest,
    },
    /// A standing grant was revoked.
    Revoked {
        decision_id: GateDecisionId,
        grant_ref: String,
    },
}

impl ConsentReceipt {
    /// The Gate decision this receipt was recorded under.
    #[must_use]
    pub const fn decision_id(&self) -> GateDecisionId {
        match self {
            Self::Approved { decision_id, .. }
            | Self::Used { decision_id, .. }
            | Self::Denied { decision_id, .. }
            | Self::Revoked { decision_id, .. } => *decision_id,
        }
    }

    /// The pinned Gate outcome string for this receipt.
    #[must_use]
    pub const fn gate_outcome(&self) -> &'static str {
        match self {
            Self::Approved { .. } | Self::Used { .. } => "approved",
            Self::Denied { .. } => "denied",
            Self::Revoked { .. } => "revoked",
        }
    }

    /// The pinned `gate.`-namespaced reason code for this receipt.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Approved {
                grant: ConsentGrant::ApproveOnce(_),
                ..
            } => CONSENT_REASON_APPROVE_ONCE,
            Self::Approved {
                grant: ConsentGrant::Standing(_),
                ..
            } => CONSENT_REASON_STANDING_CREATED,
            Self::Used { .. } => CONSENT_REASON_STANDING_USED,
            Self::Denied { .. } => CONSENT_REASON_DENIED,
            Self::Revoked { .. } => CONSENT_REASON_REVOKED,
        }
    }

    /// The standing-grant row this receipt joins, when it has one.
    #[must_use]
    pub fn grant_ref(&self) -> Option<String> {
        match self {
            Self::Approved {
                grant: ConsentGrant::Standing(grant),
                ..
            } => Some(grant.bound().digest().to_hex()),
            Self::Used { grant_ref, .. } | Self::Revoked { grant_ref, .. } => {
                Some(grant_ref.clone())
            }
            Self::Approved {
                grant: ConsentGrant::ApproveOnce(_),
                ..
            }
            | Self::Denied { .. } => None,
        }
    }

    /// The effect/bound digest this receipt projects into `diff_handle`.
    #[must_use]
    pub fn diff_handle(&self) -> Vec<u8> {
        match self {
            Self::Approved {
                grant: ConsentGrant::ApproveOnce(digest),
                ..
            }
            | Self::Used {
                effect_digest: digest,
                ..
            }
            | Self::Denied {
                effect_digest: digest,
                ..
            } => digest.as_bytes().to_vec(),
            Self::Approved {
                grant: ConsentGrant::Standing(grant),
                ..
            } => grant.bound().digest().as_bytes().to_vec(),
            // A revoke names the row, not an op: the row ref IS the bound
            // digest, so the handle stays a digest rather than free text.
            Self::Revoked { grant_ref, .. } => grant_ref.as_bytes().to_vec(),
        }
    }
}

/// Reason code for an approve-once decision.
pub const CONSENT_REASON_APPROVE_ONCE: &str = "gate.consent.approve_once";
/// Reason code for standing-grant creation (including a widening mint).
pub const CONSENT_REASON_STANDING_CREATED: &str = "gate.consent.standing_created";
/// Reason code for quiet in-bound standing reuse.
pub const CONSENT_REASON_STANDING_USED: &str = "gate.consent.standing_used";
/// Reason code for an owner denial.
pub const CONSENT_REASON_DENIED: &str = "gate.consent.denied";
/// Reason code for a registry revoke.
pub const CONSENT_REASON_REVOKED: &str = "gate.consent.revoked";

/// The pinned Gate `content_kind` for consent-registry decisions.
pub const CONSENT_CONTENT_KIND: &str = "consent_grant";
/// The pinned Gate `actor_class` for owner-authored consent decisions.
const CONSENT_ACTOR_CLASS: &str = "human";

// ---------------------------------------------------------------------------
// The guard — invariant 5
// ---------------------------------------------------------------------------

/// What a guard may say about an effect.
///
/// A proposal is a SUGGESTION and nothing more. There is deliberately no
/// `From<ConsentProposal> for ConsentGrant`, no guard-accessible persistence
/// function, and no field here that is treated as an owner stamp — the type
/// system, not a review checklist, is what stops inference from becoming
/// authority. `confidence` may change the OFFER; it never changes authority.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsentProposal {
    /// The op the guard is proposing to remember.
    pub effect_digest: EffectDigest,
    /// The bound the guard suggests.
    pub suggested_bound: GrantBound,
    /// The guard's confidence, in `0.0..=1.0`.
    pub confidence: f32,
}

/// The type-level guard contract: propose only.
pub trait ConsentGuard {
    /// Offers a bound the owner MIGHT want to remember.
    fn propose(&self, facts: &EffectFacts) -> ConsentProposal;
}

// ---------------------------------------------------------------------------
// Host-owned reversibility classification — invariant 6
// ---------------------------------------------------------------------------

/// The reversibility verdict the HOST computes. Never caller-supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReversibilityClass {
    /// Effect-reversible: undo is the net, so the op runs automatically.
    Reversible,
    /// Irreversible in effect — an outbound send or a deploy, even though the
    /// ledger records it.
    Irreversible,
    /// A sub-axis is genuinely unknown, with no irreversible or catastrophe
    /// evidence. Biased toward Auto.
    Unknown,
}

/// The engine-owned fact set reversibility is computed from.
///
/// Every field is a FACT the host observed, not a verdict anyone asserted:
/// there is no `reversible` field here, and no public request, generated-code
/// call, connector manifest, grant, or guard proposal can inject one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EffectFacts {
    /// What kind of operation this is (e.g. `claim.put`, `channel.send`).
    pub operation_kind: String,
    /// The op fires hooks whose effects the engine does not own.
    pub fires_hooks: bool,
    /// The op triggers a publish or deploy.
    pub triggers_publish: bool,
    /// The op is observable by parties outside this vault.
    pub external_observers: bool,
    /// Whether a faithful undo exists for the op's full effect.
    pub undo_fidelity: UndoFidelity,
    /// How many entities the op mutates, cumulatively.
    pub blast_radius: u64,
    /// The catastrophe classes the host matched, if any.
    pub catastrophe: Option<CatastropheClass>,
}

impl EffectFacts {
    /// Builds a fact set for one operation kind, defaulted to the quiet,
    /// local, fully-undoable case.
    pub fn new(operation_kind: impl Into<String>) -> Result<Self> {
        Ok(Self {
            operation_kind: normalized_ref("operation kind", operation_kind.into())?,
            fires_hooks: false,
            triggers_publish: false,
            external_observers: false,
            undo_fidelity: UndoFidelity::Full,
            blast_radius: 1,
            catastrophe: None,
        })
    }

    /// Marks the op as firing engine-external hooks.
    #[must_use]
    pub const fn with_hooks(mut self, fires_hooks: bool) -> Self {
        self.fires_hooks = fires_hooks;
        self
    }

    /// Marks the op as triggering a publish or deploy.
    #[must_use]
    pub const fn with_publish_trigger(mut self, triggers_publish: bool) -> Self {
        self.triggers_publish = triggers_publish;
        self
    }

    /// Marks the op as observable outside this vault.
    #[must_use]
    pub const fn with_external_observers(mut self, external_observers: bool) -> Self {
        self.external_observers = external_observers;
        self
    }

    /// Records the host's undo-fidelity finding.
    #[must_use]
    pub const fn with_undo_fidelity(mut self, undo_fidelity: UndoFidelity) -> Self {
        self.undo_fidelity = undo_fidelity;
        self
    }

    /// Records the cumulative blast radius.
    #[must_use]
    pub const fn with_blast_radius(mut self, blast_radius: u64) -> Self {
        self.blast_radius = blast_radius;
        self
    }

    /// Records a matched catastrophe class.
    #[must_use]
    pub const fn with_catastrophe(mut self, catastrophe: CatastropheClass) -> Self {
        self.catastrophe = Some(catastrophe);
        self
    }
}

/// The host's undo-fidelity finding for one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UndoFidelity {
    /// A faithful undo exists inside the engine's own window.
    Full,
    /// Undo exists but does not restore the full effect.
    Partial,
    /// No undo exists.
    None,
    /// The host could not determine undo fidelity for this op.
    Unknown,
}

/// The blast-radius count above which an op stops being "one write".
pub const BULK_BLAST_RADIUS_FLOOR: u64 = 100;

/// Classifies the composed effect's reversibility — invariant 6.
///
/// Biased-permissive: a valid unknown sub-axis with no irreversible or
/// catastrophe evidence resolves [`ReversibilityClass::Unknown`], which the
/// evaluator treats as auto-eligible. Concrete irreversible evidence — an
/// external observer, a publish/deploy trigger, an engine-external hook, a
/// missing/partial undo, or bulk blast radius — resolves
/// [`ReversibilityClass::Irreversible`].
///
/// # Errors
///
/// Returns [`Error::InvalidConsentEffectFacts`] when a required write fact is
/// malformed (an empty operation kind), so the caller takes the invariant-8
/// domain fail-safe rather than a fabricated verdict.
pub(crate) fn classify_composed_effect(facts: &EffectFacts) -> Result<ReversibilityClass> {
    if facts.operation_kind.trim().is_empty() {
        return Err(Error::InvalidConsentEffectFacts(
            "composed effect has no operation kind",
        ));
    }
    // A catastrophe-shaped effect is irreversible regardless of undo claims;
    // the floor check runs before this in the evaluator either way.
    if facts.catastrophe.is_some() {
        return Ok(ReversibilityClass::Irreversible);
    }
    if facts.external_observers
        || facts.triggers_publish
        || facts.fires_hooks
        || facts.blast_radius >= BULK_BLAST_RADIUS_FLOOR
    {
        return Ok(ReversibilityClass::Irreversible);
    }
    Ok(match facts.undo_fidelity {
        UndoFidelity::Full => ReversibilityClass::Reversible,
        UndoFidelity::Partial | UndoFidelity::None => ReversibilityClass::Irreversible,
        // Unknown-and-NOT-irreversible-and-NOT-catastrophe: biased to auto.
        UndoFidelity::Unknown => ReversibilityClass::Unknown,
    })
}

// ---------------------------------------------------------------------------
// The composed effect + the evaluator
// ---------------------------------------------------------------------------

/// One operation as the engine composed it, ready for evaluation.
///
/// A MIXED operation — a `channel_send` of private content — carries BOTH a
/// disclosure requirement and an action requirement. The evaluator applies
/// logical AND across them: both must be covered or the op does not auto-run.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ComposedEffect {
    facts: EffectFacts,
    disclosure_requirement: Option<GrantBound>,
    action_requirement: Option<GrantBound>,
}

impl ComposedEffect {
    /// Builds a composed effect from engine-owned facts, with no requirements
    /// attached yet.
    #[must_use]
    pub const fn new(facts: EffectFacts) -> Self {
        Self {
            facts,
            disclosure_requirement: None,
            action_requirement: None,
        }
    }

    /// Attaches the disclosure requirement this op must satisfy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConsentBound`] when the bound is not a
    /// disclosure bound.
    pub fn with_disclosure_requirement(mut self, bound: GrantBound) -> Result<Self> {
        if bound.domain() != ConsentDomain::Disclosure {
            return Err(invalid_bound(
                "disclosure requirement needs a disclosure-domain bound",
            ));
        }
        self.disclosure_requirement = Some(bound);
        Ok(self)
    }

    /// Attaches the action requirement this op must satisfy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConsentBound`] when the bound is not an action
    /// bound.
    pub fn with_action_requirement(mut self, bound: GrantBound) -> Result<Self> {
        if bound.domain() != ConsentDomain::Action {
            return Err(invalid_bound(
                "action requirement needs an action-domain bound",
            ));
        }
        self.action_requirement = Some(bound);
        Ok(self)
    }

    /// The engine-owned facts.
    #[must_use]
    pub const fn facts(&self) -> &EffectFacts {
        &self.facts
    }

    /// The disclosure requirement, when this op discloses.
    #[must_use]
    pub const fn disclosure_requirement(&self) -> Option<&GrantBound> {
        self.disclosure_requirement.as_ref()
    }

    /// The action requirement, when this op acts.
    #[must_use]
    pub const fn action_requirement(&self) -> Option<&GrantBound> {
        self.action_requirement.as_ref()
    }

    /// Whether this op spans both domains.
    #[must_use]
    pub const fn is_mixed(&self) -> bool {
        self.disclosure_requirement.is_some() && self.action_requirement.is_some()
    }

    /// The catastrophe class this op matched, if any.
    #[must_use]
    pub const fn catastrophe(&self) -> Option<CatastropheClass> {
        self.facts.catastrophe
    }

    /// The domain whose fail-safe applies when classification fails.
    ///
    /// A pure disclosure op hides; anything that writes asks — invariant 8. A
    /// mixed op writes, so it asks.
    #[must_use]
    pub const fn fail_safe_domain(&self) -> ConsentDomain {
        if self.action_requirement.is_some() {
            ConsentDomain::Action
        } else if self.disclosure_requirement.is_some() {
            ConsentDomain::Disclosure
        } else {
            // A requirement-free op is still a write path by default.
            ConsentDomain::Action
        }
    }

    /// The engine-computed digest identifying this exact op.
    #[must_use]
    pub fn digest(&self) -> EffectDigest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EFFECT_DIGEST_DOMAIN);
        hash_field(&mut hasher, self.facts.operation_kind.as_bytes());
        hasher.update(&[
            u8::from(self.facts.fires_hooks),
            u8::from(self.facts.triggers_publish),
            u8::from(self.facts.external_observers),
            undo_fidelity_byte(self.facts.undo_fidelity),
        ]);
        hasher.update(&self.facts.blast_radius.to_be_bytes());
        hash_field(
            &mut hasher,
            self.facts
                .catastrophe
                .map(CatastropheClass::as_str)
                .unwrap_or_default()
                .as_bytes(),
        );
        for requirement in [&self.disclosure_requirement, &self.action_requirement] {
            match requirement {
                Some(bound) => hash_field(&mut hasher, bound.digest().as_bytes()),
                None => hash_field(&mut hasher, &[]),
            }
        }
        EffectDigest(*hasher.finalize().as_bytes())
    }
}

/// The evaluator's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsentDecision {
    /// Run it; a standing reuse also writes a quiet use receipt.
    Auto,
    /// Raise the in-moment ask.
    Ask,
    /// Withhold the disclosure (the disclosure-domain fail-safe).
    Hide,
}

/// Evaluates one composed effect against the owner's remembered state.
///
/// The order is exactly the DEC-0006 order, and each step is load-bearing:
///
/// 1. **Catastrophe first.** The closed floor is evaluated before trust and
///    grants and always Asks — no standing grant, preference, or high-trust
///    actor reaches past it (invariant 7).
/// 2. **An exact store-attested approve-once authorization, or a covering
///    standing grant.** For a mixed op, "covering" means BOTH conjuncts are
///    covered (invariant 4).
/// 3. **Host reversibility.** An effect-reversible op runs automatically —
///    undo is the net (invariant 1); classification is host-owned and
///    biased-permissive (invariant 6).
///
/// Only an irreversible, ungranted, non-catastrophe operation enters the ask
/// lane. A classification failure takes the effect's domain fail-safe
/// (invariant 8) rather than guessing.
pub(crate) fn evaluate_consent(
    effect: &ComposedEffect,
    approve_once: Option<&ApproveOnceAuthorization>,
    grants: &[StandingConsentGrant],
) -> ConsentDecision {
    // 1. The only always-gate.
    if effect.catastrophe().is_some() {
        return ConsentDecision::Ask;
    }

    // 2a. Only a store-attested, still-available approve-once marker can
    // authorize exactly this op. Raw caller-supplied digest equality is not
    // authority.
    if approve_once.is_some_and(|authorization| authorization.effect_digest == effect.digest()) {
        return ConsentDecision::Auto;
    }

    // 2b. Standing coverage. Both conjuncts must be covered for a mixed op; a
    // single-domain op needs only its own conjunct. An op carrying NO
    // requirement at all has nothing to be covered — it falls through to the
    // classifier, so an unattached IRREVERSIBLE write asks (invariant 1's
    // floor: undo is the net ONLY when the classifier says the effect is
    // reversible). A vacuous double-`None` is NOT "covered".
    let has_requirement =
        effect.disclosure_requirement().is_some() || effect.action_requirement().is_some();
    let disclosure_covered = effect
        .disclosure_requirement()
        .is_none_or(|required| covers(grants, required));
    let action_covered = effect
        .action_requirement()
        .is_none_or(|required| covers(grants, required));
    if has_requirement && disclosure_covered && action_covered {
        return ConsentDecision::Auto;
    }

    // 3. Host reversibility. Anything still ungranted rides the classifier.
    match classify_composed_effect(&effect.facts) {
        Ok(ReversibilityClass::Reversible | ReversibilityClass::Unknown) => ConsentDecision::Auto,
        Ok(ReversibilityClass::Irreversible) => {
            // An irreversible DISCLOSURE that is not covered hides; an
            // irreversible write asks.
            effect.fail_safe_domain().fail_safe()
        }
        // Malformed or absent required write facts: the invariant-8 fallback.
        Err(_) => effect.fail_safe_domain().fail_safe(),
    }
}

fn covers(grants: &[StandingConsentGrant], required: &GrantBound) -> bool {
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

// ---------------------------------------------------------------------------
// Persistence codec
// ---------------------------------------------------------------------------

/// Encodes a standing consent-grant row in canonical MessagePack key order.
pub fn encode_consent_grant_row(row: &ConsentGrantRow) -> Result<Vec<u8>> {
    let bound = row.grant.bound();
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(CONSENT_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_DOMAIN),
            Value::from(bound.domain().as_str()),
        ),
        (Value::from(KEY_SUBJECT), encode_subject(bound.subject())),
        (Value::from(KEY_CLASS), Value::from(bound.class().as_str())),
        (Value::from(KEY_ENVELOPE), encode_envelope(bound.envelope())),
        (Value::from(KEY_STATUS), Value::from(row.status.as_str())),
        (
            Value::from(KEY_OWNER_STAMP),
            encode_owner_stamp(&row.owner_stamp),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(row.created_at)),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("consent grant row MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates a standing consent-grant row.
///
/// Strict: unknown keys, duplicate keys, a wrong schema version, a crossed
/// domain triple, or a malformed ref are all rejected fail-closed.
pub fn decode_consent_grant_row(bytes: &[u8]) -> Result<ConsentGrantRow> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_row())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_row());
    }
    let Value::Map(entries) = &value else {
        return Err(invalid_row());
    };
    validate_keys(entries, &CONSENT_GRANT_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(CONSENT_GRANT_SCHEMA_VERSION) {
        return Err(invalid_row());
    }
    let domain = required_value(entries, KEY_DOMAIN)?
        .as_str()
        .and_then(ConsentDomain::parse)
        .ok_or_else(invalid_row)?;
    let subject = decode_subject(required_value(entries, KEY_SUBJECT)?, domain)?;
    let class_str = required_value(entries, KEY_CLASS)?
        .as_str()
        .ok_or_else(invalid_row)?;
    let class = match domain {
        ConsentDomain::Disclosure => {
            BoundClass::Disclosure(DisclosureClass::new(class_str).map_err(|_| invalid_row())?)
        }
        ConsentDomain::Action => {
            BoundClass::Action(ActionClass::new(class_str).map_err(|_| invalid_row())?)
        }
    };
    let envelope = decode_envelope(required_value(entries, KEY_ENVELOPE)?, domain)?;
    let status = required_value(entries, KEY_STATUS)?
        .as_str()
        .and_then(ConsentGrantStatus::parse)
        .ok_or_else(invalid_row)?;
    let owner_stamp = decode_owner_stamp(required_value(entries, KEY_OWNER_STAMP)?)?;
    let created_at = required_value(entries, KEY_CREATED_AT)?
        .as_u64()
        .ok_or_else(invalid_row)?;

    let bound = GrantBound::new(subject, class, envelope).map_err(|_| invalid_row())?;
    let grant = StandingConsentGrant::from_bound(bound).map_err(|_| invalid_row())?;
    Ok(ConsentGrantRow {
        grant,
        status,
        owner_stamp,
        created_at,
    })
}

fn encode_subject(subject: &BoundSubject) -> Value {
    let (kind, refs) = match subject {
        BoundSubject::Actor(actor) => (
            SUBJECT_KIND_ACTOR,
            vec![
                Value::from(actor.actor_ref.as_str()),
                actor.actor_class.as_deref().map_or(Value::Nil, Value::from),
            ],
        ),
        BoundSubject::Audience(audience) => (
            SUBJECT_KIND_AUDIENCE,
            audience
                .members
                .iter()
                .map(|member| Value::from(member.as_str()))
                .collect(),
        ),
    };
    Value::Map(vec![
        (Value::from(SUBJECT_KEYS[0]), Value::from(kind)),
        (Value::from(SUBJECT_KEYS[1]), Value::Array(refs)),
    ])
}

fn decode_subject(value: &Value, domain: ConsentDomain) -> Result<BoundSubject> {
    let Value::Map(entries) = value else {
        return Err(invalid_row());
    };
    validate_keys(entries, &SUBJECT_KEYS)?;
    let kind = required_value(entries, SUBJECT_KEYS[0])?
        .as_str()
        .ok_or_else(invalid_row)?;
    let Value::Array(refs) = required_value(entries, SUBJECT_KEYS[1])? else {
        return Err(invalid_row());
    };

    match (kind, domain) {
        (SUBJECT_KIND_ACTOR, ConsentDomain::Action) => {
            let [actor_ref, actor_class] = refs.as_slice() else {
                return Err(invalid_row());
            };
            let actor = ActorBound::new(actor_ref.as_str().ok_or_else(invalid_row)?)
                .map_err(|_| invalid_row())?;
            let actor = match actor_class {
                Value::Nil => actor,
                other => actor
                    .with_actor_class(other.as_str().ok_or_else(invalid_row)?)
                    .map_err(|_| invalid_row())?,
            };
            Ok(BoundSubject::Actor(actor))
        }
        (SUBJECT_KIND_AUDIENCE, ConsentDomain::Disclosure) => {
            let members = refs
                .iter()
                .map(|member| member.as_str().map(str::to_owned).ok_or_else(invalid_row))
                .collect::<Result<Vec<_>>>()?;
            Ok(BoundSubject::Audience(
                AudienceBound::new(members).map_err(|_| invalid_row())?,
            ))
        }
        // A stored subject kind that disagrees with the stored domain is a
        // crossed triple on disk: reject rather than reinterpret.
        _ => Err(invalid_row()),
    }
}

fn encode_envelope(envelope: &BoundEnvelope) -> Value {
    let (selectors, target, budget, receipt_required) = match envelope {
        BoundEnvelope::Disclosure(envelope) => (&envelope.selectors, None, None, false),
        BoundEnvelope::Action(envelope) => (
            &envelope.selectors,
            envelope.target.as_deref(),
            envelope.budget,
            envelope.receipt_required,
        ),
    };
    Value::Map(vec![
        (
            Value::from(ENVELOPE_KEYS[0]),
            Value::Array(
                selectors
                    .iter()
                    .map(|selector| Value::from(selector.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(ENVELOPE_KEYS[1]),
            target.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(ENVELOPE_KEYS[2]),
            budget.map_or(Value::Nil, Value::from),
        ),
        (Value::from(ENVELOPE_KEYS[3]), Value::from(receipt_required)),
    ])
}

fn decode_envelope(value: &Value, domain: ConsentDomain) -> Result<BoundEnvelope> {
    let Value::Map(entries) = value else {
        return Err(invalid_row());
    };
    validate_keys(entries, &ENVELOPE_KEYS)?;
    let Value::Array(raw_selectors) = required_value(entries, ENVELOPE_KEYS[0])? else {
        return Err(invalid_row());
    };
    let selectors = raw_selectors
        .iter()
        .map(|selector| selector.as_str().map(str::to_owned).ok_or_else(invalid_row))
        .collect::<Result<Vec<_>>>()?;
    let target_value = required_value(entries, ENVELOPE_KEYS[1])?;
    let budget_value = required_value(entries, ENVELOPE_KEYS[2])?;
    let receipt_required = required_value(entries, ENVELOPE_KEYS[3])?
        .as_bool()
        .ok_or_else(invalid_row)?;

    match domain {
        ConsentDomain::Disclosure => {
            // A disclosure envelope has no target, budget, or receipt
            // obligation; a row carrying one is an action envelope mislabeled.
            if !matches!(target_value, Value::Nil)
                || !matches!(budget_value, Value::Nil)
                || receipt_required
            {
                return Err(invalid_row());
            }
            Ok(BoundEnvelope::Disclosure(
                DisclosureEnvelope::new(selectors).map_err(|_| invalid_row())?,
            ))
        }
        ConsentDomain::Action => {
            let mut envelope = ActionEnvelope::new(selectors).map_err(|_| invalid_row())?;
            if !matches!(target_value, Value::Nil) {
                envelope = envelope
                    .with_target(target_value.as_str().ok_or_else(invalid_row)?)
                    .map_err(|_| invalid_row())?;
            }
            if !matches!(budget_value, Value::Nil) {
                envelope = envelope.with_budget(budget_value.as_u64().ok_or_else(invalid_row)?);
            }
            Ok(BoundEnvelope::Action(
                envelope.with_receipt_required(receipt_required),
            ))
        }
    }
}

fn encode_owner_stamp(stamp: &ConsentOwnerStamp) -> Value {
    Value::Map(vec![
        (
            Value::from(OWNER_STAMP_KEYS[0]),
            Value::from(stamp.actor.to_hex()),
        ),
        (
            Value::from(OWNER_STAMP_KEYS[1]),
            Value::from(stamp.principal_ref.as_str()),
        ),
        (
            Value::from(OWNER_STAMP_KEYS[2]),
            Value::from(stamp.decision_id.to_hex()),
        ),
    ])
}

fn decode_owner_stamp(value: &Value) -> Result<ConsentOwnerStamp> {
    let Value::Map(entries) = value else {
        return Err(invalid_row());
    };
    validate_keys(entries, &OWNER_STAMP_KEYS)?;
    let actor = EntityId::from_hex(
        required_value(entries, OWNER_STAMP_KEYS[0])?
            .as_str()
            .ok_or_else(invalid_row)?,
    )
    .map_err(|_| invalid_row())?;
    let principal_ref = normalized_ref(
        "principal_ref",
        required_value(entries, OWNER_STAMP_KEYS[1])?
            .as_str()
            .ok_or_else(invalid_row)?
            .to_owned(),
    )
    .map_err(|_| invalid_row())?;
    let decision_hex = required_value(entries, OWNER_STAMP_KEYS[2])?
        .as_str()
        .ok_or_else(invalid_row)?;
    let decision_id =
        GateDecisionId::from_bytes(hex_to_16_bytes(decision_hex).ok_or_else(invalid_row)?);
    Ok(ConsentOwnerStamp {
        actor,
        principal_ref,
        decision_id,
    })
}

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

fn outbound_scope_axes(
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

// ---------------------------------------------------------------------------
// The registry surface (invariant 9 surface (b))
// ---------------------------------------------------------------------------

/// Query for the unified consent registry — surface (b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentRegistryQuery {
    /// Maximum rows returned.
    pub limit: usize,
    /// Include revoked rows (audit view) as well as active ones.
    pub include_revoked: bool,
}

impl ConsentRegistryQuery {
    /// Builds a registry query.
    #[must_use]
    pub const fn new(limit: usize, include_revoked: bool) -> Self {
        Self {
            limit,
            include_revoked,
        }
    }
}

/// One registry row: who-can-see-what / what-can-run, with a one-tap revoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRegistryRow {
    /// The stable row reference (the bound digest hex).
    pub grant_ref: String,
    /// Which domain this row governs.
    pub domain: ConsentDomain,
    /// The subject, rendered for display.
    pub subject: String,
    /// The class, rendered for display.
    pub class: String,
    /// The envelope selectors, rendered for display.
    pub selectors: Vec<String>,
    /// Lifecycle state.
    pub status: ConsentGrantStatus,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// The one-tap revoke command the host interprets.
    pub revoke_action: ConsentRevokeAction,
}

/// The one-tap revoke command carried by every registry row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRevokeAction {
    /// Pinned command name.
    pub command: String,
    /// The row this command revokes.
    pub grant_ref: String,
}

/// Pinned one-tap revoke command for a consent registry row.
pub const CONSENT_REVOKE_COMMAND: &str = "consent.revoke_grant";

/// The unified consent registry projection — surface (b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRegistry {
    /// The rows, newest first.
    pub rows: Vec<ConsentRegistryRow>,
}

impl ConsentRegistryRow {
    fn from_row(row: &ConsentGrantRow) -> Self {
        let bound = row.grant.bound();
        let grant_ref = row.grant_ref();
        Self {
            domain: bound.domain(),
            subject: render_subject(bound.subject()),
            class: bound.class().as_str().to_owned(),
            selectors: render_selectors(bound.envelope()),
            status: row.status,
            created_at: row.created_at,
            revoke_action: ConsentRevokeAction {
                command: CONSENT_REVOKE_COMMAND.to_owned(),
                grant_ref: grant_ref.clone(),
            },
            grant_ref,
        }
    }
}

fn render_subject(subject: &BoundSubject) -> String {
    match subject {
        BoundSubject::Actor(actor) => match actor.actor_class() {
            Some(class) => format!("{}/{}", actor.actor_ref(), class),
            None => actor.actor_ref().to_owned(),
        },
        BoundSubject::Audience(audience) => audience.members().join(", "),
    }
}

fn render_selectors(envelope: &BoundEnvelope) -> Vec<String> {
    match envelope {
        BoundEnvelope::Disclosure(envelope) => envelope.selectors().to_vec(),
        BoundEnvelope::Action(envelope) => {
            let mut selectors = envelope.selectors().to_vec();
            if let Some(target) = envelope.target() {
                selectors.push(format!("target:{target}"));
            }
            if let Some(budget) = envelope.budget() {
                selectors.push(format!("budget:{budget}"));
            }
            selectors
        }
    }
}

// ---------------------------------------------------------------------------
// The Vault doors
// ---------------------------------------------------------------------------

impl Vault {
    /// Produces an [`AuthenticatedOwner`] from the independent checks DEC-0006
    /// requires: the store-truth human-actor check, the GenUI
    /// principal-authentication result, the entity's REGISTRY-ACTIVE state,
    /// and the principal↔actor binding.
    ///
    /// This is the ONLY constructor of [`AuthenticatedOwner`]. A guard, a
    /// preference, a claim, or a transcript line cannot reach it, so
    /// "owner-only minting" is an engine check rather than a UI promise.
    ///
    /// The registry-active assertion is load-bearing: a PERSON row that has
    /// been merged or split away is a redirect shell, not an owner — an
    /// `AuthenticatedOwner` minted on it would stamp grants on a dead
    /// identity. [`ActorBound::new`] then verifies the principal ref normalizes
    /// to a non-empty reference; and a hex principal ref must decode to THIS
    /// actor, so the ref that authenticated is the actor the grant lands for
    /// (no cross-actor principal substitution).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConsentOwnerNotAuthenticated`] when the principal did
    /// not authenticate, the principal ref normalizes empty, the named actor
    /// is not a store-truth human entity, the entity is registry-inactive
    /// (merged / split shell), or a hex principal ref binds to another actor.
    pub fn authenticate_owner(
        &self,
        actor: EntityId,
        principal_ref: &str,
        principal_authenticated: bool,
        decision_id: GateDecisionId,
    ) -> Result<AuthenticatedOwner> {
        if !principal_authenticated {
            return Err(Error::ConsentOwnerNotAuthenticated(
                "GenUI principal authentication did not succeed",
            ));
        }
        let principal_ref = normalized_ref("principal_ref", principal_ref.to_owned())
            .map_err(|_| Error::ConsentOwnerNotAuthenticated("principal_ref is empty"))?;
        // The ActorBound constructor is the lane's principal-shape check: an
        // unusable principal ref is a rejected authentication, not a stamped
        // grant on a malformed subject.
        ActorBound::new(principal_ref.as_str())
            .map_err(|_| Error::ConsentOwnerNotAuthenticated("principal_ref is unusable"))?;
        if !self.is_store_truth_human_actor(&actor)? {
            return Err(Error::ConsentOwnerNotAuthenticated(
                "actor is not a store-truth human entity",
            ));
        }
        // Registry-active: a merged or split shell is a redirect, not an
        // owner. The topology fold fails closed.
        match self
            .entity_lifecycle_state(&actor)
            .map_err(|_| Error::ConsentOwnerNotAuthenticated("actor lifecycle is unreadable"))?
        {
            crate::identity_topology::EntityLifecycleState::Active => {}
            crate::identity_topology::EntityLifecycleState::Merged
            | crate::identity_topology::EntityLifecycleState::Split => {
                return Err(Error::ConsentOwnerNotAuthenticated(
                    "actor is registry-inactive (merged/split shell), not an owner",
                ));
            }
        }
        // A hex principal ref is an entity reference: it must decode to THIS
        // actor, or the authenticated principal and the minted grant would
        // name different actors.
        if let Ok(principal_id) = EntityId::from_hex(principal_ref.as_str())
            && principal_id != actor
        {
            return Err(Error::ConsentOwnerNotAuthenticated(
                "principal_ref binds to a different actor entity",
            ));
        }
        Ok(AuthenticatedOwner {
            actor,
            principal_ref,
            decision_id,
        })
    }

    fn is_store_truth_human_actor(&self, actor: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, actor.as_bytes())? else {
            return Ok(false);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(header.entity_type == crate::registry::ENTITY_TYPE_PERSON)
    }

    /// Approves exactly one pending operation, identified by its exact
    /// engine-computed digest.
    ///
    /// Consumes only that digest: an approve-once receipt authorizes this op,
    /// now, and covers no other op and no future op. It mints no standing row.
    /// The mint is REPLAY-REJECTED: a spent marker keyed by the digest is
    /// claimed in the SAME write transaction as the receipt, so a second
    /// `approve_once` over the same digest — the owner re-tapping an
    /// already-answered ask, or a replayed digest — is refused with
    /// [`Error::ConsentApproveOnceSpent`]. LMDB serializes writers, so a
    /// concurrent mint sees the committed marker and rolls back.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConsentApproveOnceSpent`] when the digest was already
    /// approved, and [`Error::ConsentOwnerNotAuthenticated`] transitively
    /// from the owner-stamp check.
    pub fn approve_once(
        &self,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        let decision_id = GateDecisionId::now();
        self.claim_approve_once_in_txn(&mut wtxn, &effect_digest, decision_id)?;
        let receipt = ConsentReceipt::Approved {
            decision_id,
            grant: ConsentGrant::ApproveOnce(effect_digest),
        };
        self.append_consent_receipt_in_txn(&mut wtxn, owner, &receipt)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Claims the approve-once slot for `digest` inside `wtxn`, or fails when
    /// any marker already exists. The available marker carries the approving
    /// [`GateDecisionId`], so a contested mint names its evidence; delivery
    /// preserves that id while atomically changing the state to spent. LMDB
    /// serializes writers, so two racing mints cannot both win.
    fn claim_approve_once_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        digest: &EffectDigest,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        let key = consent_approve_once_key(digest);
        if self.store.vault_meta.get(&*wtxn, &key)?.is_some() {
            return Err(Error::ConsentApproveOnceSpent(
                "this op digest already carries an approve-once receipt",
            ));
        }
        let marker = encode_approve_once_marker(CONSENT_APPROVE_ONCE_AVAILABLE, decision_id);
        self.store.vault_meta.put(wtxn, &key, &marker)?;
        Ok(())
    }

    /// The ONLY persistence door for a standing consent grant.
    ///
    /// Requires an [`AuthenticatedOwner`], rejects catastrophe-class bounds
    /// (the floor is non-rememberable — invariant 7), and writes the row and
    /// its Gate receipt in ONE transaction. Reuse never mutates a bound: a
    /// wider bound is a NEW owner decision that lands as a NEW row with its
    /// own receipt, which is also what "approve-and-stop-asking on a
    /// scope-exceed ask" mints.
    pub fn create_standing_grant(
        &self,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn(|wtxn| self.create_standing_grant_in_txn(wtxn, owner, bound))
    }

    /// Transaction-composable [`Vault::create_standing_grant`].
    ///
    /// Exists so a caller whose PRECONDITION must hold at mint time can test
    /// it in the same transaction that writes the row: ONE-1748's graduation
    /// tap reads the scope's ramp posture here, so a stale tap cannot overtake
    /// the demotion that retracted the offer it is answering.
    pub(crate) fn create_standing_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
    ) -> Result<ConsentReceipt> {
        if bound_catastrophe_class(&bound).is_some() {
            return Err(Error::ConsentCatastropheNotRememberable(
                "the catastrophe floor is non-rememberable; no standing grant may cover it",
            ));
        }
        let grant = StandingConsentGrant::from_bound(bound)?;
        let row = ConsentGrantRow {
            grant: grant.clone(),
            status: ConsentGrantStatus::Active,
            owner_stamp: owner.stamp(),
            created_at: crate::unix_seconds_now(),
        };
        let receipt = ConsentReceipt::Approved {
            decision_id: GateDecisionId::now(),
            grant: ConsentGrant::Standing(grant),
        };

        let key = consent_grant_key(&row.grant_ref());
        let data = encode_consent_grant_row(&row)?;
        // Re-minting an identical bound is the owner re-affirming it; the row
        // is idempotent, and the receipt is still written so the act is
        // audit-visible.
        self.store.vault_meta.put(wtxn, &key, &data)?;
        self.append_consent_receipt_in_txn(wtxn, owner, &receipt)?;
        Ok(receipt)
    }

    /// Denies one pending operation, recording the refusal in the receipt
    /// family so a denial is as legible as an approval.
    pub fn deny_consent(
        &self,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let receipt = ConsentReceipt::Denied {
            decision_id: GateDecisionId::now(),
            effect_digest,
        };
        let mut wtxn = self.store.env.write_txn()?;
        self.append_consent_receipt_in_txn(&mut wtxn, owner, &receipt)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Revokes a standing grant. Revocation is immediate: the row flips to
    /// [`ConsentGrantStatus::Revoked`] in the same transaction as its receipt,
    /// so no in-flight read can observe a revoked row as live.
    pub fn revoke_consent_grant(
        &self,
        owner: &AuthenticatedOwner,
        grant_ref: &str,
    ) -> Result<ConsentReceipt> {
        let key = consent_grant_key(grant_ref);
        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw) = self.store.vault_meta.get(&wtxn, &key)? else {
            return Err(Error::ConsentGrantNotFound);
        };
        let mut row = decode_consent_grant_row(&raw)?;
        row.status = ConsentGrantStatus::Revoked;
        let data = encode_consent_grant_row(&row)?;
        self.store.vault_meta.put(&mut wtxn, &key, &data)?;
        let receipt = ConsentReceipt::Revoked {
            decision_id: GateDecisionId::now(),
            grant_ref: grant_ref.to_owned(),
        };
        self.append_consent_receipt_in_txn(&mut wtxn, owner, &receipt)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Records quiet in-bound standing reuse — the post-hoc receipt an owner
    /// sees for an auto-shared facet or an auto-run action.
    ///
    /// The reuse itself is authorized by [`evaluate_consent`]; this door only
    /// records it, and never widens or touches the grant row.
    pub fn record_standing_grant_use(
        &self,
        grant_ref: &str,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let key = consent_grant_key(grant_ref);
        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw) = self.store.vault_meta.get(&wtxn, &key)? else {
            return Err(Error::ConsentGrantNotFound);
        };
        let row = decode_consent_grant_row(&raw)?;
        if !row.is_active() {
            return Err(Error::ConsentGrantRevoked);
        }
        let receipt = ConsentReceipt::Used {
            decision_id: GateDecisionId::now(),
            grant_ref: grant_ref.to_owned(),
            effect_digest,
        };
        self.append_consent_gate_decision_in_txn(&mut wtxn, &row.owner_stamp, &receipt)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Reads one standing consent-grant row.
    pub fn consent_grant(&self, grant_ref: &str) -> Result<Option<ConsentGrantRow>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &consent_grant_key(grant_ref))?
        else {
            return Ok(None);
        };
        decode_consent_grant_row(&raw).map(Some)
    }

    /// Every ACTIVE standing grant, for the evaluator.
    ///
    /// Revoked rows are filtered here rather than at the call site so a
    /// revocation is immediate for every consumer.
    pub fn active_standing_consent_grants(&self) -> Result<Vec<StandingConsentGrant>> {
        let rtxn = self.store.env.read_txn()?;
        self.active_standing_consent_grants_in_txn(&rtxn)
    }

    /// Transaction-composable [`Vault::active_standing_consent_grants`].
    ///
    /// Reads on the caller's transaction (read or write — an `RwTxn`
    /// derefs here), so a door composing the consent context INSIDE its own
    /// write txn sees the same snapshot the enclosing commit is decided on.
    pub fn active_standing_consent_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<StandingConsentGrant>> {
        load_active_standing_grants(&self.store, txn)
    }

    /// The DEC-0006 door: evaluates one composed effect against the owner's
    /// current remembered state and returns both the verdict and the Gate
    /// reason codes that explain it.
    ///
    /// This is what a write door calls to opt onto the unified consent path.
    /// It loads the ACTIVE grants itself, so a caller cannot pass a stale or
    /// hand-picked grant set, and it routes through the one evaluator, so no
    /// door re-implements the ladder. `pending_approve_once` is the exact
    /// engine-emitted digest of an approve-once receipt already in hand for this
    /// op, if any. Digest equality alone is not authority: this door reads the
    /// marker, evaluates the ladder, and changes an admitted marker to spent in
    /// one write transaction. A replay is refused before another `Auto` can be
    /// returned.
    ///
    /// The returned reason codes are empty exactly when the verdict is
    /// [`ConsentDecision::Auto`].
    pub fn evaluate_consent_for(
        &self,
        effect: &ComposedEffect,
        pending_approve_once: Option<&EffectDigest>,
    ) -> Result<ConsentEvaluation> {
        let mut wtxn = self.store.env.write_txn()?;
        let grants = self.active_standing_consent_grants_in_txn(&wtxn)?;
        let approve_once = pending_approve_once
            .map(|digest| approve_once_authorization_in_txn(&self.store, &wtxn, digest))
            .transpose()?
            .flatten();
        let context =
            crate::gate::ConsentGateContext::evaluate(effect, approve_once.as_ref(), &grants);
        if context.decision == ConsentDecision::Auto
            && let Some(authorization) = approve_once.as_ref()
        {
            spend_approve_once_in_txn(&self.store, &mut wtxn, authorization)?;
        }
        let evaluation = ConsentEvaluation {
            decision: context.decision,
            reason_codes: crate::gate::consent_gate_reason_codes(&context),
        };
        wtxn.commit()?;
        Ok(evaluation)
    }

    /// The unified consent registry — surface (b) of invariant 9.
    ///
    /// Review and one-tap revoke for BOTH domains in one place. There is no
    /// third surface and no settings screen: the in-moment ask (`genui.rs`) is
    /// surface (a), and this is surface (b).
    pub fn consent_registry(&self, query: ConsentRegistryQuery) -> Result<ConsentRegistry> {
        let mut rows: Vec<ConsentRegistryRow> = self
            .consent_grant_rows()?
            .iter()
            .filter(|row| query.include_revoked || row.is_active())
            .map(ConsentRegistryRow::from_row)
            .collect();
        rows.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.grant_ref.cmp(&right.grant_ref))
        });
        rows.truncate(query.limit);
        Ok(ConsentRegistry { rows })
    }

    fn consent_grant_rows(&self) -> Result<Vec<ConsentGrantRow>> {
        let rtxn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, CONSENT_GRANT_KEY_PREFIX)?
        {
            let (_, value) = entry?;
            rows.push(decode_consent_grant_row(&value)?);
        }
        Ok(rows)
    }

    fn append_consent_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        receipt: &ConsentReceipt,
    ) -> Result<()> {
        self.append_consent_gate_decision_in_txn(wtxn, &owner.stamp(), receipt)
    }

    /// Projects a [`ConsentReceipt`] into the existing Gate receipt family.
    ///
    /// `diff_handle` holds the effect/bound digest and `grant_ref` joins
    /// standing use, exactly as every other Gate receipt does — no second
    /// receipt ledger is minted.
    fn append_consent_gate_decision_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        stamp: &ConsentOwnerStamp,
        receipt: &ConsentReceipt,
    ) -> Result<()> {
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: receipt.decision_id(),
            created_at: crate::unix_seconds_now(),
            outcome: receipt.gate_outcome().to_owned(),
            reason_codes: vec![receipt.reason_code().to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: CONSENT_ACTOR_CLASS.to_owned(),
            actor_ref: Some(stamp.actor.to_hex()),
            content_kind: CONSENT_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: receipt.grant_ref(),
            diff_handle: receipt.diff_handle(),
            read_frontier_hash: [0_u8; 32],
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(wtxn, &record)
    }
}

/// One consent verdict plus the Gate reason codes that explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentEvaluation {
    /// The evaluator's verdict.
    pub decision: ConsentDecision,
    /// Stable `gate.`-namespaced pending reason codes; empty iff `decision`
    /// is [`ConsentDecision::Auto`].
    pub reason_codes: Vec<String>,
}

/// The catastrophe class a bound would cover, if any.
///
/// Used to reject catastrophe bounds from standing-grant minting. The match is
/// on the bound's action class against the closed floor's pinned strings, so
/// adding a floor member automatically extends the rejection.
#[must_use]
pub fn bound_catastrophe_class(bound: &GrantBound) -> Option<CatastropheClass> {
    let class = bound.class().as_str();
    CATASTROPHE_FLOOR_V1
        .into_iter()
        .find(|catastrophe| catastrophe.as_str() == class)
}

/// Every ACTIVE standing grant, read on the caller's transaction.
///
/// This is the `Store`-level projection a write door (which holds the store
/// and its in-flight write txn, not the `Vault`) uses to compose a
/// [`crate::gate::ConsentGateContext`]. Reading on the SAME transaction the
/// enclosing commit rides on keeps a revocation inside that txn visible to
/// the verdict.
///
/// Revoked rows are filtered here rather than at the call site so a
/// revocation is immediate for every consumer — the `RoTxn` bound accepts a
/// `&RwTxn` by deref.
pub fn load_active_standing_grants(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<StandingConsentGrant>> {
    let mut grants = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(txn, CONSENT_GRANT_KEY_PREFIX)?
    {
        let (_, value) = entry?;
        let row = decode_consent_grant_row(&value)?;
        if row.is_active() {
            grants.push(row.grant);
        }
    }
    Ok(grants)
}

/// Whether one standing grant row exists and is live, on the caller's
/// transaction.
///
/// The consent registry is the single truth for "is this bound graduated": a
/// consumer that needs the answer reads THIS row rather than keeping a second
/// copy that could disagree with it (ONE-1748's ramp derives
/// [`crate::consent_graduation::RampState`] here).
pub(crate) fn standing_grant_is_active_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    grant_ref: &str,
) -> Result<bool> {
    let Some(raw) = store.vault_meta.get(txn, &consent_grant_key(grant_ref))? else {
        return Ok(false);
    };
    Ok(decode_consent_grant_row(&raw)?.is_active())
}

/// Flips one standing grant to [`ConsentGrantStatus::Revoked`] inside the
/// caller's write transaction, reporting whether a live row was actually
/// revoked.
///
/// Deliberately owner-free, unlike [`Vault::revoke_consent_grant`]: REDUCING
/// authority is safe for anyone to do, and only GRANTING requires an
/// [`AuthenticatedOwner`]. The caller owns the receipt — this door writes none,
/// so an engine-side self-demotion records exactly one act (ONE-1748) instead
/// of a revocation receipt and a demotion receipt describing the same event.
pub(crate) fn revoke_standing_grant_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant_ref: &str,
) -> Result<bool> {
    let key = consent_grant_key(grant_ref);
    let Some(raw) = store.vault_meta.get(&*wtxn, &key)? else {
        return Ok(false);
    };
    let mut row = decode_consent_grant_row(&raw)?;
    if !row.is_active() {
        return Ok(false);
    }
    row.status = ConsentGrantStatus::Revoked;
    let data = encode_consent_grant_row(&row)?;
    store.vault_meta.put(wtxn, &key, &data)?;
    Ok(true)
}

/// Reads one approve-once marker from the caller's transaction.
///
/// An available marker yields an unforgeable authorization. A spent marker is
/// a replay and fails typed. Absence yields `None`, so a caller-supplied digest
/// with no receipt never reaches the evaluator's approve-once `Auto` arm.
pub(crate) fn approve_once_authorization_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    digest: &EffectDigest,
) -> Result<Option<ApproveOnceAuthorization>> {
    let key = consent_approve_once_key(digest);
    let Some(raw) = store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let (state, _) = decode_approve_once_marker(&raw)?;
    match state {
        CONSENT_APPROVE_ONCE_AVAILABLE => Ok(Some(ApproveOnceAuthorization {
            effect_digest: *digest,
        })),
        CONSENT_APPROVE_ONCE_SPENT => Err(Error::ConsentApproveOnceSpent(
            "this approve-once authorization already delivered its effect",
        )),
        _ => Err(Error::CorruptedIndex("consent approve-once marker state")),
    }
}

/// Changes one store-attested approve-once marker to spent in `wtxn`.
///
/// The caller performs this only when the enclosing authorization is `Auto`.
/// Because the state transition shares the effect's write transaction, aborting
/// that transaction restores the available tap; committing it makes every
/// replay fail before authorization.
pub(crate) fn spend_approve_once_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    authorization: &ApproveOnceAuthorization,
) -> Result<()> {
    let key = consent_approve_once_key(&authorization.effect_digest);
    let Some(raw) = store.vault_meta.get(&*wtxn, &key)? else {
        return Err(Error::ConsentApproveOnceSpent(
            "approve-once authorization has no live marker",
        ));
    };
    let (state, decision_id) = decode_approve_once_marker(&raw)?;
    if state == CONSENT_APPROVE_ONCE_SPENT {
        return Err(Error::ConsentApproveOnceSpent(
            "this approve-once authorization already delivered its effect",
        ));
    }
    if state != CONSENT_APPROVE_ONCE_AVAILABLE {
        return Err(Error::CorruptedIndex("consent approve-once marker state"));
    }
    let marker = encode_approve_once_marker(CONSENT_APPROVE_ONCE_SPENT, decision_id);
    store.vault_meta.put(wtxn, &key, &marker)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn encode_approve_once_marker(state: u8, decision_id: GateDecisionId) -> [u8; 18] {
    let mut marker = [0_u8; CONSENT_APPROVE_ONCE_MARKER_LEN];
    marker[0] = CONSENT_APPROVE_ONCE_MARKER_VERSION;
    marker[1] = state;
    marker[2..].copy_from_slice(&decision_id.as_bytes());
    marker
}

fn decode_approve_once_marker(raw: &[u8]) -> Result<(u8, GateDecisionId)> {
    if raw.len() != CONSENT_APPROVE_ONCE_MARKER_LEN || raw[0] != CONSENT_APPROVE_ONCE_MARKER_VERSION
    {
        return Err(Error::CorruptedIndex("consent approve-once marker"));
    }
    let decision_id = GateDecisionId::from_bytes(
        raw[2..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("consent approve-once marker"))?,
    );
    Ok((raw[1], decision_id))
}

fn consent_approve_once_key(digest: &EffectDigest) -> Vec<u8> {
    let mut key = Vec::with_capacity(CONSENT_APPROVE_ONCE_KEY_PREFIX.len() + 32);
    key.extend_from_slice(CONSENT_APPROVE_ONCE_KEY_PREFIX);
    key.extend_from_slice(digest.as_bytes());
    key
}

fn consent_grant_key(grant_ref: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(CONSENT_GRANT_KEY_PREFIX.len() + grant_ref.len());
    key.extend_from_slice(CONSENT_GRANT_KEY_PREFIX);
    key.extend_from_slice(grant_ref.as_bytes());
    key
}

fn normalized_ref(label: &'static str, value: String) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidConsentBound(label));
    }
    if trimmed.len() > MAX_CONSENT_REF_LEN {
        return Err(Error::InvalidConsentBound(label));
    }
    Ok(trimmed.to_owned())
}

fn normalized_selectors(selectors: impl IntoIterator<Item = String>) -> Result<Vec<String>> {
    let mut selectors = selectors
        .into_iter()
        .map(|selector| normalized_ref("envelope selector", selector))
        .collect::<Result<Vec<_>>>()?;
    selectors.sort_unstable();
    selectors.dedup();
    if selectors.is_empty() {
        return Err(invalid_bound(
            "envelope has no selectors; an empty envelope is not a bound",
        ));
    }
    if selectors.len() > MAX_ENVELOPE_SELECTORS {
        return Err(invalid_bound("envelope exceeds the selector cap"));
    }
    Ok(selectors)
}

/// Selector containment over two sorted, deduped sets.
fn selectors_contain(bound: &[String], candidate: &[String]) -> bool {
    candidate
        .iter()
        .all(|selector| bound.binary_search(selector).is_ok())
}

/// Length-prefixed field hashing, so `["ab","c"]` and `["a","bc"]` never
/// collide into the same digest.
fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

const fn undo_fidelity_byte(fidelity: UndoFidelity) -> u8 {
    match fidelity {
        UndoFidelity::Full => 0,
        UndoFidelity::Partial => 1,
        UndoFidelity::None => 2,
        UndoFidelity::Unknown => 3,
    }
}

fn hex_to_16_bytes(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_row)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_row());
        };
        if seen[index] {
            return Err(invalid_row());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err(invalid_row())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_row)
}

const fn invalid_bound(message: &'static str) -> Error {
    Error::InvalidConsentBound(message)
}

const fn invalid_row() -> Error {
    Error::InvalidConsentGrantRow("body failed validation")
}

#[cfg(test)]
mod tests;
