use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::GateDecisionId;

use super::bound::{ConsentDomain, GrantBound};
use super::effect::{EffectDigest, EffectFacts};
use super::support::invalid_bound;

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
    ///
    /// [`Error::InvalidConsentBound`]: crate::error::Error::InvalidConsentBound
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
    ///
    /// [`Error::InvalidConsentBound`]: crate::error::Error::InvalidConsentBound
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
///
/// [`GateDecisionRecord`]: crate::store::GateDecisionRecord
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
