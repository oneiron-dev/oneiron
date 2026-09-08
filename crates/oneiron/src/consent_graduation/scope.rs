//! RampScope domain type: tuple validation, key/grant derivation, ramp eligibility gate.

use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::entity_id::ENTITY_ID_LEN;
use crate::error::{Error, Result};
use crate::identity_topology::{ProposalScope, is_identity_topology_op_kind};

/// Domain separator for the scope handle digest.
const RAMP_SCOPE_DIGEST_DOMAIN: &[u8] = b"oneiron.consent_graduation.scope.v1";

/// Per-field cap on a scope tuple field, matching
/// [`crate::consent::MAX_CONSENT_REF_LEN`] so a scope that validates here also
/// converts to a [`GrantBound`] without a second, looser gate.
const MAX_RAMP_SCOPE_FIELD_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN;

/// The compiled default streak floor: this many consecutive approved-untouched
/// rulings in one scope are the repetition half of a graduation offer.
///
/// Since ED-05 (ONE-1761) this is the streak axis of the catch-all row in
/// [`crate::edit_distance::graduation`]'s threshold table, where it is paired
/// with [`crate::edit_distance::graduation::DEFAULT_POSTERIOR_GUARD`]. The two
/// are co-designed: a SPOTLESS twelve-approval streak clears that guard and a
/// twelve-approval streak with corrections behind it does not.
pub const DEFAULT_GRADUATION_STREAK_FLOOR: u32 = 12;

/// The DEC-0006 bound tuple the ramp keys on: (op kind × target class ×
/// actor).
///
/// Identical to the [`ProposalScope`] MS-05 stamps on every proposal-outcome
/// receipt — deliberately, so a receipts-alone rebuild needs no ledger join.
///
/// `actor` is a `String` rather than an `EntityId` because the slot is
/// genuinely wider than an entity: a proposal that bound no actor stamps
/// [`crate::identity_topology::PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED`], and the
/// DEC-0006 actor axis names skills and agents that have no entity row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RampScope {
    /// The op's wire kind (`"merge"`, `"send_email"`, …).
    pub op_kind: String,
    /// The class of thing the op targets (`"PERSON"`, `"client_followup"`, …).
    pub target_class: String,
    /// The acting skill/agent reference whose autonomy the ramp measures.
    pub actor: String,
}

impl RampScope {
    /// Builds a scope from its tuple, normalizing each field (trim, reject
    /// empty, cap length) so two spellings of one scope cannot key apart.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when a field is empty or oversized.
    pub fn new(
        op_kind: impl Into<String>,
        target_class: impl Into<String>,
        actor: impl Into<String>,
    ) -> Result<Self> {
        let (op_kind, target_class, actor) = (op_kind.into(), target_class.into(), actor.into());
        Ok(Self {
            op_kind: normalized_scope_field(SCOPE_OP_KIND_LABEL, &op_kind)?.to_owned(),
            target_class: normalized_scope_field(SCOPE_TARGET_CLASS_LABEL, &target_class)?
                .to_owned(),
            actor: normalized_scope_field(SCOPE_ACTOR_LABEL, &actor)?.to_owned(),
        })
    }

    /// Re-checks the tuple [`RampScope::new`] would have produced.
    ///
    /// The fields are `pub` (ED-05 builds scopes from its own policy rows), so
    /// [`RampScope::new`] is a door, not a gate: a caller may assemble a tuple
    /// that is empty, oversized, or merely un-normalized — and an
    /// un-normalized twin keys to a DIFFERENT row than the scope it names.
    /// Every mutating door runs this before its first write, so an unbuildable
    /// tuple can never leave a committed row behind for the all-scopes scan to
    /// choke on.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when a field is empty, oversized, or
    /// carries surrounding whitespace.
    pub fn validate(&self) -> Result<()> {
        for (label, value) in [
            (SCOPE_OP_KIND_LABEL, &self.op_kind),
            (SCOPE_TARGET_CLASS_LABEL, &self.target_class),
            (SCOPE_ACTOR_LABEL, &self.actor),
        ] {
            if normalized_scope_field(label, value)? != value.as_str() {
                return Err(Error::InvalidConsentBound(label));
            }
        }
        Ok(())
    }

    /// The deterministic 16-byte storage handle for this tuple.
    ///
    /// Length-prefixed field hashing, so `("a", "bc", …)` and `("ab", "c", …)`
    /// cannot collide by concatenation.
    #[must_use]
    pub fn key(&self) -> [u8; ENTITY_ID_LEN] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(RAMP_SCOPE_DIGEST_DOMAIN);
        for field in [&self.op_kind, &self.target_class, &self.actor] {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field.as_bytes());
        }
        let mut key = [0_u8; ENTITY_ID_LEN];
        key.copy_from_slice(&hasher.finalize().as_bytes()[..ENTITY_ID_LEN]);
        key
    }

    /// The DEC-0006 action bound this scope graduates into: the actor is the
    /// subject, the op kind is the verb class, and the target class is the
    /// envelope's single selector.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when a field cannot be a bound axis.
    pub fn to_grant_bound(&self) -> Result<GrantBound> {
        GrantBound::action(
            ActorBound::new(self.actor.clone())?,
            ActionClass::new(self.op_kind.clone())?,
            ActionEnvelope::new([self.target_class.clone()])?,
        )
    }

    /// The consent registry reference of this scope's grant — the bound
    /// digest, so a grant the owner minted through the plain
    /// [`Vault::create_standing_grant`] door is the SAME row this module reads.
    /// There is no second bookkeeping table to drift.
    ///
    /// # Errors
    ///
    /// Propagates [`RampScope::to_grant_bound`].
    pub fn grant_ref(&self) -> Result<String> {
        Ok(self.to_grant_bound()?.digest().to_hex())
    }

    /// Whether this scope may ever graduate — see [`op_kind_is_ramp_eligible`].
    #[must_use]
    pub fn is_graduatable(&self) -> bool {
        op_kind_is_ramp_eligible(&self.op_kind)
    }
}

impl From<&ProposalScope> for RampScope {
    fn from(scope: &ProposalScope) -> Self {
        Self {
            op_kind: scope.op_kind.to_owned(),
            target_class: scope.target_class.clone(),
            actor: scope.actor.clone(),
        }
    }
}

/// Whether an op kind sits on the propose→auto ramp at all.
///
/// FALSE for the identity-topology family. Those ops are AUTO day one (MS-01
/// r3) and carry their own per-write consent axis, so there is no propose lane
/// for the ramp to let anyone skip: graduating one would be authority the ramp
/// invented rather than authority the owner ever withheld. The ramp is the exit
/// path for scopes that honestly START at propose — external effects,
/// cross-person reach, tinkerer dials.
#[must_use]
pub fn op_kind_is_ramp_eligible(op_kind: &str) -> bool {
    !is_identity_topology_op_kind(op_kind)
}

const SCOPE_OP_KIND_LABEL: &str = "ramp scope op kind";

const SCOPE_TARGET_CLASS_LABEL: &str = "ramp scope target class";

const SCOPE_ACTOR_LABEL: &str = "ramp scope actor";

fn normalized_scope_field<'a>(label: &'static str, value: &'a str) -> Result<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_RAMP_SCOPE_FIELD_LEN {
        return Err(Error::InvalidConsentBound(label));
    }
    Ok(trimmed)
}
