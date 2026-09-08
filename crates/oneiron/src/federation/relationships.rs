//! Member-to-person binding, label trust classes, and relationship claim doors.

use rmpv::Value;

use super::codec::decode_canonical_entity_ref;
use super::pact_scope::SelectorRange;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// CLAIM predicate binding a grant's `member_ref` to a PERSON entity.
///
/// Deliberately NOT in `CLAIM_PREDICATE_REGISTRY`: the registry is the
/// crate-owned STRUCTURAL schema list, and the generic claim door already
/// accepts a well-formed non-structural predicate. Registering these two would
/// claim a validator seat neither of them needs.
pub const PREDICATE_RELATIONSHIP_PERSON_REF: &str = "core.relationship.person_ref";

/// CLAIM predicate labelling a PERSON entity with a relationship word.
pub const PREDICATE_RELATIONSHIP_LABEL: &str = "core.relationship.label";

/// Maximum byte length of a relationship label.
///
/// The label grammar is ASCII-only, so this bounds the character count too.
pub const MAX_RELATIONSHIP_LABEL_BYTES: usize = 64;

/// Trust class a relationship label resolves to.
///
/// The word lists are FIXED: there is no Unicode folding and no synonym model,
/// so an unrecognized but well-formed label lands on [`Self::Unlabeled`] rather
/// than being guessed into a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelationshipTrustClass {
    /// Partner-grade closeness.
    Intimate,
    /// Blood or household family.
    Family,
    /// Chosen personal closeness.
    Friend,
    /// Work relationships inside one's own org.
    Professional,
    /// Commercial counterparties.
    Client,
    /// Bound to a person, but with no label in the fixed table.
    Unlabeled,
}

/// Resolved label context for a member bound to a PERSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRelationshipContext {
    /// PERSON entity the member is bound to.
    pub person: EntityId,
    /// Winning label, stored verbatim.
    pub label: String,
    /// CLAIM entity the winning label came from.
    pub label_claim: EntityId,
    /// Trust class [`relationship_trust_class`] maps `label` to.
    pub trust_class: RelationshipTrustClass,
}

/// Relationship state of a federation grant's `member_ref`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberRelationship {
    /// Bound to a person carrying a valid label.
    Labeled(MemberRelationshipContext),
    /// Bound to a person with no valid label claim.
    Unlabeled {
        /// PERSON entity the member is bound to.
        person: EntityId,
    },
    /// No valid person binding.
    Unbound,
}

/// Resolves the relationship a grant's `member_ref` carries.
///
/// Deterministic and agent-independent by construction: the signature takes no
/// actor, so two agent contexts reading the same vault state get the same
/// answer. Person binding wins by (learned_at, claim id) descending; the label
/// on the bound person then prefers Approved over Auto REGARDLESS OF AGE,
/// falling back to (learned_at, claim id) descending. Proposed, Rejected,
/// non-Active, and malformed claims never enter either contest.
///
/// This reads only `member_ref`, so it is total over every
/// [`FederationGrantRole`] — a Delegate resolves exactly like an Owner.
pub fn resolve_member_relationship(
    vault: &Vault,
    member_ref: EntityId,
) -> Result<MemberRelationship> {
    let person = relationship_claims(
        vault,
        member_ref,
        PREDICATE_RELATIONSHIP_PERSON_REF,
        |value| decode_canonical_entity_ref(value).ok(),
    )?
    .into_iter()
    .max_by_key(|claim| (claim.learned_at, claim.claim))
    .map(|claim| claim.payload);

    let Some(person) = person else {
        return Ok(MemberRelationship::Unbound);
    };

    let label = relationship_claims(vault, person, PREDICATE_RELATIONSHIP_LABEL, |value| {
        let label = value.as_str()?;
        is_relationship_label(label).then(|| label.to_owned())
    })?
    .into_iter()
    .max_by_key(|claim| (claim.approved, claim.learned_at, claim.claim));

    let Some(label) = label else {
        return Ok(MemberRelationship::Unlabeled { person });
    };

    let trust_class = relationship_trust_class(&label.payload);
    Ok(MemberRelationship::Labeled(MemberRelationshipContext {
        person,
        label: label.payload,
        label_claim: label.claim,
        trust_class,
    }))
}

/// Maps a relationship label to its trust class.
///
/// The word lists are the pinned table; anything else is
/// [`RelationshipTrustClass::Unlabeled`].
#[must_use]
pub fn relationship_trust_class(label: &str) -> RelationshipTrustClass {
    match label {
        "girlfriend" | "boyfriend" | "partner" | "wife" | "husband" | "spouse" => {
            RelationshipTrustClass::Intimate
        }
        "mother" | "father" | "mom" | "dad" | "parent" | "brother" | "sister" | "sibling"
        | "son" | "daughter" | "family" => RelationshipTrustClass::Family,
        "friend" | "roommate" => RelationshipTrustClass::Friend,
        "coworker" | "colleague" | "manager" | "report" | "boss" | "teammate" => {
            RelationshipTrustClass::Professional
        }
        "client" | "customer" | "vendor" | "contractor" => RelationshipTrustClass::Client,
        _ => RelationshipTrustClass::Unlabeled,
    }
}

/// Default trust tier for a class. Callers may narrow, never widen.
#[must_use]
pub const fn default_trust_tier(class: RelationshipTrustClass) -> u8 {
    match class {
        RelationshipTrustClass::Intimate | RelationshipTrustClass::Family => 3,
        RelationshipTrustClass::Friend => 2,
        RelationshipTrustClass::Professional | RelationshipTrustClass::Client => 1,
        RelationshipTrustClass::Unlabeled => 0,
    }
}

/// Default retrieval bands for a class. Callers may narrow, never widen.
///
/// Client and Professional share a tier but NOT a band set: a client sees Crm,
/// a coworker sees Core.
#[must_use]
pub fn default_retrieval_bands(class: RelationshipTrustClass) -> Vec<SelectorRange> {
    match class {
        RelationshipTrustClass::Intimate | RelationshipTrustClass::Family => vec![
            SelectorRange::Semantic,
            SelectorRange::Core,
            SelectorRange::Companion,
        ],
        RelationshipTrustClass::Friend => vec![SelectorRange::Semantic, SelectorRange::Core],
        RelationshipTrustClass::Professional => vec![
            SelectorRange::Semantic,
            SelectorRange::Core,
            SelectorRange::Productivity,
        ],
        RelationshipTrustClass::Client => vec![
            SelectorRange::Semantic,
            SelectorRange::Crm,
            SelectorRange::Productivity,
        ],
        RelationshipTrustClass::Unlabeled => vec![SelectorRange::Semantic],
    }
}

/// Writes an Approved person-ref claim binding `member_ref` to `person`.
///
/// `person` is the claim VALUE, not its subject, so the claim door's own
/// subject-existence check never sees it: existence is confirmed HERE, before
/// anything is written. Self-binding (`person == member_ref`) is legal.
pub fn bind_member_person(
    vault: &Vault,
    member_ref: EntityId,
    person: EntityId,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    if !vault.entity_exists(&person)? {
        return Err(Error::EntityNotFound);
    }
    put_relationship_claim(
        vault,
        RelationshipClaim {
            predicate: PREDICATE_RELATIONSHIP_PERSON_REF,
            subject: member_ref,
            value: Value::from(person.to_hex()),
            approval: ClaimApprovalStatus::Approved,
        },
        occurred,
        learned_at,
    )
}

/// Writes a relationship label claim on `person`.
///
/// Only Auto and Approved are accepted — a Proposed or Rejected label would be
/// ignored by [`resolve_member_relationship`] anyway, so writing one is a
/// caller error, not a stored no-op.
pub fn put_member_relationship_label(
    vault: &Vault,
    person: EntityId,
    label: &str,
    approval: ClaimApprovalStatus,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    if !matches!(
        approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) || !is_relationship_label(label)
    {
        return Err(invalid_relationship_claim());
    }
    put_relationship_claim(
        vault,
        RelationshipClaim {
            predicate: PREDICATE_RELATIONSHIP_LABEL,
            subject: person,
            value: Value::from(label),
            approval,
        },
        occurred,
        learned_at,
    )
}

/// One valid relationship claim reduced to its precedence key and payload.
struct RelationshipClaimCandidate<T> {
    payload: T,
    claim: EntityId,
    /// Approved outranks Auto on the LABEL axis only; the person-ref contest
    /// ignores this field and orders purely by recency.
    approved: bool,
    learned_at: u64,
}

/// The writable half of a relationship claim, so the two writer doors share one
/// mint-and-put path without a long positional argument list.
struct RelationshipClaim {
    predicate: &'static str,
    subject: EntityId,
    value: Value,
    approval: ClaimApprovalStatus,
}

/// Collects every valid `predicate` claim on `subject`, dropping any whose
/// approval, lifecycle, or value shape disqualifies it.
fn relationship_claims<T>(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
    parse: impl Fn(&Value) -> Option<T>,
) -> Result<Vec<RelationshipClaimCandidate<T>>> {
    let mut candidates = Vec::new();
    for claim in vault.claims_for_subject(&subject)? {
        let Some(body) = vault.get_claim(&claim)? else {
            continue;
        };
        if body.predicate != predicate || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let approved = match body.approval {
            ClaimApprovalStatus::Approved => true,
            ClaimApprovalStatus::Auto => false,
            ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Rejected => continue,
        };
        let Some(payload) = parse(&body.value) else {
            continue;
        };
        candidates.push(RelationshipClaimCandidate {
            payload,
            claim,
            approved,
            learned_at: vault.get_learned_at(&claim)?,
        });
    }
    Ok(candidates)
}

fn put_relationship_claim(
    vault: &Vault,
    claim: RelationshipClaim,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_claim(
        &id,
        &ClaimBody::new(
            claim.predicate,
            ClaimSubject::Entity(claim.subject),
            claim.value,
            1.0,
            claim.approval,
            ClaimLifecycleStatus::Active,
        ),
        occurred,
        learned_at,
    )?;
    Ok(id)
}

/// `[a-z_]{1,64}` — the pinned label grammar.
fn is_relationship_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_RELATIONSHIP_LABEL_BYTES
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn invalid_relationship_claim() -> Error {
    Error::InvalidClaimBody("relationship claim failed validation")
}
