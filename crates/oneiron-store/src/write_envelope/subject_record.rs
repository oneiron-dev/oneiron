//! Subject identity and substrate vocabulary with pure claim-shape validation.

use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};
pub use crate::write_envelope::claim_predicate::PREDICATE_PERSON_SUBSTRATE;
use oneiron_base::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, Result};

/// Subject-model vocabulary version. Claim bodies retain the generic claim ABI.
pub const SUBJECT_MODEL_SCHEMA_VERSION: u64 = 1;

/// The only entity kinds that can stand behind an actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectKind {
    Person,
    Org,
}

impl SubjectKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Org => "org",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "person" => Some(Self::Person),
            "org" => Some(Self::Org),
            _ => None,
        }
    }

    pub fn from_entity_type(entity_type: Option<u8>) -> Result<Self> {
        match entity_type {
            Some(ENTITY_TYPE_PERSON) => Ok(Self::Person),
            Some(ENTITY_TYPE_ORG) => Ok(Self::Org),
            _ => Err(Error::InvalidClaimBody(
                "actor.subject_ref subject must be a PERSON or ORG",
            )),
        }
    }
}

/// An actor's singular subject, with its checked entity kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActorSubjectAnchor {
    pub actor_ref: EntityId,
    pub subject_ref: EntityId,
    pub subject_kind: SubjectKind,
}

/// Anchors an actor to the PERSON or ORG standing behind it.
///
/// Reserved `actor.*` namespace: writable only through [`anchor_actor_subject`]
/// via the crate-internal reserved claim door, never through
/// `Vault::put_claim`.
pub const PREDICATE_ACTOR_SUBJECT_REF: &str = "actor.subject_ref";

/// What a PERSON is made of (ARCH-0063 R7).
///
/// Deliberately NOT an entity-type fork. A `Model` person is a person: it
/// merges, consents, and holds relationships through exactly the same paths a
/// `Meat` person does. The registry is untouched by this distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PersonSubstrate {
    /// A biological someone.
    Meat,
    /// A model-backed someone.
    Model,
}

impl PersonSubstrate {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Meat => "meat",
            Self::Model => "model",
        }
    }

    /// Parses the wire spelling. Exactly two are accepted.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "meat" => Some(Self::Meat),
            "model" => Some(Self::Model),
            _ => None,
        }
    }
}

pub fn is_subject_model_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        PREDICATE_ACTOR_SUBJECT_REF | PREDICATE_PERSON_SUBSTRATE
    )
}

/// Archive data is demoted, not re-authored as a local observation. The owning
/// readers ignore Proposed and Rejected rows, including their retained history.
pub fn imported_subject_body(body: &ClaimBody) -> Result<ClaimBody> {
    if !is_subject_model_predicate(&body.predicate)
        || body.world.is_some()
        || body.rel.is_some()
        || body.scope.is_some()
    {
        return Err(invalid(
            "archive subject fact must be an unscoped base fact",
        ));
    }
    if body.predicate == PREDICATE_ACTOR_SUBJECT_REF {
        validate_actor_subject_claim_structure(body)?;
    } else {
        validate_person_substrate_claim_structure(body)?;
    }
    let mut body = body.clone();
    body.source = Some(ClaimSource::Imported);
    if body.approval != ClaimApprovalStatus::Rejected {
        body.approval = ClaimApprovalStatus::Proposed;
    }
    Ok(body)
}

pub fn validate_actor_subject_claim_structure(body: &ClaimBody) -> Result<(EntityId, EntityId)> {
    let ClaimSubject::Entity(actor) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "actor.subject_ref subject must name an actor entity",
        ));
    };
    let subject = body
        .value
        .as_str()
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or(Error::InvalidClaimBody(
            "actor.subject_ref value must be an entity ID string",
        ))?;
    Ok((actor, subject))
}

pub fn validate_person_substrate_claim_structure(body: &ClaimBody) -> Result<EntityId> {
    let ClaimSubject::Entity(person) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "person.substrate subject must name a PERSON entity",
        ));
    };
    if body
        .value
        .as_str()
        .and_then(PersonSubstrate::parse)
        .is_none()
    {
        return Err(Error::InvalidClaimBody(
            "person.substrate value must be exactly meat or model",
        ));
    }
    Ok(person)
}

pub fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}
