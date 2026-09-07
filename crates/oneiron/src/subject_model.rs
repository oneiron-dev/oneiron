//! Subject model: who, if anyone, stands behind an actor (ARCH-0063 R7).
//!
//! # There is no ACTOR entity kind
//!
//! An actor is not a type byte. It is a ROLE an authority-bearing entity
//! plays on a channel: a named agent is normally an `AGENT_DEF`, and a
//! connector/plumbing actor keeps whatever reference it already had. Minting
//! an `ACTOR` kind was rejected because it would force every existing agent
//! and connector reference to migrate to a new identity, and would make
//! "is there a someone here?" a property of the KIND rather than a separate,
//! revisable assertion.
//!
//! # Two independent axes
//!
//! * [`PREDICATE_ACTOR_SUBJECT_REF`] anchors an actor to exactly one active
//!   PERSON or ORG. Its ABSENCE is meaningful and legal: an unanchored actor
//!   is plumbing — a mail relay, a scraper, a bot with no one behind it — and
//!   it routes normally. No placeholder person is ever minted to fill the
//!   hole, because a placeholder someone is a lie the rest of the system
//!   would then have to believe.
//! * [`PREDICATE_PERSON_SUBSTRATE`] records whether a PERSON is `meat` or
//!   `model`. Substrate is a property OF the person, never a fork of the
//!   entity kind: a model-substrate person is still a person, so consent,
//!   merge, and relationship machinery keep working on it unchanged.
//!
//! The two axes are orthogonal on purpose. An anchored actor whose person is
//! `model` is an AI someone; an unanchored actor is nobody at all. Collapsing
//! them into one enum would make those two cases indistinguishable.
//!
//! # Merge repair is a READ, not a table
//!
//! When two PERSON records turn out to be the same someone, the ARCH-0055
//! redirect projection already answers "who survived". So
//! [`actor_subject_anchor`] resolves through [`Vault::resolve_entity`] at read
//! time and historical claim subjects are never rewritten. There is no
//! second same-as/link table here, and an unmerge stays possible because the
//! stored anchor still names what the writer actually stated.

use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

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

    fn from_entity_type(entity_type: Option<u8>) -> Result<Self> {
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

impl Vault {
    /// Writes one active anchor and stamps the host-authenticated writer.
    pub fn set_actor_subject_anchor(
        &self,
        anchor: ActorSubjectAnchor,
        writer: &WriteActor,
        learned_at: u64,
    ) -> Result<EntityId> {
        write_actor_subject_anchor(self, anchor, *writer, learned_at)
    }

    /// Resolves an anchor through the existing identity redirect projection.
    pub fn actor_subject_anchor(&self, actor_ref: &EntityId) -> Result<Option<ActorSubjectAnchor>> {
        let rtxn = self.store.env.read_txn()?;
        actor_subject_anchor_in_txn(self, &rtxn, actor_ref)
    }

    /// Records a PERSON's substrate using the checked claim door.
    pub fn set_person_substrate(
        &self,
        person_ref: EntityId,
        substrate: PersonSubstrate,
        writer: &WriteActor,
        learned_at: u64,
    ) -> Result<EntityId> {
        set_person_substrate(self, person_ref, substrate, *writer, learned_at)
    }

    /// Reads the PERSON's active substrate, refusing malformed claims.
    pub fn person_substrate(&self, person_ref: &EntityId) -> Result<Option<PersonSubstrate>> {
        person_substrate(self, person_ref)
    }
}

/// Anchors an actor to the PERSON or ORG standing behind it.
///
/// Reserved `actor.*` namespace: writable only through [`anchor_actor_subject`]
/// via the crate-internal reserved claim door, never through
/// `Vault::put_claim`.
pub const PREDICATE_ACTOR_SUBJECT_REF: &str = "actor.subject_ref";

/// Records whether a PERSON is `meat` or `model`.
pub const PREDICATE_PERSON_SUBSTRATE: &str = "person.substrate";

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

/// Anchors `actor_ref` to `subject_ref`, superseding any prior anchor.
///
/// `subject_ref` must be a live PERSON or ORG; any other entity type is a
/// typed [`Error::InvalidClaimBody`] rather than a silently stored dangling
/// anchor. An actor holds at most ONE active anchor, so re-anchoring closes
/// the previous head in the same transaction rather than leaving two live
/// answers to "who is this".
///
/// `writer` must satisfy the canonical human-owner rule in the write
/// transaction: a live, class-valid human and an active owner binding once
/// the vault has an authority root. Unrooted vaults retain store-truth owner
/// semantics. The target must also be an authority-bearing entity.
pub fn anchor_actor_subject(
    vault: &Vault,
    actor_ref: EntityId,
    subject_ref: EntityId,
    writer: WriteActor,
    at: u64,
) -> Result<EntityId> {
    let subject_kind = SubjectKind::from_entity_type(vault.get_entity_type(&subject_ref)?)?;
    write_actor_subject_anchor(
        vault,
        ActorSubjectAnchor {
            actor_ref,
            subject_ref,
            subject_kind,
        },
        writer,
        at,
    )
}

fn write_actor_subject_anchor(
    vault: &Vault,
    anchor: ActorSubjectAnchor,
    writer: WriteActor,
    at: u64,
) -> Result<EntityId> {
    let ActorSubjectAnchor {
        actor_ref,
        subject_ref,
        subject_kind,
    } = anchor;
    let claim_id = EntityId::now();
    let mut body = ClaimBody::new(
        PREDICATE_ACTOR_SUBJECT_REF,
        ClaimSubject::Entity(actor_ref),
        Value::from(subject_ref.to_hex()),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(at);
    body.source = Some(ClaimSource::Observed);
    body.evidence = Some(writer_evidence(writer));

    // `actor.*` is a RESERVED namespace, so this rides the crate-internal
    // engine door; `Vault::put_claim` refuses it by design.
    vault.with_write_txn(|wtxn| {
        validate_writer_in_txn(vault, wtxn, writer)?;
        vault.verify_owner_write_actor_in_txn(wtxn, &writer)?;
        validate_anchor_entities_in_txn(vault, wtxn, actor_ref, subject_ref)?;
        let actual_kind =
            SubjectKind::from_entity_type(vault.get_entity_type_in_txn(wtxn, &subject_ref)?)?;
        if actual_kind != subject_kind {
            return Err(Error::InvalidClaimBody(
                "actor.subject_ref subject kind mismatch",
            ));
        }
        write_head_in_txn(vault, wtxn, &claim_id, &body, at, Reserved::Yes)
    })?;
    Ok(claim_id)
}

/// The PERSON or ORG standing behind `actor_ref`, canonicalized through the
/// redirect projection.
///
/// `Ok(None)` is the PLUMBING answer and is not an error: this actor has no
/// someone behind it.
///
/// After a merge, the stored anchor still names the pre-merge subject; this
/// read resolves it to the surviving head.
///
/// # Why an ambiguous split reads as `None`
///
/// [`Vault::resolve_entity`] answers with a SET, and a split shell can have
/// several heads: the record this anchor named turned out to be more than one
/// someone. There is no fact here that picks one of them, so this returns
/// `None` rather than the numerically smallest id. Guessing would stamp a
/// confidently wrong person onto every routed event, which is strictly worse
/// than the honest "no determinate subject" that a caller already has to
/// handle for plumbing. A zero-head split reads `None` for the same reason.
pub fn actor_subject_anchor(vault: &Vault, actor_ref: &EntityId) -> Result<Option<EntityId>> {
    Ok(vault
        .actor_subject_anchor(actor_ref)?
        .map(|anchor| anchor.subject_ref))
}

pub(crate) fn actor_subject_anchor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor_ref: &EntityId,
) -> Result<Option<ActorSubjectAnchor>> {
    let Some(body) = single_active_body_in_txn(vault, txn, actor_ref, PREDICATE_ACTOR_SUBJECT_REF)?
    else {
        return Ok(None);
    };
    let stored = body
        .value
        .as_str()
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or(Error::InvalidClaimBody(
            "actor.subject_ref must be an entity reference",
        ))?;
    let subject_kind = SubjectKind::from_entity_type(vault.get_entity_type_in_txn(txn, &stored)?)?;
    let heads = vault.resolve_entity_in_txn(txn, &stored)?;
    let [head] = heads.as_slice() else {
        return Ok(None);
    };
    if SubjectKind::from_entity_type(vault.get_entity_type_in_txn(txn, head)?)? != subject_kind {
        return Err(Error::InvalidClaimBody(
            "actor.subject_ref redirect kind mismatch",
        ));
    }
    Ok(Some(ActorSubjectAnchor {
        actor_ref: *actor_ref,
        subject_ref: *head,
        subject_kind,
    }))
}

/// Records the substrate of a PERSON, superseding any prior value.
///
/// Refuses any entity that is not a PERSON: an ORG has no substrate, and an
/// actor is not a someone at all. Redirects must identify one PERSON, with
/// no malformed or competing active substrate claims. Supersession closes
/// the canonical person's prior claim without changing its stored subject.
pub fn set_person_substrate(
    vault: &Vault,
    person_ref: EntityId,
    substrate: PersonSubstrate,
    writer: WriteActor,
    at: u64,
) -> Result<EntityId> {
    let claim_id = EntityId::now();
    let mut body = ClaimBody::new(
        PREDICATE_PERSON_SUBSTRATE,
        ClaimSubject::Entity(person_ref),
        Value::from(substrate.as_str()),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(at);
    body.source = Some(ClaimSource::Observed);
    body.evidence = Some(writer_evidence(writer));

    // `person.*` is NOT reserved, so this rides the ordinary claim doors. The
    // substrate of a someone is a normal fact about them, not engine-owned
    // truth, and giving it the reserved door would have quietly widened that
    // namespace.
    vault.with_write_txn(|wtxn| {
        if vault.get_entity_type_in_txn(wtxn, &person_ref)? != Some(ENTITY_TYPE_PERSON) {
            return Err(Error::InvalidClaimBody(
                "person.substrate subject must be a PERSON",
            ));
        }
        validate_writer_in_txn(vault, wtxn, writer)?;
        write_head_in_txn(vault, wtxn, &claim_id, &body, at, Reserved::No)
    })?;
    Ok(claim_id)
}

/// Which write door a predicate's namespace demands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reserved {
    Yes,
    No,
}

/// Writes `body` as the new single active head for `subject`, closing every
/// prior head of the same predicate in the SAME transaction.
///
/// For anchors, closes EVERY prior head, not the first found. Substrate
/// heads must first pass the canonical person's single-head validation.
/// `EntityId::now()` is per-replica unique, so two replicas that stated this
/// fact hold distinct claim entities and both read Active after a sync. Closing one
/// would leave the other live forever.
fn write_head_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
    at: u64,
    reserved: Reserved,
) -> Result<()> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "subject-model claim requires an entity subject",
        ));
    };
    let occurred = TimeRange { start: at, end: at };
    let superseded = if body.predicate == PREDICATE_PERSON_SUBSTRATE {
        active_person_substrate_bodies_in_txn(vault, wtxn, &subject)?
    } else {
        active_bodies_in_txn(vault, wtxn, &subject, &body.predicate)?
    };
    match reserved {
        Reserved::Yes => vault.put_reserved_claim_in_txn(wtxn, claim_id, body, occurred, at)?,
        Reserved::No => vault.put_claim_in_txn(wtxn, claim_id, body, occurred, at)?,
    }
    for (head_id, head_body) in superseded {
        let now = at.max(head_body.valid_from.unwrap_or(0));
        match reserved {
            Reserved::Yes => {
                vault.supersede_reserved_claim_in_txn(wtxn, claim_id, &head_id, now)?;
            }
            Reserved::No => vault.supersede_claim_in_txn(wtxn, claim_id, &head_id, now)?,
        }
    }
    Ok(())
}

/// Onboarding may fill an absent anchor, never replace an existing someone.
/// The caller verifies authority in this transaction before calling this door.
/// The read and write share LMDB's writer lock, including across Vault handles.
pub(crate) fn ensure_actor_subject_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    subject: EntityId,
    writer: WriteActor,
    at: u64,
) -> Result<()> {
    validate_anchor_entities_in_txn(vault, txn, actor, subject)?;
    validate_writer_in_txn(vault, txn, writer)?;
    ensure_fact_in_txn(
        vault,
        txn,
        subject_fact(
            PREDICATE_ACTOR_SUBJECT_REF,
            actor,
            Value::from(subject.to_hex()),
            writer,
            at,
        ),
        at,
        Reserved::Yes,
    )
}

/// An existing meat or malformed substrate is not an absent model fact.
/// The caller verifies onboarding authority in this same transaction.
pub(crate) fn ensure_model_person_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    person: EntityId,
    writer: WriteActor,
    at: u64,
) -> Result<()> {
    if vault.get_entity_type_in_txn(txn, &person)? != Some(ENTITY_TYPE_PERSON) {
        return Err(Error::InvalidClaimBody(
            "person.substrate subject must be a PERSON",
        ));
    }
    validate_writer_in_txn(vault, txn, writer)?;
    ensure_fact_in_txn(
        vault,
        txn,
        subject_fact(
            PREDICATE_PERSON_SUBSTRATE,
            person,
            Value::from(PersonSubstrate::Model.as_str()),
            writer,
            at,
        ),
        at,
        Reserved::No,
    )
}

fn ensure_fact_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    body: ClaimBody,
    at: u64,
    reserved: Reserved,
) -> Result<()> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvariantViolation(
            "subject model fact must name an entity",
        ));
    };
    let prior = if body.predicate == PREDICATE_PERSON_SUBSTRATE {
        active_person_substrate_bodies_in_txn(vault, txn, &subject)?
            .pop()
            .map(|(_, body)| body)
    } else {
        let prior = single_active_body_in_txn(vault, txn, &subject, &body.predicate)?;
        if prior.is_some() && actor_subject_anchor_in_txn(vault, txn, &subject)?.is_none() {
            return Err(Error::InvalidClaimBody(
                "actor.subject_ref requires one canonical subject",
            ));
        }
        prior
    };
    if let Some(prior) = prior {
        // Proposed or qualified facts cannot prove onboarding completed. Do not
        // hide them and then overwrite history through an "absent" fast path.
        if !matches!(
            prior.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) || prior.world.is_some()
            || prior.rel.is_some()
            || prior.scope.is_some()
        {
            return Err(Error::InvalidClaimBody(
                "subject model fact is not an unqualified approved fact",
            ));
        }
        // Compare the stored assertion, not the redirected anchor: a retry
        // must never rewrite the subject the original writer actually named.
        return if prior.value == body.value {
            Ok(())
        } else {
            Err(Error::InvalidClaimBody(
                "subject model fact is already bound differently",
            ))
        };
    }
    write_head_in_txn(vault, txn, &EntityId::now(), &body, at, reserved)
}

fn subject_fact(
    predicate: &str,
    subject: EntityId,
    value: Value,
    writer: WriteActor,
    at: u64,
) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(at);
    body.source = Some(ClaimSource::Observed);
    body.evidence = Some(writer_evidence(writer));
    body
}

/// The substrate recorded for `person_ref`, if any, through identity redirects.
/// Ambiguous identities and malformed or competing active claims are refused.
pub fn person_substrate(vault: &Vault, person_ref: &EntityId) -> Result<Option<PersonSubstrate>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut heads = active_person_substrate_bodies_in_txn(vault, &rtxn, person_ref)?;
    let Some((_, body)) = heads.pop() else {
        return Ok(None);
    };
    body.value
        .as_str()
        .and_then(PersonSubstrate::parse)
        .map(Some)
        .ok_or(Error::InvalidClaimBody(
            "person.substrate must be meat or model",
        ))
}

/// Reads the canonical person's claims without moving their historical subjects.
/// The same snapshot supplies both the read and the superseding write's old head.
fn active_person_substrate_bodies_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person_ref: &EntityId,
) -> Result<Vec<(EntityId, ClaimBody)>> {
    if vault.get_entity_type_in_txn(txn, person_ref)? != Some(ENTITY_TYPE_PERSON) {
        if active_bodies_in_txn(vault, txn, person_ref, PREDICATE_PERSON_SUBSTRATE)?.is_empty() {
            return Ok(Vec::new());
        }
        return Err(Error::InvalidClaimBody(
            "person.substrate subject must be a PERSON",
        ));
    }
    let resolved = vault.resolve_entity_in_txn(txn, person_ref)?;
    let [canonical] = resolved.as_slice() else {
        return Err(Error::InvalidClaimBody(
            "person.substrate requires one canonical PERSON",
        ));
    };
    if vault.get_entity_type_in_txn(txn, canonical)? != Some(ENTITY_TYPE_PERSON) {
        return Err(Error::InvalidClaimBody(
            "person.substrate redirect must name a PERSON",
        ));
    }
    let mut subjects = crate::identity_redirect::inbound_redirect_shells_in_txn(
        &vault.store,
        txn,
        &std::collections::BTreeSet::from([*canonical]),
    )?;
    subjects.insert(*canonical);
    let mut heads = Vec::new();
    for subject in subjects {
        // Validate every reached path, including an empty shell at the inverse
        // walk's depth bound: truncation must not hide a more distant claim.
        let resolved = vault.resolve_entity_in_txn(txn, &subject)?;
        let bodies = active_bodies_in_txn(vault, txn, &subject, PREDICATE_PERSON_SUBSTRATE)?;
        if bodies.is_empty() {
            continue;
        }
        // Inbound shell edges also witness splits. A claim on a split shell
        // cannot pick one of its people, even when queried through that head.
        if !resolved.contains(canonical) {
            continue;
        }
        if resolved.as_slice() != [*canonical] {
            return Err(Error::InvalidClaimBody(
                "person.substrate requires one canonical PERSON",
            ));
        }
        if vault.get_entity_type_in_txn(txn, &subject)? != Some(ENTITY_TYPE_PERSON) {
            return Err(Error::InvalidClaimBody(
                "person.substrate subject must be a PERSON",
            ));
        }
        for (_, body) in &bodies {
            if body
                .value
                .as_str()
                .and_then(PersonSubstrate::parse)
                .is_none()
            {
                return Err(Error::InvalidClaimBody(
                    "person.substrate must be meat or model",
                ));
            }
        }
        heads.extend(bodies);
        if heads.len() > 1 {
            return Err(Error::InvalidClaimBody(
                "subject-model claim has multiple active heads",
            ));
        }
    }
    Ok(heads)
}

fn active_bodies_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<Vec<(EntityId, ClaimBody)>> {
    let mut heads = Vec::new();
    // Keep the generic reader's bounded, fail-closed scan rather than bypassing
    // its ceiling. Ignore stale claim_of edges whose body names another subject.
    vault.find_claim_for_subject_in_txn(txn, subject, |id, body| {
        if body.subject == ClaimSubject::Entity(*subject)
            && body.predicate == predicate
            && body.lifecycle == ClaimLifecycleStatus::Active
        {
            heads.push((*id, body.clone()));
        }
        None::<()>
    })?;
    Ok(heads)
}

fn single_active_body_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<Option<ClaimBody>> {
    let mut heads = active_bodies_in_txn(vault, txn, subject, predicate)?;
    if heads.len() > 1 {
        return Err(Error::InvalidClaimBody(
            "subject-model claim has multiple active heads",
        ));
    }
    Ok(heads.pop().map(|(_, body)| body))
}

// WriteActor is supplied by the authenticated host. As at the existing write
// envelope doors, reject a missing actor or a class that disagrees with its kind.
fn validate_writer_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, writer: WriteActor) -> Result<()> {
    let entity_type = vault
        .get_entity_type_in_txn(txn, &writer.entity_ref())?
        .ok_or(Error::EntityNotFound)?;
    crate::provenance::validate_actor_class(entity_type, writer.actor_class())
}

/// Stamps the authenticated writer into the claim's evidence.
fn writer_evidence(writer: WriteActor) -> Value {
    Value::Map(vec![
        (
            Value::from("writer_ref"),
            Value::from(writer.entity_ref().to_hex()),
        ),
        (
            Value::from("writer_class"),
            Value::from(writer.actor_class().gate_actor_class()),
        ),
    ])
}

fn validate_anchor_entities_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    subject: EntityId,
) -> Result<()> {
    let kind = vault.get_entity_type_in_txn(txn, &actor)?.ok_or(Error::InvalidClaimBody(
        "actor.subject_ref actor must exist",
    ))?;
    let class = match kind {
        ENTITY_TYPE_PERSON | crate::registry::ENTITY_TYPE_AGENT_DEF => {
            crate::edge::EdgeActorClass::Agent
        }
        crate::registry::ENTITY_TYPE_MACHINE => crate::edge::EdgeActorClass::System,
        _ => {
            return Err(Error::InvalidClaimBody(
                "actor.subject_ref actor must be authority-bearing",
            ));
        }
    };
    crate::provenance::validate_actor_class(kind, class)?;
    if !matches!(
        vault.get_entity_type_in_txn(txn, &subject)?,
        Some(ENTITY_TYPE_PERSON) | Some(ENTITY_TYPE_ORG)
    ) {
        return Err(Error::InvalidClaimBody(
            "actor.subject_ref subject must be a PERSON or ORG",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
