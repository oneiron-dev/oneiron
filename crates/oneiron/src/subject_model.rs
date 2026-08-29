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
/// `writer` is required: an anchor is an assertion about a someone, so it
/// carries the authenticated author that stamped it.
pub fn anchor_actor_subject(
    vault: &Vault,
    actor_ref: EntityId,
    subject_ref: EntityId,
    writer: WriteActor,
    at: u64,
) -> Result<EntityId> {
    require_entity_exists(vault, &actor_ref, "actor.subject_ref actor must exist")?;
    let subject_type = vault.get_entity_type(&subject_ref)?;
    if !matches!(
        subject_type,
        Some(ENTITY_TYPE_PERSON) | Some(ENTITY_TYPE_ORG)
    ) {
        return Err(Error::InvalidClaimBody(
            "actor.subject_ref subject must be a PERSON or ORG",
        ));
    }

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
    write_head_in_txn(vault, &claim_id, &body, actor_ref, at, Reserved::Yes)?;
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
    let rtxn = vault.store.env.read_txn()?;
    let stored = vault.find_claim_for_subject_in_txn(&rtxn, actor_ref, |_, body| {
        (body.predicate == PREDICATE_ACTOR_SUBJECT_REF
            && body.lifecycle == ClaimLifecycleStatus::Active)
            .then(|| {
                body.value
                    .as_str()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
            })
    })?;
    let Some(Some(stored)) = stored else {
        return Ok(None);
    };
    // Read-time canonicalization (ARCH-0055): the ledger keeps what the writer
    // stated, the reader follows the redirect.
    let heads = vault.resolve_entity_in_txn(&rtxn, &stored)?;
    match heads.as_slice() {
        [head] => Ok(Some(*head)),
        _ => Ok(None),
    }
}

/// Records the substrate of a PERSON, superseding any prior value.
///
/// Refuses any entity that is not a PERSON: an ORG has no substrate, and an
/// actor is not a someone at all.
pub fn set_person_substrate(
    vault: &Vault,
    person_ref: EntityId,
    substrate: PersonSubstrate,
    writer: WriteActor,
    at: u64,
) -> Result<EntityId> {
    if vault.get_entity_type(&person_ref)? != Some(ENTITY_TYPE_PERSON) {
        return Err(Error::InvalidClaimBody(
            "person.substrate subject must be a PERSON",
        ));
    }

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
    write_head_in_txn(vault, &claim_id, &body, person_ref, at, Reserved::No)?;
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
/// Closes EVERY prior head, not the first found: `EntityId::now()` is
/// per-replica unique, so two replicas that each stated this fact hold two
/// distinct claim entities and both read Active after a sync. Closing one
/// would leave the other live forever.
fn write_head_in_txn(
    vault: &Vault,
    claim_id: &EntityId,
    body: &ClaimBody,
    subject: EntityId,
    at: u64,
    reserved: Reserved,
) -> Result<()> {
    let occurred = TimeRange { start: at, end: at };
    vault.with_write_txn(|wtxn| {
        let superseded = active_heads_in_txn(vault, &*wtxn, &subject, &body.predicate)?;
        match reserved {
            Reserved::Yes => vault.put_reserved_claim_in_txn(wtxn, claim_id, body, occurred, at)?,
            Reserved::No => vault.put_claim_in_txn(wtxn, claim_id, body, occurred, at)?,
        }
        for (head_id, head_start) in superseded {
            // `at.max(head_start)` keeps the re-Put range valid when an
            // out-of-order event time would otherwise invert it.
            let now = at.max(head_start);
            match reserved {
                Reserved::Yes => {
                    vault.supersede_reserved_claim_in_txn(wtxn, claim_id, &head_id, now)?;
                }
                Reserved::No => vault.supersede_claim_in_txn(wtxn, claim_id, &head_id, now)?,
            }
        }
        Ok(())
    })
}

/// The substrate recorded for `person_ref`, if any.
pub fn person_substrate(vault: &Vault, person_ref: &EntityId) -> Result<Option<PersonSubstrate>> {
    let rtxn = vault.store.env.read_txn()?;
    let found = vault.find_claim_for_subject_in_txn(&rtxn, person_ref, |_, body| {
        (body.predicate == PREDICATE_PERSON_SUBSTRATE
            && body.lifecycle == ClaimLifecycleStatus::Active)
            .then(|| body.value.as_str().and_then(PersonSubstrate::parse))
    })?;
    Ok(found.flatten())
}

/// Active heads of `predicate` on `subject`, with each head's valid-from.
fn active_heads_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<Vec<(EntityId, u64)>> {
    let mut heads = Vec::new();
    vault.find_claim_for_subject_within(txn, subject, usize::MAX, |id, body| {
        if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
            heads.push((*id, body.valid_from.unwrap_or(0)));
        }
        None::<()>
    })?;
    Ok(heads)
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

fn require_entity_exists(vault: &Vault, id: &EntityId, reason: &'static str) -> Result<()> {
    if vault.get_entity_type(id)?.is_none() {
        return Err(Error::InvalidClaimBody(reason));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
