//! A seeded system agent's subject facts (FIX 12098): its PERSON's
//! `person.substrate` and its own `actor.subject_ref`, each written as the
//! claim id its caller derives and at the seed time, never a clock, so every
//! device holds the same rows byte for byte.

use rmpv::Value;

use super::{
    PREDICATE_ACTOR_SUBJECT_REF, PREDICATE_PERSON_SUBSTRATE, PersonSubstrate,
    actor_subject_anchor_in_txn, person_substrate_bodies_in_txn, single_subject_value,
    subject_fact, validate_anchor_entities_in_txn, validate_writer_in_txn, validation,
    write_head_in_txn,
};
use crate::Vault;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;

/// [`super::ensure_model_person_in_txn`] as the claim `claim_id` at `at`.
pub(crate) fn ensure_seeded_model_person_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    person: EntityId,
    writer: WriteActor,
    claim_id: EntityId,
    at: u64,
) -> Result<()> {
    validation::require_person_in_txn(&vault.store, txn, &person)?;
    validate_writer_in_txn(vault, txn, writer)?;
    let body = subject_fact(
        PREDICATE_PERSON_SUBSTRATE,
        person,
        Value::from(PersonSubstrate::Model.as_str()),
        writer,
        at,
    )?;
    ensure_fact_as_in_txn(vault, txn, &claim_id, body, at)
}

/// [`super::ensure_actor_subject_in_txn`] as the claim `claim_id` at `at`.
pub(crate) fn ensure_seeded_actor_subject_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    subject: EntityId,
    writer: WriteActor,
    claim_id: EntityId,
    at: u64,
) -> Result<()> {
    validate_anchor_entities_in_txn(vault, txn, actor, subject)?;
    validate_writer_in_txn(vault, txn, writer)?;
    let body = subject_fact(
        PREDICATE_ACTOR_SUBJECT_REF,
        actor,
        Value::from(subject.to_hex()),
        writer,
        at,
    )?;
    ensure_fact_as_in_txn(vault, txn, &claim_id, body, at)
}

/// `ensure_fact_in_txn`'s rule under the caller's claim id: an equal prior
/// fact writes nothing, a different one refuses.
fn ensure_fact_as_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: ClaimBody,
    at: u64,
) -> Result<()> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvariantViolation(
            "subject model fact must name an entity",
        ));
    };
    let prior = if body.predicate == PREDICATE_PERSON_SUBSTRATE {
        person_substrate_bodies_in_txn(vault, txn, &subject, at, false)?
            .pop()
            .map(|(_, body)| body.value)
    } else {
        let prior = single_subject_value(vault, txn, &subject, &body.predicate, at)?;
        if prior.is_some() && actor_subject_anchor_in_txn(vault, txn, &subject, at)?.is_none() {
            return Err(Error::InvalidClaimBody(
                "actor.subject_ref requires one canonical subject",
            ));
        }
        prior
    };
    if let Some(prior) = prior {
        return if prior == body.value {
            Ok(())
        } else {
            Err(Error::InvalidClaimBody(
                "subject model fact is already bound differently",
            ))
        };
    }
    write_head_in_txn(vault, txn, claim_id, &body, at)
}
