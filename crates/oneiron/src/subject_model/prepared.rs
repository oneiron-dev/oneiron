//! The native subject fact's read/compare result, before its write.

use super::{
    PREDICATE_PERSON_SUBSTRATE, actor_subject_anchor_in_txn, person_substrate_bodies_in_txn,
    single_subject_value,
};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

pub(crate) struct PreparedSubjectFact {
    pub(super) id: EntityId,
    pub(super) body: ClaimBody,
}

pub(super) fn prepare_subject_fact_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: ClaimBody,
    at: u64,
) -> Result<Option<PreparedSubjectFact>> {
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
        // Compare the stored assertion, not the redirected anchor: a retry
        // must never rewrite the subject the original writer actually named.
        return if prior == body.value {
            Ok(None)
        } else {
            Err(Error::InvalidClaimBody(
                "subject model fact is already bound differently",
            ))
        };
    }
    Ok(Some(PreparedSubjectFact {
        id: vault.store.clock.entity_id()?,
        body,
    }))
}
