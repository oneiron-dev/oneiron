//! The native subject fact's read/compare result, before its write.

use super::{PREDICATE_PERSON_SUBSTRATE, single_subject_value};
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
    prepare_subject_fact_with_planned_in_txn(vault, txn, body, at, None)
}

fn prepare_subject_fact_with_planned_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: ClaimBody,
    at: u64,
    planned: Option<&PlannedSubjectEntities<'_>>,
) -> Result<Option<PreparedSubjectFact>> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvariantViolation(
            "subject model fact must name an entity",
        ));
    };
    let prior = if body.predicate == PREDICATE_PERSON_SUBSTRATE {
        super::person_substrate_bodies_with_planned_in_txn(
            vault, txn, &subject, at, false, planned,
        )?
        .pop()
        .map(|(_, body)| body.value)
    } else {
        let prior = single_subject_value(vault, txn, &subject, &body.predicate, at)?;
        if prior.is_some()
            && super::actor_subject_anchor_with_planned_in_txn(vault, txn, &subject, at, planned)?
                .is_none()
        {
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

/// A native fact and every predecessor it will supersede, captured before Gate.
pub(crate) struct PreparedSubjectHead {
    fact: PreparedSubjectFact,
    superseded: Vec<(EntityId, ClaimBody)>,
    at: u64,
}

impl PreparedSubjectHead {
    pub(crate) fn encoded_puts(&self) -> Result<Vec<(EntityId, Vec<u8>)>> {
        let mut puts = vec![(
            self.fact.id,
            crate::claim::encode_claim_body(&self.fact.body)?,
        )];
        for (id, body) in &self.superseded {
            let mut body = body.clone();
            body.lifecycle = crate::claim::ClaimLifecycleStatus::Superseded;
            body.valid_to = Some(self.at);
            puts.push((*id, crate::claim::encode_claim_body(&body)?));
        }
        Ok(puts)
    }

    pub(crate) fn entity_puts(&self) -> impl Iterator<Item = EntityId> + '_ {
        std::iter::once(self.fact.id).chain(self.superseded.iter().map(|(id, _)| *id))
    }

    pub(super) fn apply(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        owner: Option<crate::agent_def::PreparedSetupOwner>,
    ) -> Result<()> {
        write_captured_head_with_setup_owner_in_txn(
            vault,
            txn,
            &self.fact.id,
            &self.fact.body,
            crate::temporal::TimeRange {
                start: self.at,
                end: self.at,
            },
            self.at,
            self.superseded.into_iter().map(|(id, _)| id),
            owner,
        )
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the captured head retains its native row, supersessions, time and optional setup owner"
)]
pub(super) fn write_captured_head_with_setup_owner_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
    occurred: crate::TimeRange,
    at: u64,
    superseded: impl IntoIterator<Item = EntityId>,
    owner: Option<crate::agent_def::PreparedSetupOwner>,
) -> Result<()> {
    match owner {
        Some(owner) => vault.put_reserved_claim_with_setup_owner_in_txn(
            wtxn, claim_id, body, occurred, at, owner,
        )?,
        None => vault.put_reserved_claim_in_txn(wtxn, claim_id, body, occurred, at)?,
    }
    for head_id in superseded {
        vault.supersede_reserved_claim_in_txn(wtxn, claim_id, &head_id, at)?;
    }
    Ok(())
}

pub(super) fn prepare_subject_head_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: ClaimBody,
    at: u64,
    planned: &PlannedSubjectEntities<'_>,
) -> Result<Option<PreparedSubjectHead>> {
    let Some(fact) = prepare_subject_fact_with_planned_in_txn(vault, txn, body, at, Some(planned))?
    else {
        return Ok(None);
    };
    let ClaimSubject::Entity(subject) = fact.body.subject else {
        return Err(Error::InvariantViolation(
            "subject model fact must name an entity",
        ));
    };
    let superseded = if fact.body.predicate == PREDICATE_PERSON_SUBSTRATE {
        super::person_substrate_bodies_with_planned_in_txn(
            vault,
            txn,
            &subject,
            at,
            true,
            Some(planned),
        )?
    } else {
        super::replacement_heads_in_txn(vault, txn, &subject, &fact.body.predicate, at)?
    };
    Ok(Some(PreparedSubjectHead {
        fact,
        superseded,
        at,
    }))
}

/// Only encoded Puts belonging to this native agent-setup plan may fill absence.
pub(super) struct PlannedSubjectEntities<'a> {
    agent: (EntityId, &'a [u8]),
    person: Option<(EntityId, &'a [u8])>,
    preceding: &'a [crate::agent_def::SetupEntityPut<'a>],
}

impl PlannedSubjectEntities<'_> {
    pub(super) fn kind(&self, id: &EntityId) -> Option<u8> {
        if let Some(put) = self.preceding.iter().rev().find(|put| put.id == *id) {
            Some(put.entity_type)
        } else if *id == self.agent.0 {
            Some(crate::registry::ENTITY_TYPE_AGENT_DEF)
        } else if self.person.is_some_and(|(person, _)| person == *id) {
            Some(crate::registry::ENTITY_TYPE_PERSON)
        } else {
            None
        }
    }
}

pub(super) fn subject_entity_type_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    planned: Option<&PlannedSubjectEntities<'_>>,
) -> Result<Option<u8>> {
    let stored = vault.get_entity_type_in_txn(txn, id)?;
    Ok(stored.or_else(|| planned.and_then(|planned| planned.kind(id))))
}
pub(super) fn validate_anchor_with_planned_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    subject: EntityId,
    planned: Option<&PlannedSubjectEntities<'_>>,
) -> Result<()> {
    match planned {
        Some(planned) => super::validation::require_planned_anchor_entities_in_txn(
            &vault.store,
            txn,
            &actor,
            &subject,
            planned,
        ),
        None => super::validate_anchor_entities_in_txn(vault, txn, actor, subject),
    }
}

/// A native encoded definition used only to read its forthcoming subject facts.
pub(crate) struct PreparedSubjectAgent<'a> {
    id: EntityId,
    data: &'a [u8],
    preceding: &'a [crate::agent_def::SetupEntityPut<'a>],
}

impl<'a> PreparedSubjectAgent<'a> {
    pub(crate) fn new(id: EntityId, data: &'a [u8]) -> Result<Self> {
        crate::agent_def::decode_agent_definition(data)?;
        Ok(Self {
            id,
            data,
            preceding: &[],
        })
    }

    pub(crate) fn after_puts(
        id: EntityId,
        data: &'a [u8],
        preceding: &'a [crate::agent_def::SetupEntityPut<'a>],
    ) -> Result<Self> {
        let mut agent = Self::new(id, data)?;
        agent.preceding = preceding;
        Ok(agent)
    }

    pub(crate) fn has_subject_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        at: u64,
    ) -> Result<bool> {
        let planned = PlannedSubjectEntities {
            agent: (self.id, self.data),
            person: None,
            preceding: self.preceding,
        };
        Ok(super::actor_subject_anchor_with_planned_in_txn(
            vault,
            txn,
            &self.id,
            at,
            Some(&planned),
        )?
        .is_some())
    }

    pub(crate) fn prepare_person_facts_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
        person_put: Option<&[u8]>,
        at: u64,
    ) -> Result<PreparedAgentSubjects> {
        let planned = PlannedSubjectEntities {
            agent: (self.id, self.data),
            person: person_put.map(|data| (person, data)),
            preceding: self.preceding,
        };
        let writer = crate::WriteActor::new(self.id, crate::EdgeActorClass::Agent);
        let model = prepare_subject_head_in_txn(
            vault,
            txn,
            super::subject_fact(
                PREDICATE_PERSON_SUBSTRATE,
                person,
                rmpv::Value::from(super::PersonSubstrate::Model.as_str()),
                writer,
                at,
            )?,
            at,
            &planned,
        )?;
        let mut anchor_body = super::subject_fact(
            super::PREDICATE_ACTOR_SUBJECT_REF,
            self.id,
            rmpv::Value::from(person.to_hex()),
            writer,
            at,
        )?;
        anchor_body.scope_facet =
            super::actor_subject_facet_with_planned_in_txn(vault, txn, self.id, Some(&planned))?;
        let anchor = prepare_subject_head_in_txn(vault, txn, anchor_body, at, &planned)?;
        Ok(PreparedAgentSubjects {
            agent: self.id,
            person,
            model,
            anchor,
        })
    }
}

pub(crate) struct PreparedAgentSubjects {
    agent: EntityId,
    person: EntityId,
    model: Option<PreparedSubjectHead>,
    anchor: Option<PreparedSubjectHead>,
}

impl PreparedAgentSubjects {
    pub(crate) fn heads(&self) -> impl Iterator<Item = &PreparedSubjectHead> {
        self.model.iter().chain(self.anchor.iter())
    }

    pub(crate) fn entity_puts(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.model
            .iter()
            .chain(self.anchor.iter())
            .flat_map(PreparedSubjectHead::entity_puts)
    }

    pub(crate) fn fresh_claims(&self) -> impl Iterator<Item = (&EntityId, &ClaimBody)> {
        self.model
            .iter()
            .chain(self.anchor.iter())
            .map(|head| (&head.fact.id, &head.fact.body))
    }

    pub(crate) fn apply(self, vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        self.apply_with_setup_owners(vault, txn, &mut Vec::new())
    }

    pub(crate) fn apply_with_setup_owners(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        owners: &mut Vec<crate::agent_def::PreparedSetupOwner>,
    ) -> Result<()> {
        let writer = crate::WriteActor::new(self.agent, crate::EdgeActorClass::Agent);
        super::validation::require_person_in_txn(&vault.store, txn, &self.person)?;
        super::validate_writer_in_txn(vault, txn, writer)?;
        if let Some(model) = self.model {
            let owner = crate::agent_def::take_setup_owner_before(owners, model.fact.id);
            model.apply(vault, txn, owner)?;
        }
        super::validate_anchor_entities_in_txn(vault, txn, self.agent, self.person)?;
        super::validate_writer_in_txn(vault, txn, writer)?;
        if let Some(anchor) = self.anchor {
            let owner = crate::agent_def::take_setup_owner_before(owners, anchor.fact.id);
            anchor.apply(vault, txn, owner)?;
        }
        Ok(())
    }
}
