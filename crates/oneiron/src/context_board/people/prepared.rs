//! Exact native PERSON and subject-fact tuples prepared before setup Gate.

use super::{AGENT_PERSON_DOMAIN, agent_person_body};
use crate::batch::PreparedPersonSubstrate;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::subject_model::{PreparedAgentSubjects, PreparedSubjectAgent};
use crate::{EntityId, TimeRange, Vault};

pub(crate) struct PreparedAgentPerson {
    pub(crate) person: EntityId,
    pub(crate) person_put: Option<Vec<u8>>,
    pub(crate) substrate: Option<PreparedPersonSubstrate>,
    pub(crate) subjects: PreparedAgentSubjects,
    at: u64,
}

pub(crate) fn prepare_agent_person_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    definition_data: &[u8],
    name: &str,
    at: u64,
) -> Result<Option<PreparedAgentPerson>> {
    prepare_agent_person_after_puts_in_txn(vault, txn, agent, definition_data, name, at, &[])
}

pub(crate) fn prepare_agent_person_after_puts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    definition_data: &[u8],
    name: &str,
    at: u64,
    preceding: &[crate::agent_def::SetupEntityPut<'_>],
) -> Result<Option<PreparedAgentPerson>> {
    if crate::dreamer_runner::authority::is_base_agent_actor(&agent)? {
        return Ok(None);
    }
    let person = EntityId::derive(AGENT_PERSON_DOMAIN, &[agent.as_bytes()])?;
    let prepared_agent = PreparedSubjectAgent::after_puts(agent, definition_data, preceding)?;
    // The old anchor read precedes the PERSON-create branch: it may project
    // the candidate definition, but cannot assume a PERSON will be created.
    if prepared_agent.has_subject_in_txn(vault, txn, at)? {
        return Ok(None);
    }
    let stored_person = vault.store.port_entity_record(txn, &person)?;
    let earlier_person = preceding.iter().rev().find(|put| put.id == person);
    let (person_put, substrate) = if stored_person.is_none() && earlier_person.is_none() {
        let body = agent_person_body(name)?;
        let substrate = crate::batch::prepare_person_substrate_after_puts(
            &vault.store,
            txn,
            person,
            TimeRange { start: at, end: at },
            at,
            preceding,
        )?;
        (Some(body), Some(substrate))
    } else {
        (None, None)
    };
    let mut subject_preceding = preceding
        .iter()
        .map(|put| crate::agent_def::SetupEntityPut::borrowed(put.id, put.entity_type, &put.data))
        .collect::<Vec<_>>();
    if let Some(body) = person_put.as_deref() {
        subject_preceding.push(crate::agent_def::SetupEntityPut::borrowed(
            person,
            crate::registry::ENTITY_TYPE_PERSON,
            body,
        ));
    }
    if let Some((facet, body)) = substrate
        .as_ref()
        .and_then(PreparedPersonSubstrate::facet_put)
    {
        subject_preceding.push(crate::agent_def::SetupEntityPut::borrowed(
            facet,
            crate::registry::ENTITY_TYPE_FACET,
            body,
        ));
    }
    let subjects = PreparedSubjectAgent::after_puts(agent, definition_data, &subject_preceding)?
        .prepare_person_facts_in_txn(vault, txn, person, person_put.as_deref(), at)?;
    Ok(Some(PreparedAgentPerson {
        person,
        person_put,
        substrate,
        subjects,
        at,
    }))
}

impl PreparedAgentPerson {
    pub(crate) fn apply(self, vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        self.apply_with_setup_owners(vault, txn, &mut Vec::new())
    }

    pub(crate) fn apply_with_setup_owners(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        owners: &mut Vec<crate::agent_def::PreparedSetupOwner>,
    ) -> Result<()> {
        if let Some(body) = self.person_put {
            let mut batch = vault.batch_in().put(
                &self.person,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange {
                    start: self.at,
                    end: self.at,
                },
                self.at,
                &body,
            );
            if let Some(substrate) = self.substrate {
                batch = batch.with_prepared_person_substrate(substrate);
            }
            batch.apply(txn)?;
        }
        self.subjects.apply_with_setup_owners(vault, txn, owners)
    }

    pub(crate) fn person_puts(&self) -> impl Iterator<Item = crate::agent_def::SetupEntityPut<'_>> {
        self.person_put
            .iter()
            .map(|body| {
                crate::agent_def::SetupEntityPut::borrowed(
                    self.person,
                    crate::registry::ENTITY_TYPE_PERSON,
                    body,
                )
            })
            .chain(
                self.substrate
                    .iter()
                    .filter_map(|plan| plan.facet_put())
                    .map(|(id, body)| {
                        crate::agent_def::SetupEntityPut::borrowed(
                            id,
                            crate::registry::ENTITY_TYPE_FACET,
                            body,
                        )
                    }),
            )
    }

    pub(crate) fn entity_puts(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.person_put
            .iter()
            .map(|_| self.person)
            .chain(
                self.substrate
                    .iter()
                    .filter_map(|plan| plan.facet_put().map(|(id, _)| id)),
            )
            .chain(self.subjects.entity_puts())
    }
}
