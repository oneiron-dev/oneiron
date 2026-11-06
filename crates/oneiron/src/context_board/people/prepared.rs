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
}

pub(crate) fn prepare_agent_person_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    definition_data: &[u8],
    name: &str,
    at: u64,
) -> Result<Option<PreparedAgentPerson>> {
    if crate::dreamer_runner::authority::is_base_agent_actor(&agent)? {
        return Ok(None);
    }
    let person = EntityId::derive(AGENT_PERSON_DOMAIN, &[agent.as_bytes()])?;
    let prepared_agent = PreparedSubjectAgent::new(agent, definition_data)?;
    // The old anchor read precedes the PERSON-create branch: it may project
    // the candidate definition, but cannot assume a PERSON will be created.
    if prepared_agent.has_subject_in_txn(vault, txn, at)? {
        return Ok(None);
    }
    let (person_put, substrate) = if vault.store.port_entity_record(txn, &person)?.is_none() {
        let body = agent_person_body(name)?;
        let substrate = crate::batch::prepare_person_substrate(
            &vault.store,
            txn,
            person,
            TimeRange { start: at, end: at },
            at,
        )?;
        (Some(body), Some(substrate))
    } else {
        (None, None)
    };
    let subjects = prepared_agent.prepare_person_facts_in_txn(
        vault,
        txn,
        person,
        person_put.as_deref(),
        at,
    )?;
    Ok(Some(PreparedAgentPerson {
        person,
        person_put,
        substrate,
        subjects,
    }))
}

impl PreparedAgentPerson {
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
