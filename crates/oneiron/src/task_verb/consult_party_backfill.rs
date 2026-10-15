//! One-time open migration for consults minted before ConsultAssignee facts
//! existed. This is a direct pre-GA switch: such a consult gets the one fact
//! its creation would have minted, so a second fact naming anyone else is a
//! fork there too.

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_TASK;
use crate::side_table::{self, SideTable};
use crate::task_authority::{
    ConsultParties, TaskAuthorityFact, TaskAuthorityFactKind, put_task_authority_fact_in_txn,
};
use crate::{EntityId, Vault};

use super::verb_kind::{TaskAssignee, TaskKind};
use super::wire_decode::task_verb_body_in;

pub(super) const BACKFILLED: SideTable<(), [u8; 1], side_table::Raw> =
    SideTable::new(&side_table::TASK_CONSULT_PARTY_BACKFILLED);

impl Vault {
    /// Mints the ConsultAssignee fact of every consult that has an Owner fact
    /// and no party fact: its asker is the owner that fact proves, its
    /// assignee the one its TASK holds now, and each generation the binding
    /// the party holds now. A consult whose facts do not read (a forked
    /// owner) is left without one, and so gives nobody party standing.
    pub(crate) fn backfill_consult_party_facts_on_open(&self) -> Result<()> {
        if BACKFILLED.contains(&self.store, &self.store.env.read_txn()?, &())? {
            return Ok(());
        }
        self.with_write_txn_grouped(|wtxn| {
            if BACKFILLED.contains(&self.store, wtxn, &())? {
                return Ok(());
            }
            let tasks = self
                .store
                .port_entity_raw_records(wtxn)?
                .filter_map(|entry| match entry {
                    Err(error) => Some(Err(error)),
                    Ok((id, raw))
                        if raw.first() == Some(&ENTITY_TYPE_TASK)
                            && raw.len() > ENTITY_METADATA_HEADER_LEN =>
                    {
                        Some(Ok(id))
                    }
                    Ok(_) => None,
                })
                .collect::<Result<Vec<EntityId>>>()?;
            for task_ref in tasks {
                let Ok(Some(body)) = task_verb_body_in(self, wtxn, task_ref) else {
                    continue;
                };
                if body.task_kind() != TaskKind::Consult {
                    continue;
                }
                let Ok(facts) = self.task_authority_facts_in(wtxn, task_ref) else {
                    continue;
                };
                let (Some(asker), ConsultParties::Unminted) =
                    (facts.owner_ref, facts.consult_parties)
                else {
                    continue;
                };
                let assignee = body.assignee.and_then(TaskAssignee::entity_ref);
                let actor_generation = self.actor_binding_generation_in_txn(wtxn, asker)?;
                let assigned_generation = match assignee {
                    Some(assignee) => self.actor_binding_generation_in_txn(wtxn, assignee)?,
                    None => None,
                };
                put_task_authority_fact_in_txn(
                    self,
                    wtxn,
                    TaskAuthorityFact {
                        task_ref,
                        kind: TaskAuthorityFactKind::ConsultAssignee,
                        actor_ref: asker,
                        assigned_ref: assignee,
                        actor_generation,
                        assigned_generation,
                        occurred_at: body.created_at,
                    },
                )?;
            }
            BACKFILLED.put(&self.store, wtxn, &(), &[1])
        })
    }
}
