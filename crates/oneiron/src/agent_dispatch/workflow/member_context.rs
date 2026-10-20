//! A member's bound run reads its context on that member's own lane (FIX
//! 5416): the memory and chat a step resolves to, less every row the
//! member's grants do not read, which the step's context counts in its
//! notice. Nothing here refuses: a withheld row, even every one, is left
//! out. The lane is the member's grant key, rebuilt from the binding their
//! run's wrapper stores wherever context resolves; no credential is kept.
//! Owner- and agent-bound runs never reach it.

use crate::agent_dispatch::AgentDispatcher;
use crate::attempt_queue::AttemptRecord;
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadActorKey};
use crate::context_projection::ResolvedContextProjection;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

impl AgentDispatcher<'_> {
    /// The member whose bound run `row` wraps: a registered wrapper whose
    /// TASK binding requires a payer and names a person other than the vault
    /// owner. `None` for every other row, the owner's and an agent's runs
    /// included: the owner bound through the person door reads his full
    /// context, as at his own door (FIX 6289).
    pub(in crate::agent_dispatch) fn workflow_member(
        &self,
        row: &AttemptRecord,
    ) -> Result<Option<EntityId>> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(self
            .workflow_task_source_in_txn(&txn, row)?
            .filter(|bind| {
                bind.payer_required && bind.bound_by.actor_class() == EdgeActorClass::Human
            })
            .map(|bind| bind.bound_by.entity_ref())
            .filter(|person| {
                !crate::memory::actor_is_vault_owner_in_txn(
                    self.vault,
                    &txn,
                    *person,
                    EdgeActorClass::Human,
                )
                .unwrap_or(false)
            }))
    }

    /// `projection` as `member`'s own grant lane reads it: each memory and
    /// chat section's row judged by that lane's point read at every claim
    /// status, in one snapshot, and only the readable ones kept, in order.
    /// The key is the one a non-owner's handle with no credential reads
    /// under. Its grants are judged at the clock the vault last persisted,
    /// which the workflow host persists before it runs a step; this opens
    /// no writer, as it may run inside one.
    pub(in crate::agent_dispatch) fn member_context(
        &self,
        projection: ResolvedContextProjection,
        member: EntityId,
    ) -> Result<ResolvedContextProjection> {
        if projection.memory_sections.is_empty() && projection.chat_sections.is_empty() {
            return Ok(projection);
        }
        let lane = ScopedReadActorKey::with_actor_class(
            member.to_hex(),
            EdgeActorClass::Human.gate_actor_class(),
        )
        .ok_or(Error::InvariantViolation(
            "a member's id builds no read key",
        ))?
        .require_access_grants(Some(member));
        let read = self
            .vault
            .scoped_read(lane)
            .with_claim_status(ClaimReadStatus::Recorded);
        let txn = self.vault.store.env.read_txn()?;
        let memory = readable_in(&read, &txn, &projection.memory_sections)?;
        let chat = readable_in(&read, &txn, &projection.chat_sections)?;
        Ok(projection.lane_narrowed(memory, chat))
    }
}

/// Of `sections`, the ones whose row `read` reads in `txn`, body included,
/// in order. Every section is read, however many.
fn readable_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    sections: &[String],
) -> Result<Vec<String>> {
    let rows = sections
        .iter()
        .map(String::as_str)
        .map(section_row)
        .collect::<Result<Vec<_>>>()?;
    Ok(sections
        .iter()
        .zip(read.get_entities_parts_in_txn(txn, &rows)?)
        .filter_map(|(section, row)| row.map(|_| section.clone()))
        .collect())
}

/// The row a context section names: `<domain>:cl_<hex>` or `tn_<hex>`.
fn section_row(section: &str) -> Result<EntityId> {
    let hex = section
        .rsplit_once(":cl_")
        .map(|(_, hex)| hex)
        .or_else(|| section.strip_prefix("tn_"))
        .ok_or(Error::InvariantViolation("a context section names no row"))?;
    EntityId::from_hex(hex)
}
