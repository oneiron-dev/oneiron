//! A member's bound run reads its context on that member's own lane (FIX
//! 5416): the memory and chat a step resolves to, less every row the
//! member's grants do not read, which the step's context counts in its
//! notice. Nothing here refuses: a withheld row, even every one, is left
//! out. The lane is the member's grant key, rebuilt from the binding their
//! run's wrapper stores wherever context resolves; no credential is kept.
//! Owner- and agent-bound runs never reach it: theirs meets each private
//! thread's cut, their binder's own (FIX 6412), and a run an agent or the
//! system bound meets that binder's own admission too (FIX 6715).

use crate::agent_dispatch::AgentDispatcher;
use crate::attempt_queue::AttemptRecord;
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadActorKey};
use crate::context_projection::ResolvedContextProjection;
use crate::conversation::AudienceCache;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;

/// How the rows an agent's or the system's own admission leaves out of the
/// run it bound are told (CALLS "FIX 6715 own-entry selector notice"): in
/// the binder's count-only `workflow_context_narrowed` notice, beside its
/// private-thread cut, never naming a row or another member's join.
const OWN_ENTRY_SELECTOR_NOTICE: OwnEntryNotice = OwnEntryNotice::CountOnlyBinderNarrowed;

/// The notice [`OWN_ENTRY_SELECTOR_NOTICE`] picks.
enum OwnEntryNotice {
    /// [`ResolvedContextProjection::binder_narrowed`]'s count-only notice.
    CountOnlyBinderNarrowed,
}

/// Whether a binder's cut refills what it left out with more rows (CALLS
/// "FIX 6715 no refill after own-entry filtering"): it does not. A
/// descriptor's limit stays a maximum, as after a member's lane or a
/// private-thread cut, and a wholly filtered context is empty, never an
/// error.
const SELECTOR_REFILL_AFTER_BINDER_FILTER: bool = false;
const _: () = assert!(!SELECTOR_REFILL_AFTER_BINDER_FILTER);

/// Whether a binder's cut keeps the sections it leaves in as they resolved
/// (CALLS "FIX 6715 selector order kept"): it does, a stable filter, so the
/// projection stays Layers, Memory, Chat, Briefing, newest-learned first.
const SELECTOR_ORDER_KEPT: bool = true;
const _: () = assert!(SELECTOR_ORDER_KEPT);

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

    /// The owner or agent who bound the run `row` wraps, as its stored TASK
    /// binding names them, never the leaf agent, the payer or the caller.
    /// `None` for a member's run ([`Self::workflow_member`]), a TASK-less
    /// one and every other row.
    pub(in crate::agent_dispatch) fn workflow_binder(
        &self,
        row: &AttemptRecord,
    ) -> Result<Option<WriteActor>> {
        if self.workflow_member(row)?.is_some() {
            return Ok(None);
        }
        let txn = self.vault.store.env.read_txn()?;
        Ok(self
            .workflow_task_source_in_txn(&txn, row)?
            .map(|bind| bind.bound_by))
    }

    /// `projection` less every memory and chat section whose row one of
    /// `binders` does not read: an owner's or agent's bound run meets each
    /// private thread's cut under its binder's own CONTENT rule (FIX 6412),
    /// and each agent or system binder's own admission as well, by the one
    /// check its own transcript and digest reads meet (`own_entry_admits_in`,
    /// FIX 5861, 6715). The owner's or a person's binding adds no admission
    /// check, and no grant, facet or floor stands beside these. A section
    /// whose row cannot be named or judged against a thread is left out too,
    /// as is one its admission check cannot judge. The rest keep their order
    /// and nothing refills them (`SELECTOR_ORDER_KEPT`,
    /// `SELECTOR_REFILL_AFTER_BINDER_FILTER`). Nothing here refuses; a store
    /// or room-walk failure the admission check meets is an error, as it is
    /// on those reads.
    pub(in crate::agent_dispatch) fn binder_context(
        &self,
        projection: ResolvedContextProjection,
        binders: &[WriteActor],
    ) -> Result<ResolvedContextProjection> {
        if binders.is_empty()
            || (projection.memory_sections.is_empty() && projection.chat_sections.is_empty())
        {
            return Ok(projection);
        }
        let reads = binders
            .iter()
            .map(|binder| {
                ScopedReadActorKey::with_actor_class(
                    binder.entity_ref().to_hex(),
                    binder.actor_class().gate_actor_class(),
                )
                .map(|key| self.vault.scoped_read(key))
                .ok_or(Error::InvariantViolation(
                    "a binder's id builds no read key",
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        // The agents and the system among them read by their own admission
        // (FIX 6715); the owner's and a person's binding add no such check.
        let own_entry: Vec<EntityId> = binders
            .iter()
            .filter(|binder| {
                matches!(
                    binder.actor_class(),
                    EdgeActorClass::Agent | EdgeActorClass::System
                )
            })
            .map(|binder| binder.entity_ref())
            .collect();
        let txn = self.vault.store.env.read_txn()?;
        let dbs = self.vault.store.read();
        let entry = AudienceCache::default();
        let kept = |sections: &[String]| -> Result<Vec<String>> {
            let mut kept = Vec::with_capacity(sections.len());
            for section in sections {
                let Ok(row) = section_row(section) else {
                    continue;
                };
                if reads
                    .iter()
                    .all(|read| read.private_threads_admit_in(&txn, &row).unwrap_or(false))
                    && own_entry_admits_in(self.vault, &entry, &dbs, &txn, row, &own_entry)?
                {
                    kept.push(section.clone());
                }
            }
            Ok(kept)
        };
        let memory = kept(&projection.memory_sections)?;
        let chat = kept(&projection.chat_sections)?;
        Ok(match OWN_ENTRY_SELECTOR_NOTICE {
            OwnEntryNotice::CountOnlyBinderNarrowed => projection.binder_narrowed(memory, chat),
        })
    }
}

/// Whether each of `readers`, an agent or the system who bound the run,
/// reads `row` as it stands in `txn` by its own admission (FIX 5861, 6715):
/// the one check an unbound agent's transcript and digest reads meet
/// (`AudienceCache::own_entry_readable_raw`), its errors theirs. No reader,
/// or a row that is gone, adds nothing here.
fn own_entry_admits_in(
    vault: &crate::Vault,
    entry: &AudienceCache,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    row: EntityId,
    readers: &[EntityId],
) -> Result<bool> {
    if readers.is_empty() {
        return Ok(true);
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &row)? else {
        return Ok(true);
    };
    for reader in readers {
        if !entry.own_entry_readable_raw(vault, dbs, txn, row, &raw, *reader)? {
            return Ok(false);
        }
    }
    Ok(true)
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
