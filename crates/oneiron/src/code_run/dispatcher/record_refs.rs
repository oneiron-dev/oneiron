//! OF-063 on a run's in-core memory writes (FIX 1214). The run rows
//! `vault.claims.put`, `vault.claims.supersede` and `vault.edges.put` carry
//! no verb-table `refs` (a run row has exactly five keys), so the records
//! they name meet the check here, before their write: each must resolve for
//! the writer under the run's host-bound reader, or the write is refused
//! with the receipted invented-reference refusal, as a facade row's is
//! ([`crate::gate::record_references`]). A missing record and one the
//! writer may not read give the same refusal.

use crate::claim::ScopedReadActorKey;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{SelfDispatchOutcome, SelfEffect, SelfFailedResult};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::MemoryError;
use crate::receipt::{ReferenceOutcome, ReferenceRefusalFacts, receipt_reference_refusals};

use super::HostSelfDispatcher;

impl HostSelfDispatcher<'_> {
    /// The refusal `effect`'s write gets when a record it names in `refs`,
    /// each a (field pointer, id) of its run row `row`, does not resolve for
    /// its writer: under `read_as`, the key its door admitted the call with,
    /// else the actor's own read key, and under a slip-woken program's slip
    /// key too. The refusal names the field, never the ref, and is receipted
    /// first. `None` when every record resolves, and on a session-bound run,
    /// whose room rows the vault's reader cannot name.
    ///
    /// # Errors
    /// Storage errors, and a receipt that could not be written.
    pub(super) fn refused_write_reference(
        &self,
        effect: SelfEffect,
        row: &'static str,
        read_as: Option<&ScopedReadActorKey>,
        refs: &[(&'static str, EntityId)],
    ) -> Result<Option<SelfDispatchOutcome>> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(None);
        };
        if refs.is_empty() {
            return Ok(None);
        }
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        let key = match read_as {
            Some(key) => key.clone(),
            None => match memory.read_key() {
                Ok(key) => key,
                Err(error) => return Ok(Some(refused(effect, &error))),
            },
        };
        let slip_key = match self.program_proof() {
            Some(proof) => Some(vault.credential_target_key(proof)?),
            None => None,
        };
        for (pointer, id) in refs {
            let resolves = vault.scoped_read(key.clone()).all_refs_readable(&[*id])?
                && match &slip_key {
                    Some(Some(slip_key)) => vault
                        .scoped_read(slip_key.clone())
                        .all_refs_readable(&[*id])?,
                    Some(None) => false,
                    None => true,
                };
            if !resolves {
                let recorded = receipt_reference_refusals(
                    &memory,
                    &[ReferenceRefusalFacts {
                        actor: memory.actor(),
                        actor_class: memory.actor_class(),
                        row,
                        field: (*pointer).to_owned(),
                        outcome: ReferenceOutcome::Refused,
                    }],
                )?;
                let error = crate::gate::record_references::invented_reference(pointer, recorded);
                return Ok(Some(refused(effect, &error)));
            }
        }
        Ok(None)
    }
}

/// `effect` failed with `error`'s code, as the run's other typed refusals
/// fail.
fn refused(effect: SelfEffect, error: &MemoryError) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Failed(SelfFailedResult {
        effect,
        error: error.code.clone(),
        code: None,
        disk_floor: None,
    })
}
