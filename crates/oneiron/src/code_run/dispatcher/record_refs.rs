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
        let refusal = crate::gate::record_references::admit_run_row_references(
            &memory,
            row,
            read_as,
            self.program_proof(),
            refs,
        )?;
        Ok(refusal.map(|error| refused(effect, &error)))
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
