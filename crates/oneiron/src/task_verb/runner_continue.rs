//! The TASK a continued outside session realizes (census L10-17).
//!
//! The continue door mints it under the owner's principal in the caller's
//! writer and never routes it, so no Dreamer attempt is queued for it: the
//! bound runner work realizes it.

use rmpv::Value;

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::MemoryResult;

use super::create_validation::ValidatedTaskCreate;
use super::verb_kind::TaskKind;

impl Vault {
    /// The TASK a continued outside session realizes (census L10-17):
    /// minted under the owner's principal in the caller's writer and never
    /// routed, so no Dreamer attempt is queued for it: the bound runner
    /// work realizes it.
    ///
    /// Like the reconciliation minter's shape but unrouted: no
    /// `route_created_task_in_txn` (it would queue a Dreamer realization),
    /// no rate-limit record, no ceiling check.
    ///
    /// # Errors
    ///
    /// A TASK row that does not encode; a store failure.
    pub(crate) fn mint_runner_continue_task_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        label: String,
        spec: Value,
        provenance: &Value,
        now: u64,
    ) -> MemoryResult<EntityId> {
        let validated = ValidatedTaskCreate::engine_internal(
            TaskKind::Standard,
            None,
            spec,
            crate::task_type::TaskTypeRef::seed(
                crate::task_type::SeedTaskType::Build,
                crate::task_type::SEEDED_TREE_VERSION,
            ),
        );
        self.memory(owner, EdgeActorClass::Human).mint_task_in_txn(
            txn,
            &validated,
            Some(label),
            owner,
            provenance,
            now,
        )
    }
}
