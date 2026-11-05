//! Closed authority carried only by the typed SKILL state door.

#[cfg(feature = "sync")]
use super::{SkillLifecycle, SkillRecord};
#[cfg(feature = "sync")]
use crate::claim::ClaimApprovalStatus;
use crate::error::Result;
use crate::store::Store;
use crate::{EntityId, TimeRange};
use heed::RoTxn;

#[cfg(feature = "sync")]
pub(crate) struct SkillStateWrite {
    snapshot: crate::entity_doc::SkillStateSnapshot,
    lifecycle: SkillLifecycle,
    approval: ClaimApprovalStatus,
}

#[cfg(not(feature = "sync"))]
#[derive(Debug)]
pub(crate) enum SkillStateWrite {}

#[cfg(feature = "sync")]
impl std::fmt::Debug for SkillStateWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillStateWrite")
            .field("entity", &self.entity())
            .finish_non_exhaustive()
    }
}

impl SkillStateWrite {
    #[cfg(feature = "sync")]
    pub(super) fn prepare(
        store: &Store,
        txn: &RoTxn<'_>,
        entity: EntityId,
        updated: &SkillRecord,
    ) -> Result<Option<Self>> {
        Ok(
            crate::entity_doc::SkillStateSnapshot::capture(store, txn, entity, updated)?.map(
                |snapshot| Self {
                    snapshot,
                    lifecycle: updated.lifecycle_status,
                    approval: updated.approval_status,
                },
            ),
        )
    }

    #[cfg(feature = "sync")]
    pub(super) fn apply(
        self,
        vault: &crate::Vault,
        txn: &mut heed::RwTxn<'_>,
        data: Vec<u8>,
        successor: Option<EntityId>,
    ) -> Result<()> {
        let (occurred, learned_at) = self.times();
        let mut batch = vault.batch_in().put(
            &self.entity(),
            crate::registry::ENTITY_TYPE_SKILL,
            occurred,
            learned_at,
            &data,
        );
        if let Some(successor) = successor {
            batch = batch.edge(
                &successor,
                crate::edge::EdgeKind::Supersedes,
                &self.entity(),
                crate::edge::EdgeKind::Supersedes
                    .default_weight()
                    .unwrap_or(0.3),
            );
        }
        batch.apply_skill_state(txn, self)
    }

    pub(crate) fn revalidate(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<()> {
        #[cfg(feature = "sync")]
        {
            self.snapshot.current(store, txn, entity)
        }
        #[cfg(not(feature = "sync"))]
        {
            match *self {}
        }
    }

    pub(crate) fn entity(&self) -> EntityId {
        #[cfg(feature = "sync")]
        {
            self.snapshot.entity()
        }
        #[cfg(not(feature = "sync"))]
        {
            match *self {}
        }
    }

    #[cfg(feature = "sync")]
    pub(super) fn times(&self) -> (TimeRange, u64) {
        self.snapshot.times()
    }

    pub(crate) fn validate_carrier(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        metadata: (u8, TimeRange, u64),
        data: &[u8],
    ) -> Result<()> {
        #[cfg(feature = "sync")]
        {
            self.snapshot.validate_carrier(
                store,
                txn,
                entity,
                metadata,
                data,
                self.lifecycle,
                self.approval,
            )
        }
        #[cfg(not(feature = "sync"))]
        {
            match *self {}
        }
    }

    pub(crate) fn materialize(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        #[cfg(feature = "sync")]
        {
            self.snapshot
                .materialize(store, txn, entity, data, self.lifecycle)
        }
        #[cfg(not(feature = "sync"))]
        {
            match *self {}
        }
    }
}
