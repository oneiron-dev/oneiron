//! The authenticated roster-update door (OF-417 slice 2). A roster write
//! lands through the project's own write door, and the members it newly
//! seats are filed into the project's home room through the three consents
//! in the same commit, by the bound caller and only for the subjects that
//! caller stands for. The roster is never standing by itself: everyone else
//! joins on their own first write or an explicit join.
use super::*;
use crate::WriteActor;
use crate::memory::{Memory, MemoryResult};

impl Memory<'_> {
    /// Writes `record` as `project`'s new state through
    /// [`Vault::write_project`], then files the joins of the seats the
    /// served authority newly gives, as this bound caller (never an id the
    /// request names). Only an existing served project is updated; a birth
    /// goes through its own door. A held write, or one that serves no
    /// authority, files no join.
    pub fn projects_write_roster(
        &self,
        project: EntityId,
        record: &ProjectRecord,
    ) -> MemoryResult<ProjectWriteOutcome> {
        let vault = self.vault();
        let caller = WriteActor::new(self.actor(), self.actor_class());
        self.with_verified_actor_write_txn(|txn| {
            let (_, before) = vault
                .effective_project_in_txn(txn, project)?
                .ok_or(Error::EntityNotFound)?;
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            let outcome = vault.write_project_in_txn(txn, project, record, now)?;
            if matches!(outcome, ProjectWriteOutcome::Installed(_))
                && let Some((installed, after)) = vault.effective_project_in_txn(txn, project)?
            {
                let added = after
                    .seats
                    .difference(&before.seats)
                    .cloned()
                    .collect::<BTreeSet<_>>();
                if !added.is_empty() {
                    crate::workspace_roster::workplace_join::file_roster_joins_in_txn(
                        vault,
                        txn,
                        EntityId::from_hex(&installed.home_room)?,
                        &added,
                        caller,
                        now,
                    )?;
                }
            }
            Ok(outcome)
        })
    }
}
