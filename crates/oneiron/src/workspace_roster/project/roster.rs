//! The authenticated roster-update door (OF-417 slice 2). A roster write
//! lands through the project's own write door, and the members it newly
//! seats are filed into the project's home room through the OF-531 consents
//! in the same commit, by the bound caller: a join for each subject that
//! caller stands for, an invitation for each unrelated person, which takes
//! effect once she accepts. The invitation governs her join receipt and its
//! participation evidence, not the seat the signed roster gives her.
use super::*;
use crate::WriteActor;
use crate::memory::{Memory, MemoryResult};

/// `vault.projects.roster.write`: an existing project's new signed record.
/// The caller is the bound actor, never a field of the request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRosterWriteRequest {
    pub project: EntityId,
    /// The signed record, validated by serde and the project's proof door.
    #[schemars(with = "serde_json::Value")]
    pub record: ProjectRecord,
}

/// What a roster write did: whether its record was installed (false: held,
/// with its owner question stored), and the invitations it filed for the
/// people it newly seats and its caller cannot speak for. The caller hands
/// each `join_ref` to its person, who answers it through `rooms.consent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRosterWriteOutcome {
    pub installed: bool,
    pub invitations: Vec<crate::workspace_roster::JoinOutcome>,
}

impl Memory<'_> {
    /// Writes `record` as `project`'s new state through
    /// [`Vault::write_project`], then files the joins and invitations of the
    /// seats the served authority newly gives, as this bound caller (never an
    /// id the request names). Only an existing served project is updated; a
    /// birth goes through its own door. A held write, or one that serves no
    /// authority, files nothing.
    pub fn projects_write_roster(
        &self,
        project: EntityId,
        record: &ProjectRecord,
    ) -> MemoryResult<ProjectRosterWriteOutcome> {
        let vault = self.vault();
        let caller = WriteActor::new(self.actor(), self.actor_class());
        self.with_verified_actor_write_txn(|txn| {
            let (_, before) = vault
                .effective_project_in_txn(txn, project)?
                .ok_or(Error::EntityNotFound)?;
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            let outcome = vault.write_project_in_txn(txn, project, record, now)?;
            let mut invitations = Vec::new();
            if matches!(outcome, ProjectWriteOutcome::Installed(_))
                && let Some((installed, after)) = vault.effective_project_in_txn(txn, project)?
            {
                let added = after
                    .seats
                    .difference(&before.seats)
                    .cloned()
                    .collect::<BTreeSet<_>>();
                if !added.is_empty() {
                    invitations =
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
            Ok(ProjectRosterWriteOutcome {
                installed: matches!(outcome, ProjectWriteOutcome::Installed(_)),
                invitations,
            })
        })
    }
}
