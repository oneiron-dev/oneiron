//! Cross-project widening routes to an ordinary ask on the common board.
use super::leader_chat::{denied, lineage, project_in};
use super::*;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::task_verb::{
    TaskAskDefault, TaskAskQuestion, TaskAskReceipt, TaskAskSpec, TaskAskTarget,
};

const PREFIX: &[u8] = b"project.widen_ask.v1/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectWidenAxis {
    Scope,
    Budget,
    Roster,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWidenAsk {
    pub requesting_project: EntityId,
    pub other_project: EntityId,
    pub board_project: EntityId,
    pub axis: ProjectWidenAxis,
    pub ask: EntityId,
}

impl Memory<'_> {
    /// Talk needs no ask. Only requests for broader scope, budget or roster
    /// travel upward to the closest shared ancestor's board as an ordinary ask.
    /// `question` is an existing, audience-checked CLAIM or TURN reference;
    /// it never embeds another project's content in a sideways claim.
    pub fn project_widen_ask(
        &self,
        requesting: EntityId,
        other: EntityId,
        axis: ProjectWidenAxis,
        question: TaskAskQuestion,
        until: u64,
    ) -> MemoryResult<TaskAskReceipt> {
        let vault = self.vault();
        let (board_project, people) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let own = project_in(vault, &txn, requesting)?;
            if requesting == other || own.leader != self.actor().to_hex() {
                return Err(MemoryError::from(denied()));
            }
            let other_lineage: BTreeSet<_> = lineage(vault, &txn, other)?.into_iter().collect();
            let common = lineage(vault, &txn, requesting)?
                .into_iter()
                .find(|id| other_lineage.contains(id))
                .ok_or_else(|| MemoryError::from(denied()))?;
            let project = project_in(vault, &txn, common)?;
            let board = project
                .board
                .iter()
                .map(|id| EntityId::from_hex(id))
                .collect::<Result<BTreeSet<_>>>()?;
            if board.is_empty() {
                return Err(MemoryError::from(denied()));
            }
            (common, board)
        };
        let mut spec = TaskAskSpec::shorthand(
            Some(TaskAskTarget::People(people.clone())),
            question,
            Some(until),
            TaskAskDefault::Hold,
        );
        spec.intent_key = format!(
            "project.widen/{}/{}/{:?}/{}",
            requesting.to_hex(),
            other.to_hex(),
            axis,
            spec.intent_key
        );
        self.tasks_ask_with_txn_effect(&spec, |txn, ask| {
            // Revalidate the route in the writer snapshot. If a leader, ancestor
            // or board changed during admission, the ask and its TASKs roll back.
            if project_in(vault, txn, requesting)?.leader != self.actor().to_hex() {
                return Err(MemoryError::from(denied()));
            }
            let other_lineage: BTreeSet<_> = lineage(vault, txn, other)?.into_iter().collect();
            let current_board = lineage(vault, txn, requesting)?
                .into_iter()
                .find(|id| other_lineage.contains(id))
                .ok_or_else(|| MemoryError::from(denied()))?;
            let mut board = project_in(vault, txn, current_board)?;
            let current_people = board
                .board
                .iter()
                .map(|id| EntityId::from_hex(id))
                .collect::<Result<BTreeSet<_>>>()?;
            if current_board != board_project || current_people != people {
                return Err(MemoryError::from(denied()));
            }
            let binding = ProjectWidenAsk {
                requesting_project: requesting,
                other_project: other,
                board_project,
                axis,
                ask,
            };
            vault.store.vault_meta.put(
                txn,
                &[PREFIX, ask.as_bytes()].concat(),
                &encode(&binding)?,
            )?;
            board.asks.push(ask.to_hex());
            let now = vault.store.clock.now_recorded_at();
            vault
                .batch_in()
                .put(
                    &board_project,
                    vault.project_type_byte()?,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode(&board)?,
                )
                .apply(txn)?;
            Ok(())
        })
    }
}

impl Vault {
    /// The source and destination of a routed project ask, not an authority grant.
    pub fn project_widen_ask_route(&self, ask: EntityId) -> Result<Option<ProjectWidenAsk>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &[PREFIX, ask.as_bytes()].concat())?
            .map(|raw| decode(&raw))
            .transpose()
    }
}
