//! Cross-project widening routes to an ordinary ask on the common board.
use super::leader_chat::{denied, lineage, project_in};
use super::*;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::task_verb::{
    ProjectWidenRoute, TaskAskDefault, TaskAskQuestion, TaskAskReceipt, TaskAskSpec, TaskAskTarget,
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
        let (board_project, people, fallback) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let fallback = crate::gate::resolve_policy_manifest(&vault.store, &txn)?
                .project_collaboration()
                .ok_or_else(|| MemoryError::from(denied()))?
                .widen_ask_fallback;
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
            (common, board, fallback)
        };
        let fallback = match fallback {
            crate::gate::ProjectWidenAskFallback::Hold => TaskAskDefault::Hold,
            crate::gate::ProjectWidenAskFallback::AskMe => TaskAskDefault::AskMe,
        };
        let mut spec = TaskAskSpec::shorthand(
            Some(TaskAskTarget::People(people.clone())),
            question,
            Some(until),
            fallback,
        );
        spec.intent_key = format!(
            "project.widen/{}/{}/{:?}/{}",
            requesting.to_hex(),
            other.to_hex(),
            axis,
            spec.intent_key
        );
        self.tasks_ask_widen(
            &spec,
            ProjectWidenRoute {
                requesting_project: requesting,
                other_project: other,
                board_project,
                axis,
                people,
                fallback,
            },
        )
    }

    /// A widening ask's effect: the route and the policy's fallback are
    /// revalidated in the writer, so a changed policy cannot land an ask
    /// with a stale fallback choice, and the binding lands on the common
    /// board.
    pub(crate) fn widen_ask_effect_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ask: EntityId,
        route: &ProjectWidenRoute,
    ) -> MemoryResult<()> {
        let vault = self.vault();
        let current = crate::gate::resolve_policy_manifest(&vault.store, txn)?
            .project_collaboration()
            .ok_or_else(|| MemoryError::from(denied()))?;
        let selected = match current.widen_ask_fallback {
            crate::gate::ProjectWidenAskFallback::Hold => TaskAskDefault::Hold,
            crate::gate::ProjectWidenAskFallback::AskMe => TaskAskDefault::AskMe,
        };
        if selected != route.fallback
            || project_in(vault, txn, route.requesting_project)?.leader != self.actor().to_hex()
        {
            return Err(MemoryError::from(denied()));
        }
        let other_lineage: BTreeSet<_> = lineage(vault, txn, route.other_project)?
            .into_iter()
            .collect();
        let current_board = lineage(vault, txn, route.requesting_project)?
            .into_iter()
            .find(|id| other_lineage.contains(id))
            .ok_or_else(|| MemoryError::from(denied()))?;
        let (mut board, effective) = vault
            .effective_project_in_txn(txn, current_board)?
            .ok_or_else(|| MemoryError::from(denied()))?;
        let current_people = effective
            .board
            .iter()
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<BTreeSet<_>>>()?;
        if current_board != route.board_project || current_people != route.people {
            return Err(MemoryError::from(denied()));
        }
        let binding = ProjectWidenAsk {
            requesting_project: route.requesting_project,
            other_project: route.other_project,
            board_project: route.board_project,
            axis: route.axis,
            ask,
        };
        vault
            .store
            .vault_meta
            .put(txn, &[PREFIX, ask.as_bytes()].concat(), &encode(&binding)?)?;
        board.asks.push(ask.to_hex());
        let now = vault.store.clock.now_recorded_at();
        vault
            .batch_in()
            .put(
                &route.board_project,
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
