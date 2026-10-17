//! The typed effects the composed ask doors write beside their ask (OF-393):
//! a project ask joining its project's list (and a skill tradeoff's route),
//! a widening's binding on the common board, and a report's block
//! continuation. An effect runs in the ask's admission transaction when the
//! ask goes out at once. When the approval mode holds the ask, the effect is
//! kept on the ask's launch hold, never dropped, and runs as the owner's
//! approval releases the ask, revalidated in that transaction.

use std::collections::BTreeSet;

use super::TaskAskDefault;
use super::highway_block::BlockContinuation;
use super::project_tradeoff::ProjectTradeoffRoute;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryResult};
use crate::workspace_roster::ProjectWidenAxis;
use serde::{Deserialize, Serialize};

/// One composed ask door's effect, kept whole until its ask goes out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AskEffect {
    /// A project ask joins `project`'s list while its leader and board are
    /// still `holders`; a skill tradeoff's ask also routes its question.
    Project {
        project: EntityId,
        task: EntityId,
        holders: BTreeSet<EntityId>,
        tradeoff: Option<ProjectTradeoffRoute>,
    },
    /// A widening ask binds its route on the common board.
    Widen(ProjectWidenRoute),
    /// A report's block ask writes the continuation it runs when it settles.
    Block {
        continuation: BlockContinuation,
        label: String,
    },
}

/// The route a cross-project widening ask was addressed by: rechecked, with
/// the policy's fallback, where its binding lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectWidenRoute {
    pub(crate) requesting_project: EntityId,
    pub(crate) other_project: EntityId,
    pub(crate) board_project: EntityId,
    pub(crate) axis: ProjectWidenAxis,
    pub(crate) people: BTreeSet<EntityId>,
    pub(crate) fallback: TaskAskDefault,
}

impl Memory<'_> {
    /// A cross-project widening's ask, whose binding lands on the common
    /// board beside it, or as the owner's approval releases a held ask.
    pub(crate) fn tasks_ask_widen(
        &self,
        input: &super::TaskAskSpec,
        route: ProjectWidenRoute,
    ) -> MemoryResult<super::TaskAskReceipt> {
        self.tasks_ask_composed(input, Some(AskEffect::Widen(route)))
    }

    /// Runs `effect` for the ask `group` as this asking actor, in `txn`:
    /// the admission's transaction, or the approval that released the ask.
    pub(super) fn apply_ask_effect_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        group: EntityId,
        effect: &AskEffect,
    ) -> MemoryResult<()> {
        match effect {
            AskEffect::Project {
                project,
                task,
                holders,
                tradeoff,
            } => {
                self.project_ask_effect_in(txn, group, *project, *task, holders)?;
                if let Some(route) = tradeoff {
                    super::project_tradeoff::route_tradeoff_in(self.vault(), txn, group, route)?;
                }
                Ok(())
            }
            AskEffect::Widen(route) => self.widen_ask_effect_in(txn, group, route),
            AskEffect::Block {
                continuation,
                label,
            } => {
                self.put_block_question_in_txn(txn, group, continuation, label)?;
                Ok(())
            }
        }
    }
}
