//! Durable per-actor TASKS token budgets for HTTP board hydration and native chat.
//!
//! A TURN projects one pending snapshot before its accepted history commit
//! activates it. Polls read live state only. Revisions preserve newer pending
//! writes and reject late overwrites without refusing the board; a fresh row
//! incarnation prevents activation after erase and recreation.
//!
//! New native attenuated forks copy the source actor's live and pending
//! TASKS state once, then diverge. Kept task ids share the budget
//! snapshot. Whole-section folds use the same accepted snapshot. Other fork
//! families, program turns, shares and owner
//! defaults stay open.
//! Checkpoint rows remain unclassified. See
//! `docs/ops/context-board-tasks-layout.md` for the supported scope.

mod fold;

use super::BoardHistoryError;
use crate::memory::{Memory, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};
use fold::TaskFoldMark;
use heed::RwTxn;
use serde::{Deserialize, Serialize};

/// Actor-staged TASKS budget rows. Key: id16 (actor).
const TASKS_BUDGET: SideTable<EntityId, TasksBudgetRow, Named> =
    SideTable::new(&side_table::CONTEXT_BOARD_TASKS_BUDGET);

/// One actor's durable TASKS layout row: its live default, the monotonic
/// stage counter, the last applied revision, one pending staged write, and
/// the row's internal incarnation. Tokens and ids only, no notes or content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TasksBudgetRow {
    /// Live default this actor's ROOT board renders under: `None` is the
    /// 100-row behavior, `Some(0)` a literal zero.
    pub(crate) live: Option<u64>,
    /// Native task ids kept open beyond the optional-row projection.
    pub(crate) live_keep: Vec<EntityId>,
    pub(crate) live_folded: bool,
    pub(crate) fold_baseline: Vec<TaskFoldMark>,
    /// The last applied pending revision (`0` before any activation).
    pub(crate) live_revision: u64,
    /// Monotonic stage counter, bumped on every staged write.
    pub(crate) total_revision: u64,
    /// Staged write awaiting TURN activation: `None` is no pending;
    /// `Some` with `value: None` is a staged reset.
    pub(crate) pending: Option<TasksBudgetPending>,
    /// Fresh row identity at staging or native fork creation (`EntityId::now` bytes).
    pub(crate) incarnation: [u8; 16],
}

/// One staged TASKS budget write: its value and its captured stage revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TasksBudgetPending {
    /// Staged value: `None` resets to 100-row behavior, `Some(v)` sets
    /// (`Some(0)` a literal zero).
    pub(crate) value: Option<u64>,
    /// Full keep snapshot, never a patch at activation time.
    pub(crate) keep: Vec<EntityId>,
    pub(crate) folded: bool,
    /// The `total_revision` captured when this write staged.
    pub(crate) revision: u64,
}

/// The TASKS selection a turn projects before its accepted history commit,
/// bound to its actor and row incarnation. A chat answer's TURN may be
/// minted after capture; only its actual history writer activates this.
///
/// Public through `oneiron::context_board` so the HTTP crate can carry it
/// from hydration to the history writer; all fields are private and are
/// consumed only by the new TURN record method (through
/// [`activate_tasks_layout_in_txn`], called only there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TasksLayoutCandidate {
    actor: EntityId,
    incarnation: EntityId,
    live_revision: u64,
    pending_revision: u64,
    value: Option<u64>,
    keep: Vec<EntityId>,
    folded: bool,
    fold_baseline: Option<Vec<TaskFoldMark>>,
}

/// One actor's ROOT TASKS layout state for GET/POST: live plus pending.
/// `pending: None` is no pending; `Some` with `value: None` is a staged
/// reset. Engine `u64`; the HTTP DTO converts to `usize` losslessly on 64-bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TasksLayoutState {
    pub live: Option<u64>,
    pub live_keep: Vec<EntityId>,
    pub live_folded: bool,
    pub pending: Option<TasksLayoutPendingState>,
}

/// The staged write of [`TasksLayoutState`]: `value: None` is a staged reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TasksLayoutPendingState {
    pub value: Option<u64>,
    pub keep: Vec<EntityId>,
    pub folded: bool,
}

/// One exact render selection. Its baseline and accepted-history candidate
/// stay private; the host carries the same owned value through assembly.
#[derive(Debug, Clone, Default)]
pub struct TasksLayoutSelection {
    pub budget: Option<usize>,
    pub keep: Vec<EntityId>,
    pub folded: bool,
    baseline: Vec<TaskFoldMark>,
    capture_baseline: bool,
    candidate: Option<TasksLayoutCandidate>,
}

impl TasksLayoutSelection {
    /// Explicit per-render budgets keep the original stored-layout bypass.
    #[must_use]
    pub fn for_budget(budget: usize) -> Self {
        Self {
            budget: Some(budget),
            ..Self::default()
        }
    }

    /// The exact candidate after the full admitted fold source was captured.
    #[must_use]
    pub fn candidate(&self) -> Option<TasksLayoutCandidate> {
        self.candidate.clone()
    }
}

/// An actor's erase removes its TASKS-budget row (FIX 3520).
pub(crate) fn erase_tasks_budget_actor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    TASKS_BUDGET.delete(&vault.store, txn, actor)?;
    Ok(())
}

/// Copies the actual source actor's TASKS layout when a new native fork is
/// registered. The caller owns the accepted fork-creation transaction; retries
/// that reuse an existing fork must not call this again.
///
/// Pending stays pending in both actors. The copied counters are independent,
/// and the child gets a fresh incarnation rather than any parent candidate.
/// An absent source becomes an explicit native default, with no parent lookup.
pub(crate) fn inherit_tasks_layout_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
    fork: &EntityId,
) -> Result<()> {
    let incarnation = *EntityId::now().as_bytes();
    let mut row = TASKS_BUDGET
        .get(&vault.store, &*txn, source)?
        .unwrap_or(TasksBudgetRow {
            live: None,
            live_keep: Vec::new(),
            live_folded: false,
            fold_baseline: Vec::new(),
            live_revision: 0,
            total_revision: 0,
            pending: None,
            incarnation,
        });
    row.incarnation = incarnation;
    TASKS_BUDGET.put(&vault.store, txn, fork, &row)?;
    Ok(())
}

impl Memory<'_> {
    /// Stages the token allotment while preserving the same pending batch's
    /// kept rows (or the live keep set when no batch is pending).
    pub fn stage_tasks_layout(&self, value: Option<usize>) -> MemoryResult<TasksLayoutState> {
        self.stage_tasks_layout_update(Some(value), None)
    }

    /// Patches this actor's ONE pending TASKS snapshot. An omitted field
    /// keeps its latest pending value, else its live value. Explicit
    /// `Some(None)` resets the budget; `Some(Vec::new())` clears kept ids.
    /// Kept ids are metadata, not authority: renderers may use only their
    /// already-admitted task source. No authored text enters this row.
    pub fn stage_tasks_layout_update(
        &self,
        budget: Option<Option<usize>>,
        keep: Option<Vec<EntityId>>,
    ) -> MemoryResult<TasksLayoutState> {
        self.stage_tasks_layout_patch(budget, keep, None)
    }

    /// Patches budget, kept ids and whole-section fold in ONE pending batch.
    /// The accepted open-to-folded transition captures its baseline. Setting
    /// `folded: true` again preserves it; omitted fields preserve pending, else live.
    pub fn stage_tasks_layout_patch(
        &self,
        budget: Option<Option<usize>>,
        keep: Option<Vec<EntityId>>,
        folded: Option<bool>,
    ) -> MemoryResult<TasksLayoutState> {
        let budget = budget.map(|value| value.map(|v| v as u64));
        let keep = keep.map(|mut ids| {
            ids.sort_unstable();
            ids.dedup();
            ids
        });
        self.vault()
            .write_txn_door(crate::store::Callback::Audited, |txn| {
                // Own render preferences grant no shared-content write. Keep
                // the actor binding check in this same audited transaction.
                crate::memory::verify_actor_binding_in_txn(
                    self.vault(),
                    txn,
                    self.actor(),
                    self.actor_class(),
                )?;
                let actor = self.actor();
                let store = &self.vault().store;
                let mut row = match TASKS_BUDGET.get(store, &*txn, &actor)? {
                    Some(row) => row,
                    None => TasksBudgetRow {
                        live: None,
                        live_keep: Vec::new(),
                        live_folded: false,
                        fold_baseline: Vec::new(),
                        live_revision: 0,
                        total_revision: 0,
                        pending: None,
                        incarnation: *EntityId::now().as_bytes(),
                    },
                };
                let next = row
                    .total_revision
                    .checked_add(1)
                    .ok_or(Error::InvariantViolation(
                        "tasks layout stage counter is exhausted",
                    ))?;
                let previous = row.pending.take().unwrap_or_else(|| TasksBudgetPending {
                    value: row.live,
                    keep: row.live_keep.clone(),
                    folded: row.live_folded,
                    revision: row.live_revision,
                });
                row.total_revision = next;
                row.pending = Some(TasksBudgetPending {
                    value: budget.unwrap_or(previous.value),
                    keep: keep.clone().unwrap_or(previous.keep),
                    folded: folded.unwrap_or(previous.folded),
                    revision: next,
                });
                TASKS_BUDGET.put(store, txn, &actor, &row)?;
                Ok(row.state())
            })
    }
}

impl TasksBudgetRow {
    fn state(&self) -> TasksLayoutState {
        TasksLayoutState {
            live: self.live,
            live_keep: self.live_keep.clone(),
            live_folded: self.live_folded,
            pending: self
                .pending
                .as_ref()
                .map(|pending| TasksLayoutPendingState {
                    value: pending.value,
                    keep: pending.keep.clone(),
                    folded: pending.folded,
                }),
        }
    }
}

impl Vault {
    /// Reads one actor's ROOT TASKS layout state in one snapshot: live plus
    /// pending, never creating a row. Missing rows read as live `None` with
    /// no pending (100-row behavior). HTTP callers supply the authenticated
    /// actor; the embedded Vault door does not check credentials.
    pub fn tasks_layout_state(&self, actor: EntityId) -> Result<TasksLayoutState> {
        let rtxn = self.store.env.read_txn()?;
        let row = TASKS_BUDGET.get(&self.store, &rtxn, &actor)?;
        Ok(match row {
            Some(row) => row.state(),
            None => TasksLayoutState {
                live: None,
                live_keep: Vec::new(),
                live_folded: false,
                pending: None,
            },
        })
    }

    /// Selects one actor's exact ROOT TASKS snapshot. A no-turn read is
    /// live-only. A TURN selects pending when present, and carries that
    /// candidate to the SAME accepted history writer. Explicit per-request
    /// budgets bypass this selection through `TasksLayoutSelection::for_budget`.
    pub fn select_tasks_layout(
        &self,
        actor: EntityId,
        has_turn: bool,
        cap_tok: usize,
    ) -> Result<TasksLayoutSelection> {
        let rtxn = self.store.env.read_txn()?;
        let Some(row) = TASKS_BUDGET.get(&self.store, &rtxn, &actor)? else {
            return Ok(TasksLayoutSelection::default());
        };
        let mut selection = TasksLayoutSelection {
            budget: clamp_stored(row.live, cap_tok)?,
            keep: row.live_keep,
            folded: row.live_folded,
            baseline: row.fold_baseline,
            capture_baseline: false,
            candidate: None,
        };
        if !has_turn {
            return Ok(selection);
        }
        if let Some(pending) = row.pending {
            selection.budget = clamp_stored(pending.value, cap_tok)?;
            selection.keep = pending.keep.clone();
            selection.folded = pending.folded;
            selection.capture_baseline = pending.folded && !row.live_folded;
            let incarnation = EntityId::from_bytes(row.incarnation).map_err(|_| {
                Error::InvariantViolation("tasks layout row incarnation is invalid")
            })?;
            selection.candidate = Some(TasksLayoutCandidate {
                actor,
                incarnation,
                live_revision: row.live_revision,
                pending_revision: pending.revision,
                value: pending.value,
                keep: pending.keep,
                folded: pending.folded,
                fold_baseline: None,
            });
        }
        Ok(selection)
    }
}

/// Clamps one stored TASKS request to the actual global cap for projection
/// only: `None` stays `None` (100-row path), `Some` clamps with
/// `min(stored_u64, cap_as_u64)` before the `usize` cast, proven to fit
/// because the clamped value never exceeds the `usize` cap. No `usize::MAX`
/// fallback and no policy default.
fn clamp_stored(stored: Option<u64>, cap_tok: usize) -> Result<Option<usize>> {
    let Some(value) = stored else {
        return Ok(None);
    };
    let clamped = value.min(cap_tok as u64);
    let fitted = usize::try_from(clamped)
        .map_err(|_| Error::InvariantViolation("tasks layout clamped budget does not fit"))?;
    Ok(Some(fitted))
}

/// Activates the exact TURN-projected TASKS candidate in the SAME history
/// `RwTxn`, after `stage_board_turn` succeeded and before accept/commit.
///
/// Actor mismatch is the existing `NotTurnAuthor`; every other drift skips
/// silently and never refuses the current board: a missing row (erased after
/// capture) never resurrects, an incarnation mismatch (erase+recreate ABA)
/// never activates, and a live-revision mismatch (another successful TURN
/// already advanced live) never overwrites. When only the pending revision
/// moved, the exact rendered candidate still becomes live while the newer
/// pending batch is retained; when the pending revision still matches, it is
/// cleared. Called only by the new TURN record method.
pub(crate) fn activate_tasks_layout_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    owner: &EntityId,
    turn: &EntityId,
    candidate: &TasksLayoutCandidate,
) -> std::result::Result<(), BoardHistoryError> {
    if candidate.actor != *owner {
        return Err(BoardHistoryError::NotTurnAuthor(*turn));
    }
    let Some(mut row) = TASKS_BUDGET.get(&vault.store, &*txn, owner)? else {
        return Ok(());
    };
    if row.incarnation != *candidate.incarnation.as_bytes() {
        return Ok(());
    }
    if row.live_revision != candidate.live_revision {
        return Ok(());
    }
    row.live = candidate.value;
    row.live_keep = candidate.keep.clone();
    row.live_folded = candidate.folded;
    if !candidate.folded {
        row.fold_baseline.clear();
    } else if let Some(baseline) = &candidate.fold_baseline {
        row.fold_baseline = baseline.clone();
    }
    row.live_revision = candidate.pending_revision;
    if row
        .pending
        .as_ref()
        .is_some_and(|pending| pending.revision == candidate.pending_revision)
    {
        row.pending = None;
    }
    TASKS_BUDGET.put(&vault.store, txn, owner, &row)?;
    Ok(())
}
