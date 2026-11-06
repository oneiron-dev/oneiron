//! Durable per-actor board layouts (BOARD-LAYOUT = A, owner 2026-11-03).
//!
//! One row per actor: its live layout and one pending batch. Every layout
//! verb patches the pending batch, so the board changes once per batch
//! rather than on every call. A TURN projects the pending batch before its
//! accepted history commit activates it; a native run's board activates it
//! at its next render. A poll reads live state only. Revisions keep a newer
//! pending batch and refuse a late overwrite without refusing the board; a
//! fresh row incarnation stops activation after erase and recreation.
//!
//! A new native fork copies its source actor's live and pending layout once,
//! then diverges: its changes never flow back to the parent. An actor with
//! no row of its own renders under the owner's default layout, and the
//! owner's override sections win over every actor's own
//! ([`crate::settings::BoardLayoutSettings`]).

use super::BoardHistoryError;
use super::layout::{BoardLayout, BoardLayoutError, FoldCounts};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};
use heed::RwTxn;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Actor board layout rows. Key: id16 (actor).
const BOARD_LAYOUT: SideTable<EntityId, BoardLayoutRow, Named> =
    SideTable::new(&side_table::CONTEXT_BOARD_LAYOUT);

/// One actor's durable board layout: its live layout, the monotonic stage
/// counter, the last applied revision, one pending batch, and the row's
/// internal incarnation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoardLayoutRow {
    /// The layout this actor's board renders under.
    pub(crate) live: BoardLayout,
    /// The last applied pending revision (`0` before any activation).
    pub(crate) live_revision: u64,
    /// Monotonic stage counter, bumped on every staged write.
    pub(crate) total_revision: u64,
    /// The staged batch awaiting the next turn.
    pub(crate) pending: Option<BoardLayoutPending>,
    /// Fresh row identity at first staging or native fork creation.
    pub(crate) incarnation: [u8; 16],
}

/// One staged batch: the whole layout it sets and its stage revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoardLayoutPending {
    /// The whole staged layout, never a patch at activation time.
    pub(crate) layout: BoardLayout,
    /// The `total_revision` captured when this batch last staged.
    pub(crate) revision: u64,
}

/// The layout a turn projects before its activation, bound to its actor and
/// row incarnation. Only the turn's own history writer, or a native run's
/// board render, activates it.
///
/// Public through `oneiron::context_board` so the HTTP crate can carry it
/// from hydration to the history writer; its fields are private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardLayoutCandidate {
    actor: EntityId,
    incarnation: EntityId,
    live_revision: u64,
    pending_revision: u64,
    layout: BoardLayout,
}

impl BoardLayoutCandidate {
    /// The layout this candidate activates.
    #[must_use]
    pub fn layout(&self) -> &BoardLayout {
        &self.layout
    }

    /// The candidate with the live counts of each fold its batch starts, so
    /// the fold line counts its changes from the turn the fold applied.
    #[must_use]
    pub fn with_fold_baselines(mut self, counts: &BTreeMap<String, FoldCounts>) -> Self {
        self.layout = self.layout.with_fold_baselines(counts);
        self
    }
}

/// One actor's board layout: what renders now, and the batch the next turn
/// applies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BoardLayoutState {
    /// The actor's own layout its board renders under now.
    pub live: BoardLayout,
    /// The batch the next turn applies; absent when none is staged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<BoardLayout>,
    /// The owner's override sections for this actor (every agent's, with
    /// this agent's own laid over them), which win over the actor's own.
    #[serde(default, skip_serializing_if = "is_empty_layout")]
    pub owner_override: BoardLayout,
}

fn is_empty_layout(layout: &BoardLayout) -> bool {
    layout.sections.is_empty()
}

/// Every actor's own live board layout in `txn`, by actor id, for readers
/// that learn from layouts (the Coach's layout suggestions, FIX 12572).
/// Pending batches and the owner's layers are not included.
pub(crate) fn board_layouts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, BoardLayout)>> {
    Ok(BOARD_LAYOUT
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(actor, row)| (actor, row.live))
        .collect())
}

/// An actor's erase removes its board layout row (FIX 3520).
pub(crate) fn erase_board_layout_actor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    BOARD_LAYOUT.delete(&vault.store, txn, actor)?;
    Ok(())
}

/// Copies the source actor's board layout when a new native fork is
/// registered. The caller owns the accepted fork-creation transaction;
/// retries that reuse an existing fork must not call this again.
///
/// Pending stays pending in both actors; the copied counters are
/// independent, and the child gets a fresh incarnation, never a parent
/// candidate. A source with no row leaves the fork with none, so it renders
/// under the owner's default, as its parent does.
pub(crate) fn inherit_board_layout_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
    fork: &EntityId,
) -> Result<()> {
    let Some(mut row) = BOARD_LAYOUT.get(&vault.store, &*txn, source)? else {
        return Ok(());
    };
    row.incarnation = *EntityId::now().as_bytes();
    BOARD_LAYOUT.put(&vault.store, txn, fork, &row)?;
    Ok(())
}

fn layout_refusal(error: BoardLayoutError) -> MemoryError {
    MemoryError::bad_request(error.to_string())
}

impl Memory<'_> {
    /// This actor's own board layout: live plus pending.
    pub fn board_layout(&self) -> MemoryResult<BoardLayoutState> {
        Ok(self.vault().board_layout_state(self.actor())?)
    }

    /// Edits this actor's ONE pending batch: `edit` sees the pending layout,
    /// else the live one, else the owner's default. The result must pass
    /// [`BoardLayout::validate`]. A fold the edit starts or changes carries
    /// no baseline; its activation sets one. Layout preferences are the
    /// actor's own render settings: they grant no read and no write.
    pub fn stage_board_layout(
        &self,
        edit: impl FnOnce(&mut BoardLayout) -> MemoryResult<()>,
    ) -> MemoryResult<BoardLayoutState> {
        let vault = self.vault();
        vault.write_txn_door(crate::store::Callback::Audited, |txn| {
            crate::memory::verify_actor_binding_in_txn(
                vault,
                txn,
                self.actor(),
                self.actor_class(),
            )?;
            let actor = self.actor();
            let store = &vault.store;
            let mut row = match BOARD_LAYOUT.get(store, &*txn, &actor)? {
                Some(row) => row,
                None => BoardLayoutRow {
                    live: vault.board_layout_default_in_txn(&*txn)?,
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
                    "board layout stage counter is exhausted",
                ))?;
            let mut layout = row
                .pending
                .take()
                .map_or_else(|| row.live.clone(), |pending| pending.layout);
            edit(&mut layout)?;
            layout.validate().map_err(layout_refusal)?;
            row.total_revision = next;
            row.pending = Some(BoardLayoutPending {
                layout,
                revision: next,
            });
            BOARD_LAYOUT.put(store, txn, &actor, &row)?;
            let settings =
                crate::settings::board_layout::board_layout_settings_in_txn(vault, &*txn)?;
            Ok(row.state(settings.override_for(actor)))
        })
    }
}

impl BoardLayoutRow {
    fn state(&self, owner_override: BoardLayout) -> BoardLayoutState {
        BoardLayoutState {
            live: self.live.clone(),
            pending: self.pending.as_ref().map(|pending| pending.layout.clone()),
            owner_override,
        }
    }

    fn candidate(&self, actor: EntityId) -> Result<Option<BoardLayoutCandidate>> {
        let Some(pending) = &self.pending else {
            return Ok(None);
        };
        let incarnation = EntityId::from_bytes(self.incarnation)
            .map_err(|_| Error::InvariantViolation("board layout row incarnation is invalid"))?;
        Ok(Some(BoardLayoutCandidate {
            actor,
            incarnation,
            live_revision: self.live_revision,
            pending_revision: pending.revision,
            layout: pending.layout.clone(),
        }))
    }
}

impl Vault {
    /// One actor's board layout in one snapshot: live plus pending, never
    /// creating a row. An actor with no row reads the owner's default as
    /// live, with nothing pending. HTTP callers supply the authenticated
    /// actor; the embedded door checks no credential.
    pub fn board_layout_state(&self, actor: EntityId) -> Result<BoardLayoutState> {
        let rtxn = self.store.env.read_txn()?;
        let settings = crate::settings::board_layout::board_layout_settings_in_txn(self, &rtxn)?;
        Ok(match BOARD_LAYOUT.get(&self.store, &rtxn, &actor)? {
            Some(row) => row.state(settings.override_for(actor)),
            None => BoardLayoutState {
                owner_override: settings.override_for(actor),
                live: settings.default_layout,
                pending: None,
            },
        })
    }

    /// Selects the layout one actor's board renders under, in one snapshot.
    ///
    /// `has_turn` is true for a board whose turn will activate the
    /// selection: an explicit HTTP TURN, a native chat answer, or a native
    /// run's board render. Then the pending batch projects when one is
    /// staged, with the exact candidate the activation must apply. Without a
    /// turn this selects live only and returns no candidate. An actor with
    /// no row selects the owner's default. The layout returned is the one
    /// the board renders: the owner's override sections laid over the
    /// actor's own; the candidate keeps the actor's own layout alone.
    pub fn select_board_layout(
        &self,
        actor: EntityId,
        has_turn: bool,
    ) -> Result<(BoardLayout, Option<BoardLayoutCandidate>)> {
        let rtxn = self.store.env.read_txn()?;
        let settings = crate::settings::board_layout::board_layout_settings_in_txn(self, &rtxn)?;
        let Some(row) = BOARD_LAYOUT.get(&self.store, &rtxn, &actor)? else {
            return Ok((settings.effective(actor, &settings.default_layout), None));
        };
        if !has_turn {
            return Ok((settings.effective(actor, &row.live), None));
        }
        match row.candidate(actor)? {
            Some(candidate) => Ok((
                settings.effective(actor, &candidate.layout),
                Some(candidate),
            )),
            None => Ok((settings.effective(actor, &row.live), None)),
        }
    }

    /// The layout an actor with no row of its own renders under: the
    /// owner's default layout, else the engine's own layout of every section.
    pub(crate) fn board_layout_default_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<BoardLayout> {
        Ok(crate::settings::board_layout::board_layout_settings_in_txn(self, txn)?.default_layout)
    }

    /// The actors a board filter's group names: a project's roster, its
    /// leader and board included. A group that names no project the vault
    /// holds has no members. The caller checks its reader may read the
    /// group first; the roster only narrows rows the reader already reads.
    pub fn board_filter_group_members(
        &self,
        group: EntityId,
    ) -> Result<std::collections::BTreeSet<EntityId>> {
        Ok(self
            .project(group)?
            .map(|project| {
                project
                    .members()
                    .iter()
                    .filter_map(|member| EntityId::from_hex(member).ok())
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Activates a native run board's candidate in its own write, right
    /// after the board it projected rendered: the run's next turn. Drift
    /// skips as [`activate_board_layout_in_txn`] does.
    pub fn activate_board_layout_now(&self, candidate: &BoardLayoutCandidate) -> Result<()> {
        self.write_txn_door(crate::store::Callback::Audited, |txn| {
            activate_board_layout_row_in_txn(self, txn, candidate)
        })
    }
}

/// Activates the exact TURN-projected candidate in the SAME history `RwTxn`,
/// after `stage_board_turn` succeeded and before accept/commit.
///
/// Actor mismatch is the existing `NotTurnAuthor`; every other drift skips
/// silently and never refuses the current board: a missing row (erased after
/// capture) never resurrects, an incarnation mismatch (erase and recreate)
/// never activates, and a live-revision mismatch (another turn already
/// advanced live) never overwrites. When only the pending revision moved,
/// the exact rendered candidate still becomes live while the newer pending
/// batch stays; when the pending revision still matches, it is cleared.
pub(crate) fn activate_board_layout_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    owner: &EntityId,
    turn: &EntityId,
    candidate: &BoardLayoutCandidate,
) -> std::result::Result<(), BoardHistoryError> {
    if candidate.actor != *owner {
        return Err(BoardHistoryError::NotTurnAuthor(*turn));
    }
    activate_board_layout_row_in_txn(vault, txn, candidate)?;
    Ok(())
}

fn activate_board_layout_row_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    candidate: &BoardLayoutCandidate,
) -> Result<()> {
    let Some(mut row) = BOARD_LAYOUT.get(&vault.store, &*txn, &candidate.actor)? else {
        return Ok(());
    };
    if row.incarnation != *candidate.incarnation.as_bytes()
        || row.live_revision != candidate.live_revision
    {
        return Ok(());
    }
    row.live = candidate.layout.clone();
    row.live_revision = candidate.pending_revision;
    if row
        .pending
        .as_ref()
        .is_some_and(|pending| pending.revision == candidate.pending_revision)
    {
        row.pending = None;
    }
    BOARD_LAYOUT.put(&vault.store, txn, &candidate.actor, &row)?;
    Ok(())
}
