//! The hook cursor rows: per fact binding and source, the last position
//! delivered to that binding, whether it stands paused, and on the tick
//! feed the feed's head when the binding was enabled (ARCH-0080 §4
//! Delivery).

use serde::{Deserialize, Serialize};

use crate::runtime_hooks::source::{
    self, ClaimChangelogPosition, FactPosition, FactSource, SchedulePosition, SettlementPosition,
    SurfaceInboundPosition,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::{HookPhase, PackHookBinding};
use crate::{EntityId, Result, Vault};

/// One cursor per binding and source.
const CURSORS: SideTable<(EntityId, [u8; 1]), CursorRow, Named> =
    SideTable::new(&side_table::HOOKS_CURSOR);

/// A cursor row: the last position delivered to its binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::runtime_hooks) struct CursorRow {
    /// `None` is the start of the source.
    position: Option<CursorPosition>,
    /// The binding was seen disabled; it restarts where it is re-enabled.
    pub(in crate::runtime_hooks) paused: bool,
    updated_at: u64,
    /// On the tick feed's row, the feed's head when the binding was last
    /// enabled, 0 for an empty feed: a tick past it was released while the
    /// binding was bound ([`enabled_before_tick_in_txn`]). `None` on every
    /// other source's row, and on a row written before enables kept it,
    /// which reads as enabled before every tick.
    #[serde(default)]
    enabled_tick_head: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CursorPosition {
    ClaimChangelog([u8; 16]),
    Settlement(u64),
    Schedule(u64),
    SurfaceInbound(u64),
}

impl CursorRow {
    pub(in crate::runtime_hooks) fn new(position: Option<FactPosition>, at: u64) -> Self {
        Self {
            position: position.map(|position| match position {
                FactPosition::ClaimChangelog(position) => {
                    CursorPosition::ClaimChangelog(position.0)
                }
                FactPosition::Settlement(position) => CursorPosition::Settlement(position.0),
                FactPosition::Schedule(position) => CursorPosition::Schedule(position.0),
                FactPosition::SurfaceInbound(position) => {
                    CursorPosition::SurfaceInbound(position.0)
                }
            }),
            paused: false,
            updated_at: at,
            enabled_tick_head: None,
        }
    }

    pub(in crate::runtime_hooks) fn paused(self, at: u64) -> Self {
        Self {
            paused: true,
            updated_at: at,
            ..self
        }
    }

    pub(in crate::runtime_hooks) fn position(self) -> Option<FactPosition> {
        self.position.map(|position| match position {
            CursorPosition::ClaimChangelog(id) => {
                FactPosition::ClaimChangelog(ClaimChangelogPosition(id))
            }
            CursorPosition::Settlement(sequence) => {
                FactPosition::Settlement(SettlementPosition(sequence))
            }
            CursorPosition::Schedule(sequence) => {
                FactPosition::Schedule(SchedulePosition(sequence))
            }
            CursorPosition::SurfaceInbound(sequence) => {
                FactPosition::SurfaceInbound(SurfaceInboundPosition(sequence))
            }
        })
    }
}

pub(in crate::runtime_hooks) fn cursor(
    vault: &Vault,
    binding: EntityId,
    source: FactSource,
) -> Result<Option<CursorRow>> {
    let rtxn = vault.store.env.read_txn()?;
    cursor_in_txn(vault, &rtxn, binding, source)
}

/// [`cursor`] in the caller's snapshot.
pub(in crate::runtime_hooks) fn cursor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: EntityId,
    source: FactSource,
) -> Result<Option<CursorRow>> {
    CURSORS.get(&vault.store, txn, &(binding, [source.tag()]))
}

/// The bindings whose cursor in `source` stands unpaused, read in `txn`, in
/// binding order. A binding with no cursor there, or a paused one, takes a
/// start when it next runs or is enabled ([`source::enable_start_in_txn`]).
pub(in crate::runtime_hooks) fn unpaused_cursor_bindings_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: FactSource,
) -> Result<Vec<EntityId>> {
    let mut bindings = Vec::new();
    for row in CURSORS.iter_from(&vault.store, txn, &[])? {
        let ((binding, tag), cursor) = row?;
        if tag == [source.tag()] && !cursor.paused {
            bindings.push(binding);
        }
    }
    Ok(bindings)
}

pub(in crate::runtime_hooks) fn put_cursor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: EntityId,
    source: FactSource,
    row: &CursorRow,
) -> Result<()> {
    CURSORS.put(&vault.store, txn, &(binding, [source.tag()]), row)
}

/// Commits a fact binding's cursor with its real enable, disable or
/// replacement write. A selector-only update of an already-enabled binding
/// keeps its cursor; a disabled-to-enabled transition starts at the enable
/// write, including the settlement head (FIX 10078). A binding with no
/// `previous` row is fresh, so a watcher's starts before the earliest tick of
/// a TASK still open (FIX 4749). Each enable keeps the tick feed's head in
/// this write ([`enable_cursor_in_txn`]): a watch TASK whose tick was
/// released, and so settled it, at or before that head never runs this
/// binding, which was bound after its work was done (review #6784).
pub(crate) fn sync_binding_cursor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: EntityId,
    previous: Option<&PackHookBinding>,
    current: &PackHookBinding,
) -> Result<()> {
    if current.selector.phase != HookPhase::Fact {
        return Ok(());
    }
    let at = vault.store.clock.now_recorded_at();
    if !current.enabled {
        for source in FactSource::ALL {
            let key = (binding, [source.tag()]);
            let prior = CURSORS.get(&vault.store, txn, &key)?;
            if prior.is_some_and(|row| row.paused) {
                continue;
            }
            let row = prior.unwrap_or_else(|| CursorRow::new(None, at)).paused(at);
            CURSORS.put(&vault.store, txn, &key, &row)?;
        }
        return Ok(());
    }
    let restart = previous.is_none_or(|previous| {
        !previous.enabled
            || previous.code != current.code
            || previous.source != current.source
            || previous.hook_version != current.hook_version
            || previous.body_hash != current.body_hash
    });
    if !restart {
        return Ok(());
    }
    for source in FactSource::ALL {
        let row = enable_cursor_in_txn(vault, txn, &binding, source, previous.is_none())?;
        put_cursor_in_txn(vault, txn, binding, source, &row)?;
    }
    Ok(())
}

/// The cursor row an enable writes for `binding` in `source`, now: where
/// [`source::enable_start_in_txn`] starts it, and on the tick feed, that
/// feed's head, its enable-time tick head. A fresh binding still starts
/// before the earliest tick of a TASK still open, and is offered that
/// tick; a watch TASK's tick at or before the head was released, settling
/// the TASK, before the binding was bound, so it never reaches it
/// ([`enabled_before_tick_in_txn`]).
pub(in crate::runtime_hooks) fn enable_cursor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &EntityId,
    source: FactSource,
    fresh: bool,
) -> Result<CursorRow> {
    let start = source::enable_start_in_txn(vault, txn, binding, source, fresh)?;
    let mut row = CursorRow::new(start, vault.store.clock.now_recorded_at());
    if source == FactSource::Schedule {
        let head = match source::head_in_txn(vault, txn, source)? {
            Some(FactPosition::Schedule(SchedulePosition(sequence))) => sequence,
            _ => 0,
        };
        row.enabled_tick_head = Some(head);
    }
    Ok(row)
}

/// Whether `binding` was enabled before the tick at `position` was
/// released: the enable-time tick head its tick feed cursor keeps stands
/// before `position`. A binding with no kept head, its row written before
/// enables kept one, reads as enabled before every tick.
pub(in crate::runtime_hooks) fn enabled_before_tick_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: EntityId,
    position: FactPosition,
) -> Result<bool> {
    let key = (binding, [FactSource::Schedule.tag()]);
    Ok(CURSORS
        .get(&vault.store, txn, &key)?
        .and_then(|row| row.enabled_tick_head)
        .is_none_or(|head| FactPosition::Schedule(SchedulePosition(head)) < position))
}

/// Moves `binding`'s cursor to `position` unless it already stands there or
/// past it. The enable-time tick head stays with the binding as it reads on.
pub(in crate::runtime_hooks) fn advance_cursor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: EntityId,
    position: FactPosition,
    at: u64,
) -> Result<()> {
    let source = position.source();
    let held = CURSORS.get(&vault.store, txn, &(binding, [source.tag()]))?;
    if held
        .and_then(CursorRow::position)
        .is_some_and(|current| current >= position)
    {
        return Ok(());
    }
    let row = CursorRow {
        enabled_tick_head: held.and_then(|row| row.enabled_tick_head),
        ..CursorRow::new(Some(position), at)
    };
    put_cursor_in_txn(vault, txn, binding, source, &row)
}
