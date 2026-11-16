//! The context board's owner Setting keys (DESIGN 15-setting-primitive; restriction wave 18): how
//! many rows each board section shows, and how many bytes of a stated reason, before it counts or
//! cuts the rest. Each default is the section's fixed cap before these keys, so a board renders as
//! it did until the owner moves one. The board's token cap and its shed order still bound what
//! renders; a key only moves a section's own cap. Each key is the owner's alone: the render budget
//! is not agent state, and an agent cannot grow it. A larger value is the looser one, so an agent's
//! change waits on the owner's answer. An unreadable row reads 0, the section's tightest form.

use oneiron_records::context_board::tasks::projection::TASK_FITS_CAP;

use super::TasksSection;
use super::layout::FOLD_ATTENTION_ROWS_MAX;
use super::readers::{REASON_SHOWN_BYTES, ROWS_SHOWN};
use super::room::ROOM_INVITE_CAP;
use super::unprocessed::UNPROCESSED_LIMIT;
use crate::Vault;
use crate::error::Result;
use crate::setting::{Kind, Setting, lower_is_tighter};

// Every fixed cap below fits a u32 many times over; the casts only change the type.
fn default_tasks_rows_shown() -> u32 {
    TasksSection::RENDER_ROW_CAP as u32
}

fn default_tasks_fits_shown() -> u32 {
    TASK_FITS_CAP as u32
}

fn default_fold_attention_rows() -> u32 {
    FOLD_ATTENTION_ROWS_MAX as u32
}

fn default_unprocessed_max_items() -> u32 {
    UNPROCESSED_LIMIT as u32
}

fn default_room_invite_shown() -> u32 {
    ROOM_INVITE_CAP as u32
}

fn default_readers_rows_shown() -> u32 {
    ROWS_SHOWN
}

fn default_readers_reason_bytes() -> u32 {
    REASON_SHOWN_BYTES as u32
}

/// The tightest value of every key here: nothing shown beyond the section's counts.
fn none_shown() -> u32 {
    0
}

crate::setting::setting_keys! {
    /// TASKS rows the board renders before its `tasks: +N more` footer counts the rest (default
    /// 100). 0 renders the footer alone. A request with an explicit TASKS token budget fits its
    /// rows to that budget instead, as before.
    pub(crate) TASKS_ROWS_SHOWN: u32 = "context_board.tasks.rows_shown" {
        kind: Kind::new(default_tasks_rows_shown)
            .strictest(none_shown)
            .tighter(lower_is_tighter::<u32>),
    };
    /// Persons a TASKS row's `fits:` hint names, best fit first (default 3). 0 names none.
    pub(crate) TASKS_FITS_SHOWN: u32 = "context_board.tasks.fits_shown" {
        kind: Kind::new(default_tasks_fits_shown)
            .strictest(none_shown)
            .tighter(lower_is_tighter::<u32>),
    };
    /// Attention rows a folded section's line names beside each count before `+N` counts the
    /// rest (default 3). 0 shows the counts alone.
    pub(crate) FOLD_ATTENTION_ROWS: u32 = "context_board.fold.attention_rows" {
        kind: Kind::new(default_fold_attention_rows)
            .strictest(none_shown)
            .tighter(lower_is_tighter::<u32>),
    };
    /// Heavy memories the board's unprocessed list collects in one call before its walk stops
    /// (default 128); priority is exact within the collected set. A larger value walks further
    /// on each board read. 0 lists none.
    pub(crate) UNPROCESSED_MAX_ITEMS: u32 = "context_board.unprocessed.max_items" {
        kind: Kind::new(default_unprocessed_max_items)
            .strictest(none_shown)
            .tighter(lower_is_tighter::<u32>),
    };
    /// Persons the ROOM `invite?:` hint names before `+N` counts the rest (default 5). A layout
    /// share may name more, never fewer. 0 shows the count alone.
    pub(crate) ROOM_INVITE_SHOWN: u32 = "context_board.room.invite_shown" {
        kind: Kind::new(default_room_invite_shown)
            .strictest(none_shown)
            .tighter(lower_is_tighter::<u32>),
    };
    /// Newest logged reads, and newest review asks, each the READERS block shows (default 4 of
    /// each). Its Grant rows and counts show whatever this is. 0 shows no read or ask row.
    pub(crate) READERS_ROWS_SHOWN: u32 = "context_board.readers.rows_shown" {
        kind: Kind::new(default_readers_rows_shown)
            .strictest(none_shown)
            .tighter(lower_is_tighter::<u32>),
    };
    /// Bytes of a read's or ask's stated reason a READERS row quotes (default 160), cut back to a
    /// character boundary. 0 quotes an empty reason.
    pub(crate) READERS_REASON_BYTES: u32 = "context_board.readers.reason_bytes" {
        kind: Kind::new(default_readers_reason_bytes)
            .strictest(none_shown)
            .tighter(lower_is_tighter::<u32>),
    };
}

/// The attention rows a fold line names beside each count at this vault: the owner's
/// `context_board.fold.attention_rows`, else [`FOLD_ATTENTION_ROWS_MAX`]. A host reads it once per
/// board and passes it to [`super::apply_board_layout`].
#[must_use]
pub fn fold_attention_rows(vault: &Vault) -> usize {
    read_count(vault, &FOLD_ATTENTION_ROWS) as usize
}

/// The value `key` holds at the vault: the owner's row, else the key's default; an unreadable row
/// reads 0. A store that cannot open a read shows the default, since the board's other reads
/// report that failure themselves.
pub(crate) fn read_count(vault: &Vault, key: &Setting<u32>) -> u32 {
    let read = || -> Result<u32> {
        let txn = vault.store.env.read_txn()?;
        Ok(key.read_in_txn(vault, &txn, &[], None)?.value)
    };
    read().unwrap_or_else(|_| key.kind.default_typed())
}
