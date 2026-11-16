//! Doors for `tests/idle_wait_returns.rs` (L2-37 PR-1): the wall-clock wait rows, the weekly
//! return-table pass, and one return cell; and for `tests/idle_fold_horizon.rs` (PR-2): a run's
//! step outputs and kind marks, a return cell put as a rebuild writes one, and a wait's due and
//! made idle call. Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_run::{
    CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord, CodeRunStepCheckpoint,
    ExecutorStorage, WaitKey,
};
use crate::compaction::{FoldKind, FoldMark};
use crate::idle_fold::{self, IdleCall, IdleSessionKind, IdleWaitClass};
use crate::{EntityId, Error, Result, Vault};

/// One recorded wait, its kind and class by name.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleWaitView {
    pub key: WaitKey,
    /// `connected`, `hosted` or `unknown`.
    pub session_kind: &'static str,
    /// `user` or `tool`.
    pub wait_class: &'static str,
    pub parked_at_ms: u64,
    pub returned_at_ms: Option<u64>,
    pub never: bool,
}

/// One return cell: the sorted gaps in seconds and the never count.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleReturnCellView {
    pub returned_after_secs: Vec<u32>,
    pub never: u32,
}

/// Every recorded wait, in key order.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn waits(vault: &Vault) -> Result<Vec<IdleWaitView>> {
    Ok(idle_fold::waits(vault)?
        .into_iter()
        .map(|(key, wait)| IdleWaitView {
            key,
            session_kind: wait.session_kind.as_str(),
            wait_class: wait.wait_class.as_str(),
            parked_at_ms: wait.parked_at_ms,
            returned_at_ms: wait.returned_at_ms,
            never: wait.never,
        })
        .collect())
}

/// The Coach's weekly pass at `now_secs`, without its attempt; `true` when it rebuilt.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn rebuild(vault: &Vault, now_secs: u64) -> Result<bool> {
    idle_fold::rebuild_return_tables(vault, now_secs)
}

/// The cell of `session_kind` and `wait_class` (by name) in `band` (0 to 5) on a weekday or a
/// weekend, as the last rebuild wrote it.
///
/// # Errors
/// An unknown kind or class name, and storage.
#[doc(hidden)]
pub fn cell(
    vault: &Vault,
    session_kind: &str,
    wait_class: &str,
    band: u8,
    weekend: bool,
) -> Result<Option<IdleReturnCellView>> {
    let (kind, class) = kind_and_class(session_kind, wait_class)?;
    Ok(
        idle_fold::return_cell(vault, kind, class, band, weekend)?.map(|cell| IdleReturnCellView {
            returned_after_secs: cell.returned_after_secs,
            never: cell.never,
        }),
    )
}

/// The session kind and wait class of these names.
fn kind_and_class(
    session_kind: &str,
    wait_class: &str,
) -> Result<(IdleSessionKind, IdleWaitClass)> {
    let kind = IdleSessionKind::ALL
        .into_iter()
        .find(|kind| kind.as_str() == session_kind)
        .ok_or(Error::InvalidConfig("unknown idle session kind".to_owned()))?;
    let class = IdleWaitClass::ALL
        .into_iter()
        .find(|class| class.as_str() == wait_class)
        .ok_or(Error::InvalidConfig("unknown idle wait class".to_owned()))?;
    Ok((kind, class))
}

/// Puts the cell of `session_kind` and `wait_class` (by name) in `band` on a weekday or a
/// weekend, as a rebuild writes it: `returned_after_secs` sorted, and `never`.
///
/// # Errors
/// An unknown kind or class name, and storage.
#[doc(hidden)]
pub fn put_cell(
    vault: &Vault,
    (session_kind, wait_class): (&str, &str),
    (band, weekend): (u8, bool),
    returned_after_secs: &[u32],
    never: u32,
) -> Result<()> {
    let (kind, class) = kind_and_class(session_kind, wait_class)?;
    let mut returned_after_secs = returned_after_secs.to_vec();
    returned_after_secs.sort_unstable();
    idle_fold::put_return_cell(
        vault,
        (kind, class),
        (band, weekend),
        idle_fold::IdleReturnCell {
            returned_after_secs,
            never,
        },
    )
}

/// Writes `run`'s replay record with one step per entry of `observations`, each step's
/// observation body stored as the executor stores it, under the run.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn seed_step_observations(vault: &Vault, run: EntityId, observations: &[&[u8]]) -> Result<()> {
    let mut record = CodeRunReplayRecord::new(run, CodeRunDeterminism::new(0, [0; 32]));
    for (seq, body) in (0_u64..).zip(observations.iter().copied()) {
        let output = CodeRunRawOutput::from_bytes(
            crate::engine_executor::observation_output_path(seq),
            body,
        )?;
        vault.put_code_run_raw_output(Some(run), &output, body)?;
        record.outputs.push(output);
        record.step_checkpoints.push(CodeRunStepCheckpoint::new(
            seq,
            format!("t{seq}"),
            [0; 32],
            0,
        )?);
    }
    vault.put_code_run_replay_record(&record)
}

/// Marks `run`'s steps `from` through `through` for a fold of their outputs by kind
/// (`repl_output`), as the fold verb does at step `marked_at`; returns the mark's fold number.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn mark_output_fold(
    vault: &Vault,
    run: EntityId,
    (from, through): (u64, u64),
    marked_at: u64,
) -> Result<u64> {
    ExecutorStorage::Canonical(vault).update_code_run_folds(run, |ledger| {
        ledger.last = ledger.last.saturating_add(1);
        ledger.marks.push(FoldMark {
            fold: ledger.last,
            from,
            through,
            note: None,
            failed: None,
            kind: Some(FoldKind::ReplOutput),
            marked_at: Some(marked_at),
        });
        ledger.last
    })
}

/// `run`'s fold ledger by fold number: its pending marks and its landed folds by kind.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldLedgerView {
    pub pending_marks: Vec<u64>,
    pub kind_folds: Vec<u64>,
}

/// `run`'s fold ledger by fold number.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn fold_ledger(vault: &Vault, run: EntityId) -> Result<FoldLedgerView> {
    let ledger = ExecutorStorage::Canonical(vault).code_run_folds(run)?;
    Ok(FoldLedgerView {
        pending_marks: ledger.marks.iter().map(|mark| mark.fold).collect(),
        kind_folds: ledger
            .folds
            .iter()
            .filter(|fold| fold.kind.is_some())
            .map(|fold| fold.fold)
            .collect(),
    })
}

/// When `key`'s idle call is due, in unix milliseconds, while it is due.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn due_ms(vault: &Vault, key: &WaitKey) -> Result<Option<u64>> {
    Ok(idle_fold::due_of(vault, key)?.map(|due| due.due_ms))
}

/// The Keeps `key`'s wait got before its due idle call, while it is due.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn due_keeps(vault: &Vault, key: &WaitKey) -> Result<Option<u32>> {
    Ok(idle_fold::due_of(vault, key)?.map(|due| due.keeps))
}

/// Sets `key`'s due idle call's Keeps count, for the last-ask test.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn set_due_keeps(vault: &Vault, key: &WaitKey, keeps: u32) -> Result<()> {
    idle_fold::set_due_keeps(vault, key, keeps)
}

/// The idle call a wait got.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleCallView {
    /// Sent one refresh of the cached prefix and asked again before it expires.
    Keep {
        keeps: u32,
        at_ms: u64,
    },
    /// `folds` folds landed, whose bodies held about `tokens` prompt tokens.
    Fold {
        folds: u32,
        tokens: u64,
        keeps: u32,
        at_ms: u64,
    },
    Expire {
        keeps: u32,
        at_ms: u64,
    },
}

/// The idle call `key`'s wait got.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn idle_call(vault: &Vault, key: &WaitKey) -> Result<Option<IdleCallView>> {
    Ok(
        idle_fold::idle_call_of(vault, key)?.map(|record| match record.call {
            IdleCall::Keep => IdleCallView::Keep {
                keeps: record.keeps,
                at_ms: record.at_ms,
            },
            IdleCall::Fold { folds, tokens } => IdleCallView::Fold {
                folds,
                tokens,
                keeps: record.keeps,
                at_ms: record.at_ms,
            },
            IdleCall::Expire => IdleCallView::Expire {
                keeps: record.keeps,
                at_ms: record.at_ms,
            },
        }),
    )
}

/// Takes the folds idle calls landed while `run` was parked, as its next entry does.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn take_fold_boundary(vault: &Vault, run: EntityId) -> Result<Option<Vec<u64>>> {
    idle_fold::take_parked_fold_boundary(vault, run)
}
