//! Doors for `tests/idle_wait_returns.rs` (L2-37 PR-1): the wall-clock wait rows, the weekly
//! return-table pass, and one return cell. Compiled only under `--cfg oneiron_test_support`;
//! never API.

use crate::code_run::WaitKey;
use crate::idle_fold::{self, IdleSessionKind, IdleWaitClass};
use crate::{Error, Result, Vault};

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
    let kind = IdleSessionKind::ALL
        .into_iter()
        .find(|kind| kind.as_str() == session_kind)
        .ok_or(Error::InvalidConfig("unknown idle session kind".to_owned()))?;
    let class = IdleWaitClass::ALL
        .into_iter()
        .find(|class| class.as_str() == wait_class)
        .ok_or(Error::InvalidConfig("unknown idle wait class".to_owned()))?;
    Ok(
        idle_fold::return_cell(vault, kind, class, band, weekend)?.map(|cell| IdleReturnCellView {
            returned_after_secs: cell.returned_after_secs,
            never: cell.never,
        }),
    )
}
