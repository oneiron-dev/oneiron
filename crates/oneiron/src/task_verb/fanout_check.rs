//! The exceptional-width check of fan-outs that go out with no hold: a
//! `tasks.ask` census and a wave plan applied through the ungated door
//! (OF-393).
//!
//! The same knob and ladder as a consult fan-out: the vault's threshold row
//! marks the check; a covering standing approval, its rung 0, clears it
//! under AUTO and MANUAL (CHECKIN-PR1-SHAPE Q2), and otherwise the next role
//! is asked. FULL-ACCESS goes before rung 0, as its admission does, so its
//! check is always asked. Nothing here holds, refuses or narrows
//! the work. An asked check names the durable row its caller records in the
//! admitting transaction (`fanout_launch`); the owner settles that row with
//! an acknowledgement, never a denial, because nothing was held.

use super::consult_fanout_store::policy_in;
use super::{CheckInMode, ConsultFanOutScope};
use crate::Vault;
use crate::agent_dispatch::{FanoutStatement, WidthCheckClass};
use crate::error::Result;

/// Raises `statement`'s width check when its width crosses the vault
/// threshold. `scope` keys the rung-0 standing read, taken in `txn`, the
/// caller's writer (FIX 10696); `row_ref` names the durable
/// row the question rides on. `true`: the check asked, and the caller
/// records that row in the same transaction.
pub(super) fn raise_unheld_width_check(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    statement: &mut FanoutStatement,
    scope: &str,
    row_ref: String,
) -> Result<bool> {
    let policy = policy_in(vault, txn, &ConsultFanOutScope::default())?.policy;
    let threshold = u64::from(policy.approval_threshold);
    if !statement.crosses(threshold) {
        return Ok(false);
    }
    let cleared = match policy.mode {
        CheckInMode::AskWhenUnsure | CheckInMode::AlwaysAsk => {
            crate::fanout_auto::covering_approval_in(vault, txn, scope, statement.task_count)
        }
        CheckInMode::NeverAsk => None,
    };
    let (classification, asked) = match cleared {
        Some(row) => (
            WidthCheckClass::AutoClear {
                policy_ref: Some(row.to_hex()),
            },
            false,
        ),
        None => (WidthCheckClass::Asked { row_ref }, true),
    };
    statement.raise_width_check(threshold, classification);
    Ok(asked)
}
