//! The exceptional-width check of fan-outs that go out with no hold: a
//! `tasks.ask` census and a wave plan applied through the ungated door
//! (OF-393).
//!
//! The same knob and ladder as a consult fan-out: the vault's threshold row
//! marks the check; under AUTO a covering standing approval clears it, and
//! otherwise the next role is asked. Nothing here holds, refuses or narrows
//! the work. An asked check names the durable row its caller records in the
//! admitting transaction (`fanout_launch`); the owner settles that row with
//! an acknowledgement, never a denial, because nothing was held.

use super::consult_fanout_store::policy_in;
use super::{ConsultFanOutMode, ConsultFanOutScope};
use crate::Vault;
use crate::agent_dispatch::{FanoutStatement, WidthCheckClass};
use crate::error::Result;

/// Raises `statement`'s width check when its width crosses the vault
/// threshold. `scope` keys AUTO's standing read; `row_ref` names the durable
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
        ConsultFanOutMode::Auto => {
            crate::fanout_auto::covering_approval(vault, scope, statement.task_count)
        }
        ConsultFanOutMode::Manual | ConsultFanOutMode::FullAccess => None,
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
