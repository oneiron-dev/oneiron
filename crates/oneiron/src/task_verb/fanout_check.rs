//! The exceptional-width check of fan-outs the engine never holds: a
//! `tasks.ask` census and a wave plan (OF-393).
//!
//! The same knob and ladder as a consult fan-out: the vault's threshold row,
//! full access records the check, AUTO clears it on a covering standing
//! approval, and otherwise the next role is asked. Nothing here holds,
//! refuses or narrows the work, and Manual mode asks rather than holds,
//! because these fan-outs were never held for width.

use super::consult_fanout_store::policy_in;
use super::{ConsultFanOutMode, ConsultFanOutScope};
use crate::Vault;
use crate::agent_dispatch::{FanoutStatement, WidthCheckClass};
use crate::error::Result;

/// Raises `statement`'s width check when its width crosses the vault
/// threshold. `scope` keys AUTO's standing read; `row_ref` names the durable
/// record the question rides on.
pub(super) fn raise_unheld_width_check(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    statement: &mut FanoutStatement,
    scope: &str,
    row_ref: String,
) -> Result<()> {
    let policy = policy_in(vault, txn, &ConsultFanOutScope::default())?.policy;
    let threshold = u64::from(policy.approval_threshold);
    if !statement.crosses(threshold) {
        return Ok(());
    }
    let classification = match policy.mode {
        ConsultFanOutMode::FullAccess => WidthCheckClass::Recorded,
        ConsultFanOutMode::Auto => {
            match crate::fanout_auto::covering_approval(vault, scope, statement.task_count) {
                Some(row) => WidthCheckClass::AutoClear {
                    policy_ref: Some(row.to_hex()),
                },
                None => WidthCheckClass::Asked { row_ref },
            }
        }
        ConsultFanOutMode::Manual => WidthCheckClass::Asked { row_ref },
    };
    statement.raise_width_check(threshold, classification);
    Ok(())
}
