//! Unmet demand on a GPU line (design pass 32, section 3.5): one row for each budget refusal,
//! `over_rung_cap` or `budget_denied`, written at the reserve and nothing else with it. The
//! comparison and the planner card read them.

use serde::{Deserialize, Serialize};

use super::{Bucket, RuleRef};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Vault};

/// The line's refusals, in the order they were written.
const REFUSALS: SideTable<LineRefusalKey, LineRefusal, Named> =
    SideTable::new(&side_table::GPU_LINE_REFUSAL);

/// A refusal row's key: the line, its period, then the row's place in that period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, SideKey)]
pub struct LineRefusalKey {
    /// The lane project the line is set on.
    pub line: EntityId,
    pub period: u32,
    /// 0 is the period's first refusal.
    pub sequence: u64,
}

/// One ask the line's budget could not meet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LineRefusal {
    pub family: EntityId,
    /// The arm the ask was for; `None` for an admission, which has no arm yet.
    pub arm: Option<EntityId>,
    pub rung: u8,
    pub cohort: Option<RuleRef>,
    /// The seconds asked for.
    pub asked_secs: u64,
    /// The bucket that ran out; `None` for a rung cap.
    pub short: Option<Bucket>,
    /// What still fitted: the draw plan's largest fit, or what the rung cap left.
    pub room: u64,
    /// `over_rung_cap` or `budget_denied`.
    pub reason: String,
    /// Who asked; `None` after their erase.
    pub by: Option<EntityId>,
    pub at_ms: u64,
}

/// Writes `refusal` as the next refusal of period `period` of the line `line`, in the
/// caller's write transaction, and answers its key.
///
/// # Errors
///
/// A store failure.
pub(crate) fn record_line_refusal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    line: EntityId,
    period: u32,
    refusal: &LineRefusal,
) -> crate::Result<LineRefusalKey> {
    let sequence = line_refusals_in_txn(vault, wtxn, &line, period)?
        .last()
        .map_or(0, |(key, _)| key.sequence.saturating_add(1));
    let key = LineRefusalKey {
        line,
        period,
        sequence,
    };
    REFUSALS.put(&vault.store, wtxn, &key, refusal)?;
    Ok(key)
}

/// Every refusal of period `period` of the line `line`, in the order they were written.
///
/// # Errors
///
/// A store failure.
pub fn line_refusals_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &EntityId,
    period: u32,
) -> crate::Result<Vec<(LineRefusalKey, LineRefusal)>> {
    let mut prefix = Vec::new();
    line.encode_into(&mut prefix);
    period.encode_into(&mut prefix);
    REFUSALS.scan_from(&vault.store, txn, &prefix)
}

/// Takes the erased actor out of every refusal (the side table's actor scrub): its id is
/// forgotten and the rest of the record stays.
pub(crate) fn erase_refusal_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (key, mut refusal) in REFUSALS.scan(&vault.store, wtxn)? {
        if refusal.by == Some(*actor) {
            refusal.by = None;
            REFUSALS.put(&vault.store, wtxn, &key, &refusal)?;
        }
    }
    Ok(())
}
