//! An Owner's whole-vault export pass's judge of rows it knows only by what
//! they were made from, and its verdicts kept past the pass's snapshot (fix
//! list row 15416).

use std::collections::{BTreeMap, BTreeSet};

use super::{ExportJudge, ExportMet};
use crate::EntityId;
use crate::error::Result;

impl ExportJudge<'_, '_, '_> {
    /// Whether the copy carries what was made from exactly the rows `inputs`
    /// (a saved run's output, fix list row 15416): every one of them, each
    /// judged as [`Self::carries`] judges it. What was made from rows not all
    /// known (`None`) is of a source this vault cannot name, and stays home.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn carries_all(&mut self, inputs: Option<&[EntityId]>) -> Result<bool> {
        let Some(inputs) = inputs else {
            self.judge.met.unidentified = true;
            return Ok(false);
        };
        let mut carried = true;
        for id in inputs {
            carried &= self.carries(*id, None)?;
        }
        Ok(carried)
    }

    /// The pass's settled verdicts, kept past its snapshot, for a copy
    /// whose rows are known only once that snapshot is gone.
    pub(crate) fn settle(self) -> ExportVerdicts {
        ExportVerdicts {
            reached: self
                .judge
                .lineage
                .map_or_else(BTreeMap::new, |lineage| lineage.reached),
            met: self.judge.met,
        }
    }
}

/// An export pass's judge once its snapshot is gone (fix list row 15416):
/// what it met, and the carried members' mailboxes each row it admitted
/// reached, for the rows the copy turns out to ship.
pub(crate) struct ExportVerdicts {
    met: ExportMet,
    reached: BTreeMap<EntityId, BTreeSet<EntityId>>,
}

impl ExportVerdicts {
    /// The row `id`, which the pass carried, goes into the copy, as
    /// [`ExportJudge::ships`] marks it.
    pub(crate) fn ships(&mut self, id: EntityId) {
        if let Some(reached) = self.reached.get(&id) {
            self.met.carried.extend(reached.iter().copied());
        }
    }

    /// What the pass met.
    pub(crate) fn met(self) -> ExportMet {
        self.met
    }
}
