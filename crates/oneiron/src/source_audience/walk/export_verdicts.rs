//! An Owner's whole-vault export pass's judge of rows it knows only by what
//! they were made from, and its verdicts kept past the pass's snapshot (fix
//! list row 15416).

use std::collections::{BTreeMap, BTreeSet};

use super::{ExportJudge, ExportMet};
use crate::EntityId;
use crate::error::Result;
use crate::provenance::side_sources::{RowSources, SideSources};

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

    /// What the side ledgers `recorded` (read in this pass's snapshot) and
    /// the row's birth record the body of `id` was made from (fix list rows
    /// 22344 and 22345), read in the pass's snapshot.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn recorded_sources<'r>(
        &self,
        recorded: &'r SideSources,
        id: EntityId,
    ) -> Result<RowSources<'r>> {
        recorded.of(&self.judge.vault.store, self.judge.txn, id)
    }

    /// What the words of the row `id` came from, as [`Self::carries`] walks
    /// them (its bytes `raw`, else as the pass's view holds them): the rows
    /// each of which must go, and a CLAIM's supports, one of which must.
    /// Nothing for a row gone from the view, and nothing in a pass whose
    /// rows' own stamps alone decide (no policy and no held row here), as
    /// [`Self::carries`] reads no lineage there.
    ///
    /// # Errors
    ///
    /// Storage failures, and a row shorter than its header.
    pub(crate) fn word_sources_of(
        &self,
        id: EntityId,
        raw: Option<&[u8]>,
    ) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
        if self.quiet {
            return Ok((Vec::new(), Vec::new()));
        }
        let read;
        let bytes = match raw {
            Some(raw) => raw,
            None => {
                match crate::ports::EntityStoreRead::port_entity_raw(
                    self.judge.dbs,
                    self.judge.txn,
                    &id,
                )? {
                    Some(bytes) => {
                        read = bytes;
                        read.as_slice()
                    }
                    None => return Ok((Vec::new(), Vec::new())),
                }
            }
        };
        super::word_sources(self.judge.vault, self.judge.dbs, self.judge.txn, id, bytes)
    }

    /// The pass's settled verdicts, kept past its snapshot, for a copy
    /// whose rows are known only once that snapshot is gone.
    pub(crate) fn settle(self) -> ExportVerdicts {
        ExportVerdicts {
            reached: self
                .judge
                .export
                .map_or_else(BTreeMap::new, |export| export.reached),
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
