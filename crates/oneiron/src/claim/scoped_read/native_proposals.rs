//! Native discovery rows are admitted under the live original reader.

use super::ScopedRead;
use super::native_position::NativeReadPosition;
use crate::Result;
use crate::skill_attribution::{CanonicalSkillEditProposal, canonical_skill_edit_proposal_in_txn};
use crate::store::known_value_index::KnownValues;

impl ScopedRead<'_> {
    /// The custody guard and body pins predate this source transaction.
    pub(crate) fn native_skill_edit_proposal_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &CanonicalSkillEditProposal,
    ) -> Result<bool> {
        let Some(position) = row.read_position() else {
            return Ok(false);
        };
        let position = NativeReadPosition::from(position);
        if !position.is_complete() {
            return Ok(false);
        }
        let Some(current) = canonical_skill_edit_proposal_in_txn(self.vault, txn, row.sequence())?
        else {
            return Ok(false);
        };
        if current.key() != row.key() || current.body() != row.body() {
            return Ok(false);
        }
        if !self.every_lane_in(txn, |lane| {
            lane.native_position_lane_admitted_in(txn, row.proposal().row_id, &position)
        })? {
            return Ok(false);
        }
        let known = KnownValues::load_in_guarded_read(&self.vault.store, txn)?;
        super::native_body::body_readable(row.body(), known.as_ref())
    }
}
