//! Native rule outcomes use their original identity and the live full reader.

use super::ScopedRead;
use super::native_position::NativeReadPosition;
use crate::EntityId;
use crate::Result;
use crate::skill_reliability::{CanonicalRuleOutcome, canonical_rule_outcome_in_txn};
use crate::store::known_value_index::KnownValues;

impl ScopedRead<'_> {
    /// Body pins and the custody guard predate the source transaction. A raw
    /// classification read without native placement makes capture unknown.
    pub(crate) fn native_rule_outcome_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        skill: &EntityId,
        row: &CanonicalRuleOutcome,
    ) -> Result<bool> {
        let (Some(id), Some(position), Some(receipt)) =
            (row.row_id(), row.read_position(), row.receipt())
        else {
            return Ok(false);
        };
        let position = NativeReadPosition::from(position);
        if !position.is_complete() {
            return Ok(false);
        }
        let Some(current) = canonical_rule_outcome_in_txn(self.vault, txn, skill, receipt)? else {
            return Ok(false);
        };
        if current.key() != row.key() || current.body() != row.body() {
            return Ok(false);
        }
        if !self.every_lane_in(txn, |lane| {
            lane.native_position_lane_admitted_in(txn, id, &position)
        })? {
            return Ok(false);
        }
        let known = KnownValues::load_in_guarded_read(&self.vault.store, txn)?;
        super::native_body::body_readable(row.body(), known.as_ref())
    }
}
