//! Admit each actually consulted outcome dependency under the full current reader.

use super::ScopedRead;
use super::native_position::NativeReadPosition;
use crate::Result;
use crate::skill_reliability::{CanonicalOutcomeDependency, canonical_outcome_dependency_in_txn};
use crate::store::known_value_index::KnownValues;

impl ScopedRead<'_> {
    pub(crate) fn native_outcome_dependency_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &CanonicalOutcomeDependency,
    ) -> Result<bool> {
        let Some(current) = canonical_outcome_dependency_in_txn(self.vault, txn, &row.source())?
        else {
            return Ok(false);
        };
        if current.source() != row.source() || current.body() != row.body() {
            return Ok(false);
        }
        // An actual marker absence is bound to the primary branch that read
        // it. There is no absent row to endow with a manufactured identity.
        let Some(body) = row.body() else {
            return Ok(true);
        };
        let Some(id) = row.row_id() else {
            return Ok(false);
        };
        let position = if let Some(position) = row.original_position() {
            NativeReadPosition::from(position)
        } else if let Some(position) = row.rule_position() {
            NativeReadPosition::from(position)
        } else {
            return Ok(false);
        };
        if !position.is_complete() {
            return Ok(false);
        }
        if !self.every_lane_in(txn, |lane| {
            lane.native_position_lane_admitted_in(txn, id, &position)
        })? {
            return Ok(false);
        }
        let known = KnownValues::load_in_guarded_read(&self.vault.store, txn)?;
        super::native_body::body_readable(body, known.as_ref())
    }
}
