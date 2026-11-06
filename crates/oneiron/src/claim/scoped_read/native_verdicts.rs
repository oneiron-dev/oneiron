//! Scoped admission of the native verdict and its actual displacement mark.

use super::ScopedRead;
use super::native_position::NativeReadPosition;
use crate::error::{Error, Result};
use crate::skill_optimize::CanonicalSkillEditVerdict;
use crate::store::known_value_index::KnownValues;

impl ScopedRead<'_> {
    /// The caller holds the custody guard from before `txn` was opened.
    /// Both primary and displacement witnesses belong to that same snapshot.
    pub(crate) fn native_skill_edit_verdict_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &CanonicalSkillEditVerdict,
    ) -> Result<bool> {
        let Some(position) = row.read_position() else {
            return Ok(false);
        };
        let position = NativeReadPosition::from(position);
        if !position.is_complete() {
            return Ok(false);
        }
        let id = row.verdict().id;
        let Some(current) =
            crate::skill_optimize::canonical_skill_edit_verdict_in_txn(self.vault, txn, &id)?
        else {
            return Ok(false);
        };
        if current.key() != row.key()
            || current.body() != row.body()
            || current.displacement_key() != row.displacement_key()
            || current.displacement_body() != row.displacement_body()
        {
            return Ok(false);
        }
        if !self.every_lane_in(txn, |lane| {
            lane.native_position_lane_admitted_in(txn, id, &position)
        })? {
            return Ok(false);
        }
        let known = KnownValues::load_in_guarded_read(&self.vault.store, txn)?;
        if !super::native_body::body_readable(row.body(), known.as_ref())? {
            return Ok(false);
        }
        match row.displacement_body() {
            Some(bytes) => displacement_readable(bytes, known.as_ref()),
            None => Ok(true),
        }
    }
}

/// Displacement is a native UTF-8 revision string, not a MessagePack or JSON
/// document. Its absence was compared with the canonical witness above.
fn displacement_readable(bytes: &[u8], known: Option<&KnownValues>) -> Result<bool> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::CorruptedIndex("skill edit verdict displacement"))?;
    if crate::batch::secret_scan::scan_joined_text(text).is_some() {
        return Ok(false);
    }
    Ok(known.is_none_or(|known| known.spans(bytes).is_empty()))
}
