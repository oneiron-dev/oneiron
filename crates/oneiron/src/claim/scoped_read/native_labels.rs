//! Scoped admission of the canonical inline judge-label row.

use super::ScopedRead;
use super::native_position::NativeReadPosition;
use crate::error::{Error, Result};
use crate::skill_optimize::CanonicalJudgeLabel;
use crate::store::known_value_index::KnownValues;

impl ScopedRead<'_> {
    /// The caller holds the custody guard from before `txn` was opened.
    /// `row` is the physical LABELS row read in that same snapshot, not an
    /// entity, a supporting source or a reconstructed value.
    pub(crate) fn native_judge_label_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &CanonicalJudgeLabel,
    ) -> Result<bool> {
        let label = row.label();
        let Some(position) = &label.read_position else {
            return Ok(false);
        };
        let position = NativeReadPosition::from(position);
        if !position.is_complete() {
            return Ok(false);
        }
        // A canonical value retained across snapshots is no authority over
        // a later replacement, recheck or withdrawal of its placement.
        let Some(current) =
            crate::skill_optimize::canonical_judge_label_in_txn(self.vault, txn, &label.ask.id)?
        else {
            return Ok(false);
        };
        if current.key() != row.key() || current.body() != row.body() {
            return Ok(false);
        }
        if !self.every_lane_in(txn, |lane| {
            lane.native_position_lane_admitted_in(txn, label.row_id, &position)
        })? {
            return Ok(false);
        }
        let known = KnownValues::load_in_guarded_read(&self.vault.store, txn)?;
        inline_label_body_readable(row.body(), known.as_ref())
    }
}

/// This native read returns the exact immutable pick or no captured value.
/// It never masks the question or normalizes two different A/B choices.
fn inline_label_body_readable(bytes: &[u8], known: Option<&KnownValues>) -> Result<bool> {
    let mut tree: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Error::CorruptedIndex("judge label body"))?;
    if crate::batch::secret_scan::write_tree_hit(bytes, None).is_some()
        || crate::batch::secret_scan::release_reads_whole_json(&tree)
        || crate::batch::secret_scan::sanitize_read_credentials(&mut tree, false)
    {
        return Ok(false);
    }
    let Some(known) = known else {
        return Ok(true);
    };
    if !known.spans(bytes).is_empty() {
        return Ok(false);
    }
    let mut text = zeroize::Zeroizing::new(Vec::new());
    let mut pending = vec![&tree];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::String(value) => {
                text.extend_from_slice(value.as_bytes());
                text.push(b'\n');
            }
            serde_json::Value::Array(values) => pending.extend(values.iter().rev()),
            serde_json::Value::Object(entries) => {
                for (key, value) in entries.iter().rev() {
                    if !known.spans(key.as_bytes()).is_empty() {
                        return Ok(false);
                    }
                    pending.push(value);
                }
            }
            _ => {}
        }
    }
    Ok(known.spans(&text).is_empty())
}
