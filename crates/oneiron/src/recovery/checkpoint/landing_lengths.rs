//! The length each image row lands at, known before anything is opened, so
//! a restore claims its real size up front and a disk too full for it is
//! refused at once, never halfway (FIX 6025, 6232).
//!
//! An image row that holds an inline body's first bytes or a response's
//! stub lands with its body back in it: `keep` plus the body's length,
//! replacing the stub's length (never added to it), or, for a queue row a
//! restore unleases, the length its descriptor recorded at capture (FIX
//! 7115). A retired instance's row already holds its erased form, a
//! superseded one the live vault's row, and a dropped one is gone: each
//! counts as it stands. Nothing is decrypted to size it, and no margin is
//! added.

use std::collections::{BTreeMap, BTreeSet};

use super::CheckpointImage;

/// The lengths the rows with a body still to land land at, by database and
/// key.
#[derive(Default)]
pub(super) struct LandingRowLengths(BTreeMap<String, BTreeMap<Vec<u8>, u64>>);

impl LandingRowLengths {
    /// The lengths for `image`, once its `retired` instances' rows took
    /// their erased forms.
    pub(super) fn of(image: &CheckpointImage, retired: &BTreeSet<[u8; 16]>) -> Self {
        let mut lengths = BTreeMap::<String, BTreeMap<Vec<u8>, u64>>::new();
        for carried in &image.inline_bodies {
            if carried.superseded || retired.contains(&carried.instance) {
                continue;
            }
            let landed = carried
                .landed_len
                .unwrap_or_else(|| u64::from(carried.keep).saturating_add(carried.len));
            lengths
                .entry(carried.database.clone())
                .or_default()
                .insert(carried.key.clone(), landed);
        }
        Self(lengths)
    }

    /// The bytes the value of the row `key` of `database`, `value` in the
    /// image now, lands at.
    pub(super) fn value_len(&self, database: &str, key: &[u8], value: &[u8]) -> u64 {
        self.0
            .get(database)
            .and_then(|rows| rows.get(key))
            .copied()
            .unwrap_or(value.len() as u64)
    }
}
