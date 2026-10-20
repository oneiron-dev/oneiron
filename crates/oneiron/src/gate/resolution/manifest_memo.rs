//! Decodes a store keeps between policy resolutions: a byte-charged LRU
//! (FIX 5987). Each kept decode is charged what it owns
//! (`manifest_weight`); the least recently read go first until a new one
//! fits, and one that alone outweighs the whole budget is used uncached. A
//! decode the memo does not keep is still read in full: the memo only ever
//! saves work, never a body's policy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::error::{Error, Result};
use crate::gate::decode::{
    DecodedManifestCarrier, decode_manifest_carrier, decode_policy_manifest,
};

use super::manifest_types::SheetAnswerPrecedence;

/// Bodies kept at most, beside the byte budget. A vault holds a handful of
/// manifests, so past this the least recently read goes.
const MAX_ROWS: usize = 64;

/// Decoded bytes kept at most (FIX 5987, CALLS "manifest memo byte
/// budget"): a cache bound only, never a decode, request or body bound.
const MAX_MANIFEST_MEMO_DECODED_BYTES: usize = 16 * 1024 * 1024;

/// What a store keeps between policy resolutions. Each entry is a pure
/// function of bytes: the shipped manifest is a constant of the build, and a
/// stored manifest body decodes the same way every time it is read.
#[derive(Default)]
pub(crate) struct ManifestDecodeMemo {
    shipped: OnceLock<ShippedPolicyRows>,
    rows: Mutex<KeptRows>,
}

/// The kept decodes under their bodies' BLAKE3, with what they weigh.
#[derive(Default)]
struct KeptRows {
    rows: HashMap<[u8; 32], Kept>,
    /// The kept decodes' weights, summed.
    bytes: usize,
    /// A read counter: each read stamps its row, and the lowest stamp is
    /// the least recently read.
    reads: u64,
}

struct Kept {
    row: Arc<ManifestRow>,
    weight: usize,
    read: u64,
}

impl KeptRows {
    fn get(&mut self, key: &[u8; 32]) -> Option<Arc<ManifestRow>> {
        self.reads = self.reads.wrapping_add(1);
        let read = self.reads;
        self.rows.get_mut(key).map(|kept| {
            kept.read = read;
            Arc::clone(&kept.row)
        })
    }

    /// Keeps `row` at `weight`, the least recently read going first until it
    /// fits. One that alone outweighs the budget is not kept.
    fn admit(&mut self, key: [u8; 32], row: &Arc<ManifestRow>, weight: usize) {
        if weight > MAX_MANIFEST_MEMO_DECODED_BYTES || self.rows.contains_key(&key) {
            return;
        }
        while self.rows.len() >= MAX_ROWS
            || self.bytes.saturating_add(weight) > MAX_MANIFEST_MEMO_DECODED_BYTES
        {
            let Some(oldest) = self
                .rows
                .iter()
                .min_by_key(|(_, kept)| kept.read)
                .map(|(key, _)| *key)
            else {
                break;
            };
            if let Some(evicted) = self.rows.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(evicted.weight);
            }
        }
        self.reads = self.reads.wrapping_add(1);
        self.bytes = self.bytes.saturating_add(weight);
        self.rows.insert(
            key,
            Kept {
                row: Arc::clone(row),
                weight,
                read: self.reads,
            },
        );
    }
}

/// What a resolution takes from the shipped manifest: its sheet-answer
/// default and precedence.
#[derive(Debug, Clone, Copy)]
pub(super) struct ShippedPolicyRows {
    pub(super) sheet_answer_default_max_count: u64,
    pub(super) sheet_answer_precedence: SheetAnswerPrecedence,
}

/// One stored manifest body, decoded. Whether it is a project-depth
/// contribution envelope its fold tells from its bytes, before it decodes.
pub(super) struct ManifestRow {
    pub(super) carrier: Option<DecodedManifestCarrier>,
}

impl ManifestDecodeMemo {
    pub(super) fn shipped(&self) -> Result<ShippedPolicyRows> {
        if let Some(rows) = self.shipped.get() {
            return Ok(*rows);
        }
        let shipped =
            decode_policy_manifest(&crate::gate::default_manifest::default_policy_manifest()?)
                .ok_or(Error::InvariantViolation(
                    "shipped sheet-answer policy manifest invalid",
                ))?;
        let default_max_count = shipped
            .sheet_answer_limits
            .iter()
            .find(|row| row.artifact_ref.is_none() && row.sheet.is_none())
            .map(|row| row.max_count);
        let (Some(sheet_answer_default_max_count), Some(sheet_answer_precedence)) =
            (default_max_count, shipped.sheet_answer_precedence)
        else {
            return Err(Error::InvariantViolation(
                "shipped sheet-answer policy rows missing",
            ));
        };
        Ok(*self.shipped.get_or_init(|| ShippedPolicyRows {
            sheet_answer_default_max_count,
            sheet_answer_precedence,
        }))
    }

    /// `body` decoded, kept under its BLAKE3 hash: the identity the manifest
    /// trust and quarantine sidecars already judge a body by. A caller keeps
    /// only a body its fold reads past quarantine and trust, or a signed
    /// project-depth carrier (FIX 5987).
    pub(super) fn row(&self, body: &[u8]) -> Arc<ManifestRow> {
        let key = *blake3::hash(body).as_bytes();
        if let Some(row) = self.kept(&key) {
            return row;
        }
        let row = Arc::new(ManifestRow::decode(body));
        let weight = super::manifest_weight::row_weight(body.len(), &row);
        if let Ok(mut rows) = self.rows.lock() {
            rows.admit(key, &row, weight);
        }
        row
    }

    /// `body` decoded for this read alone: an untrusted ordinary pack's
    /// (FIX 5987), read in full and never kept. A decode already kept serves.
    pub(super) fn transient(&self, body: &[u8]) -> Arc<ManifestRow> {
        let key = *blake3::hash(body).as_bytes();
        self.kept(&key)
            .unwrap_or_else(|| Arc::new(ManifestRow::decode(body)))
    }

    fn kept(&self, key: &[u8; 32]) -> Option<Arc<ManifestRow>> {
        self.rows.lock().ok().and_then(|mut rows| rows.get(key))
    }
}

impl ManifestRow {
    fn decode(body: &[u8]) -> Self {
        Self {
            carrier: decode_manifest_carrier(body),
        }
    }
}
