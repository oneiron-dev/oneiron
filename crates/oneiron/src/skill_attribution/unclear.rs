//! The unclear ledger: every outcome the judge left `unclear`, kept for the
//! Dreamer to cluster (ARCH-0056 §5 #unclear).
//!
//! An `unclear` share charges nobody, so without this ledger it would leave no
//! trace at all. Each row is one judged outcome — a failed attempt or an
//! amendment — with a note per unclear hunk: why it landed there, the label
//! the judge leaned to, and the judge's own words. The clustering that turns
//! recurring notes into a proposed new label is the Dreamer's, and is not
//! built here; [`unclear_attributions`] is its inlet.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

use super::types::{AttributionLane, AttributionVerdict, UnclearNote, UnclearReason};

/// One judged outcome with an `unclear` share.
#[derive(Debug, Clone, PartialEq)]
pub struct UnclearAttribution {
    pub lane: AttributionLane,
    /// Where the outcome is filed in its lane: the evidence sequence for an
    /// attempt, the receipt id for an amendment.
    pub reference: String,
    /// Receipt ids the outcome rests on.
    pub evidence_receipts: Vec<String>,
    /// One note per unclear hunk.
    pub notes: Vec<UnclearNote>,
    pub at: u64,
}

impl UnclearAttribution {
    /// The outcome's whole unclear share.
    #[must_use]
    pub fn share(&self) -> f32 {
        self.notes.iter().map(|note| note.share).sum()
    }
}

/// Keyed `lane ":" reference`, so one outcome holds one row and a re-judgment
/// replaces it.
const UNCLEAR: SideTable<String, StoredUnclear, Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_UNCLEAR);

const ROW_VERSION: u8 = 1;
const ROW_LABEL: &str = "unclear attribution row";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredUnclear {
    v: u8,
    lane: String,
    reference: String,
    evidence_receipts: Vec<String>,
    notes: Vec<StoredNote>,
    at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredNote {
    reason: String,
    leaning: Option<String>,
    confidence: f32,
    share: f32,
    note: Option<String>,
}

impl RawValue for StoredUnclear {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| CodecError::Value(Error::InvariantViolation(ROW_LABEL)))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row: Self = rmp_serde::from_slice(bytes)
            .map_err(|_| CodecError::Value(Error::CorruptedIndex(ROW_LABEL)))?;
        if row.v != ROW_VERSION {
            return Err(CodecError::Value(Error::CorruptedIndex(ROW_LABEL)));
        }
        Ok(row)
    }
}

fn row_key(lane: AttributionLane, reference: &str) -> String {
    format!("{}:{reference}", lane.as_str())
}

/// Files `row`, replacing whatever the same outcome held before.
pub(crate) fn put_unclear_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &UnclearAttribution,
) -> Result<()> {
    let stored = StoredUnclear {
        v: ROW_VERSION,
        lane: row.lane.as_str().to_owned(),
        reference: row.reference.clone(),
        evidence_receipts: row.evidence_receipts.clone(),
        notes: row
            .notes
            .iter()
            .map(|note| StoredNote {
                reason: note.reason.as_str().to_owned(),
                leaning: note.leaning.map(|label| label.as_str().to_owned()),
                confidence: note.confidence,
                share: note.share,
                note: note.note.clone(),
            })
            .collect(),
        at: row.at,
    };
    UNCLEAR.put(
        &vault.store,
        wtxn,
        &row_key(row.lane, &row.reference),
        &stored,
    )?;
    Ok(())
}

/// Withdraws the outcome's row: a re-judgment that left nothing unclear.
pub(crate) fn delete_unclear_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    lane: AttributionLane,
    reference: &str,
) -> Result<()> {
    UNCLEAR.delete(&vault.store, wtxn, &row_key(lane, reference))?;
    Ok(())
}

/// Every outcome the judge left `unclear`, both lanes, in key order — the
/// Dreamer's clustering inlet.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn unclear_attributions(vault: &Vault) -> Result<Vec<UnclearAttribution>> {
    let rtxn = vault.store.env.read_txn()?;
    let corrupt = || Error::CorruptedIndex(ROW_LABEL);
    let mut out = Vec::new();
    for (_, row) in UNCLEAR.scan(&vault.store, &rtxn)? {
        let mut notes = Vec::with_capacity(row.notes.len());
        for note in row.notes {
            notes.push(UnclearNote {
                reason: UnclearReason::parse(&note.reason).ok_or_else(corrupt)?,
                leaning: note
                    .leaning
                    .as_deref()
                    .map(|label| AttributionVerdict::parse(label).ok_or_else(corrupt))
                    .transpose()?,
                confidence: note.confidence,
                share: note.share,
                note: note.note,
            });
        }
        out.push(UnclearAttribution {
            lane: AttributionLane::parse(&row.lane).ok_or_else(corrupt)?,
            reference: row.reference,
            evidence_receipts: row.evidence_receipts,
            notes,
            at: row.at,
        });
    }
    Ok(out)
}
