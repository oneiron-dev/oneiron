//! Stored PowerPoint fit evidence (ARCH-0077 `slides:oracle`: the oracle runs once per case set to create golden outputs; CI uses the stored outputs, so no always-on machine is required).
//!
//! Each committed `deck-create-v1` receipt names the SHA-256 of the candidate PowerPoint opened and, for every unit whose fit emission cannot decide, whether PowerPoint's own layout of that unit stays inside its frame. [`emit`](super::emit) takes a unit out of [`FitUnverified`] only on such a `fits` row of a clean receipt for the exact candidate bytes. An estimate never certifies ("Estimates choose candidates; they do not certify fit."), so a deck no receipt names keeps every unit unverified, and a unit PowerPoint measured running past its frame is named in [`FitUnverified::overflows`].

use super::{EmittedSlide, FitTrace, FitUnverified, Unverified};
use serde::Deserialize;
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// The committed `deck-create-v1` receipts (`scripts/office/results/deck-create-v1/<case>/receipt.json`), one per case of `scripts/office/deck-create-v1.json`.
const STORED: [&[u8]; 6] = [
    include_bytes!("../../../../scripts/office/results/deck-create-v1/board-review/receipt.json"),
    include_bytes!("../../../../scripts/office/results/deck-create-v1/long-title/receipt.json"),
    include_bytes!("../../../../scripts/office/results/deck-create-v1/cjk-body/receipt.json"),
    include_bytes!("../../../../scripts/office/results/deck-create-v1/dense-findings/receipt.json"),
    include_bytes!("../../../../scripts/office/results/deck-create-v1/wide-table/receipt.json"),
    include_bytes!("../../../../scripts/office/results/deck-create-v1/quarter-chart/receipt.json"),
];

/// What PowerPoint measured for one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FitVerdict {
    /// PowerPoint's laid-out text, or its table rows, stay inside the frame.
    Fits,
    /// PowerPoint's layout runs past the frame.
    Overflows,
    /// PowerPoint gave no measurement: a chart, a table with no readable rows, another shape, or no row.
    Inconclusive,
}

/// One unit's row in a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FitRow {
    /// The slide, 1-based in presentation order.
    pub slide: u32,
    /// The unit's `p:cNvPr` id.
    pub shape: u32,
    /// The source block.
    pub block: String,
    pub verdict: FitVerdict,
}

/// One stored Office receipt as fit evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FitReceipt {
    /// SHA-256 of the receipt file.
    pub receipt: [u8; 32],
    /// PowerPoint opened, rendered and saved the candidate with no repair, dialog or timeout. Only a clean receipt certifies.
    pub clean: bool,
    pub rows: Vec<FitRow>,
}

impl FitReceipt {
    /// PowerPoint's verdict for the unit at `slide` (1-based), `shape` and `block`, when the receipt has a row for it.
    /// A receipt holds at most one row per unit: [`FitEvidence::from_receipts`] refuses a repeat.
    pub fn verdict(&self, slide: usize, shape: u32, block: &str) -> Option<FitVerdict> {
        self.rows
            .iter()
            .find(|row| {
                usize::try_from(row.slide) == Ok(slide) && row.shape == shape && row.block == block
            })
            .map(|row| row.verdict)
    }
}

/// Office receipts keyed by the SHA-256 of the candidate each one opened. The default holds none and certifies nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FitEvidence {
    by_candidate: BTreeMap<[u8; 32], FitReceipt>,
}

/// Why receipts do not read as fit evidence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("receipt {index}: {detail}")]
    Receipt { index: usize, detail: String },
    #[error("receipts {first} and {second} name the same candidate")]
    Duplicate { first: usize, second: usize },
}

impl FitEvidence {
    /// The committed `deck-create-v1` receipts. Receipts that do not read certify nothing: the evidence is then empty, and the receipt pin test `the_stored_evidence_reads_every_committed_receipt` fails.
    pub fn stored() -> &'static Self {
        static STORED_EVIDENCE: OnceLock<FitEvidence> = OnceLock::new();
        STORED_EVIDENCE.get_or_init(|| Self::from_receipts(&STORED).unwrap_or_default())
    }

    /// Read Office receipts (`receipt.json` bytes) as evidence. Two receipts for one candidate, or two rows of one receipt for one unit, are ambiguous and refused.
    pub fn from_receipts(receipts: &[&[u8]]) -> Result<Self, EvidenceError> {
        let mut by_candidate = BTreeMap::new();
        let mut index_of = BTreeMap::new();
        for (index, bytes) in receipts.iter().enumerate() {
            let read: ReceiptFile =
                serde_json::from_slice(bytes).map_err(|error| EvidenceError::Receipt {
                    index,
                    detail: error.to_string(),
                })?;
            let candidate = digest(&read.input.sha256).ok_or_else(|| EvidenceError::Receipt {
                index,
                detail: "input.sha256 is not 64 lower-case hex digits".to_owned(),
            })?;
            if let Some(first) = index_of.insert(candidate, index) {
                return Err(EvidenceError::Duplicate {
                    first,
                    second: index,
                });
            }
            let mut units = BTreeSet::new();
            let mut rows = Vec::with_capacity(read.fit.len());
            for row in read.fit {
                if !units.insert((row.slide, row.shape_id, row.block.clone())) {
                    return Err(EvidenceError::Receipt {
                        index,
                        detail: format!(
                            "two fit rows name slide {}, shape {}, block {}",
                            row.slide, row.shape_id, row.block
                        ),
                    });
                }
                rows.push(FitRow {
                    slide: row.slide,
                    shape: row.shape_id,
                    block: row.block,
                    verdict: row.verdict,
                });
            }
            let receipt = FitReceipt {
                receipt: sha2::Sha256::digest(bytes).into(),
                clean: read.status == "clean",
                rows,
            };
            by_candidate.insert(candidate, receipt);
        }
        Ok(Self { by_candidate })
    }

    /// The receipt for the candidate whose SHA-256 is `candidate`.
    pub fn receipt(&self, candidate: &[u8; 32]) -> Option<&FitReceipt> {
        self.by_candidate.get(candidate)
    }

    /// The SHA-256 of every candidate a receipt names.
    pub fn candidates(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.by_candidate.keys()
    }
}

/// The receipt keys fit evidence reads; the rest of a receipt is the Office pass's record.
#[derive(Deserialize)]
struct ReceiptFile {
    status: String,
    input: InputFile,
    /// Absent or empty when the candidate never opened.
    #[serde(default)]
    fit: Vec<RowFile>,
}

#[derive(Deserialize)]
struct InputFile {
    sha256: String,
}

#[derive(Deserialize)]
struct RowFile {
    slide: u32,
    shape_id: u32,
    block: String,
    verdict: FitVerdict,
}

/// 64 lower-case hex digits as 32 bytes.
fn digest(hex: &str) -> Option<[u8; 32]> {
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let digits = hex.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// The candidate's fit: every unit geometry leaves undecided stays unverified unless the clean receipt for these exact bytes measured it as fitting; a measured overflow is also named. Returns the consulted receipt's SHA-256.
pub(super) fn certify(
    bytes: &[u8],
    slides: &[EmittedSlide],
    evidence: &FitEvidence,
) -> (Result<(), FitUnverified>, Option<[u8; 32]>) {
    let candidate: [u8; 32] = sha2::Sha256::digest(bytes).into();
    let receipt = evidence.receipt(&candidate).filter(|receipt| receipt.clean);
    let mut units = Vec::new();
    let mut overflows = Vec::new();
    for (index, slide) in slides.iter().enumerate() {
        for unit in &slide.units {
            if !matches!(unit.fit, FitTrace::Unverified { .. }) {
                continue;
            }
            let held = Unverified {
                slide: slide.part.clone(),
                block: unit.block.clone(),
                shape: unit.shape,
            };
            match receipt.and_then(|receipt| receipt.verdict(index + 1, unit.shape, &unit.block)) {
                Some(FitVerdict::Fits) => {}
                Some(FitVerdict::Overflows) => {
                    overflows.push(held.clone());
                    units.push(held);
                }
                Some(FitVerdict::Inconclusive) | None => units.push(held),
            }
        }
    }
    let fit = if units.is_empty() {
        Ok(())
    } else {
        Err(FitUnverified { units, overflows })
    };
    (fit, receipt.map(|receipt| receipt.receipt))
}
