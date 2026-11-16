//! L4-20 PR 2 (ARCH-0077 slides lane, `slides:oracle`): `emit` certifies a unit's fit only from a clean stored Office
//! receipt for the exact candidate bytes whose row for that unit fits. "Estimates choose candidates; they do not
//! certify fit": a deck no receipt names keeps every unit unverified, and a unit PowerPoint measured running past its
//! frame stays unverified and is named as an overflow.
//! `cargo test --locked -p oneiron-docedit --all-features --test deck_fit_evidence`.

use oneiron_docedit::contract::DeckCreated;
use oneiron_docedit::emit::oracle_cases::{self, LoadedCaseSet};
use oneiron_docedit::emit::{
    Candidate, EvidenceError, FitEvidence, FitTrace, FitUnverified, FitVerdict, Unverified,
};
use serde_json::Value;
use sha2::Digest as _;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The repository root above this crate.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

/// Lower-case hex, as the receipts write digests.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The committed receipt of case `id`.
fn receipt_bytes(id: &str) -> Vec<u8> {
    read(
        &repo()
            .join(oracle_cases::STORED_RESULTS)
            .join(id)
            .join("receipt.json"),
    )
}

/// The brief of case `id`.
fn brief(loaded: &LoadedCaseSet, id: &str) -> Vec<u8> {
    let case = loaded
        .set
        .cases
        .iter()
        .find(|case| case.id == id)
        .unwrap_or_else(|| panic!("no case {id}"));
    read(&repo().join(&case.brief))
}

fn emit(loaded: &LoadedCaseSet, id: &str, brief: &[u8], evidence: &FitEvidence) -> Candidate {
    oracle_cases::emit_brief(loaded, id, brief, evidence)
        .unwrap_or_else(|reason| panic!("{id}: refused: {reason}"))
}

/// Every unit geometry leaves undecided, as `(slide part, block, shape)`.
fn undecided(candidate: &Candidate) -> BTreeSet<(String, String, u32)> {
    candidate
        .report
        .slides
        .iter()
        .flat_map(|slide| {
            slide
                .units
                .iter()
                .filter(|unit| matches!(unit.fit, FitTrace::Unverified { .. }))
                .map(|unit| (slide.part.clone(), unit.block.clone(), unit.shape))
        })
        .collect()
}

fn keys(units: &[Unverified]) -> BTreeSet<(String, String, u32)> {
    units
        .iter()
        .map(|unit| (unit.slide.clone(), unit.block.clone(), unit.shape))
        .collect()
}

/// The long-title receipt with `edit` applied to its JSON.
fn edited_receipt(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut held: Value =
        serde_json::from_slice(&receipt_bytes("long-title")).expect("parse long-title receipt");
    edit(&mut held);
    serde_json::to_vec(&held).expect("encode receipt")
}

/// Canon `slides:oracle` ("CI uses stored outputs"): the evidence compiled into the crate is every committed receipt,
/// keyed by the candidate it opened.
#[test]
fn the_stored_evidence_reads_every_committed_receipt() {
    let loaded = oracle_cases::load(&repo()).expect("load deck-create-v1");
    let stored = FitEvidence::stored();
    assert_eq!(stored.candidates().count(), loaded.set.cases.len());
    for case in &loaded.set.cases {
        let id = case.id.as_str();
        let bytes = receipt_bytes(id);
        let file: Value = serde_json::from_slice(&bytes).expect("parse receipt");
        let candidate = file
            .pointer("/input/sha256")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{id}: receipt has no input.sha256"));
        let held = stored
            .candidates()
            .find(|key| hex(key.as_slice()) == candidate)
            .and_then(|key| stored.receipt(key))
            .unwrap_or_else(|| panic!("{id}: no stored evidence for candidate {candidate}"));
        assert_eq!(held.receipt, sha256(&bytes), "{id}: receipt hash");
        assert!(held.clean, "{id}: receipt status");
        let rows = file
            .get("fit")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{id}: receipt has no fit"));
        assert_eq!(held.rows.len(), rows.len(), "{id}: fit rows");
    }
}

/// Each case certifies exactly the units PowerPoint measured as fitting, and names its receipt.
#[test]
fn each_case_certifies_exactly_the_units_powerpoint_measured_fitting() {
    let loaded = oracle_cases::load(&repo()).expect("load deck-create-v1");
    let mut certified = 0;
    for case in &loaded.set.cases {
        let id = case.id.as_str();
        let candidate = emit(&loaded, id, &brief(&loaded, id), FitEvidence::stored());
        let bytes = receipt_bytes(id);
        assert_eq!(candidate.fit_receipt, Some(sha256(&bytes)), "{id}: receipt");
        let held = FitEvidence::stored()
            .receipt(&sha256(&candidate.bytes))
            .unwrap_or_else(|| panic!("{id}: no stored evidence for the candidate"));
        let mut open = BTreeSet::new();
        let mut overflows = BTreeSet::new();
        for row in &held.rows {
            let index = usize::try_from(row.slide).expect("slide number") - 1;
            let part = candidate.report.slides[index].part.clone();
            let key = (part, row.block.clone(), row.shape);
            match row.verdict {
                FitVerdict::Fits => certified += 1,
                FitVerdict::Overflows => {
                    overflows.insert(key.clone());
                    open.insert(key);
                }
                FitVerdict::Inconclusive => {
                    open.insert(key);
                }
            }
        }
        let (units, measured) = match &candidate.fit {
            Ok(()) => (BTreeSet::new(), BTreeSet::new()),
            Err(fit) => (keys(&fit.units), keys(&fit.overflows)),
        };
        assert_eq!(units, open, "{id}: units left unverified");
        assert_eq!(measured, overflows, "{id}: overflows");
        assert!(
            units.is_subset(&undecided(&candidate)),
            "{id}: only units geometry left undecided"
        );
    }
    // The stored run measured 31 units fitting, 0 overflowing and 5 inconclusive (3 charts, 2 tables).
    assert_eq!(certified, 31);
}

/// With no evidence, nothing is certified and no receipt is named.
#[test]
fn no_evidence_certifies_nothing() {
    let loaded = oracle_cases::load(&repo()).expect("load deck-create-v1");
    let candidate = emit(
        &loaded,
        "long-title",
        &brief(&loaded, "long-title"),
        &FitEvidence::default(),
    );
    let fit = candidate.fit.as_ref().expect_err("fit stays unverified");
    assert_eq!(keys(&fit.units), undecided(&candidate));
    assert!(fit.overflows.is_empty());
    assert_eq!(candidate.fit_receipt, None);
}

/// A deck one word away from a receipted case has no receipt: an estimate never certifies.
#[test]
fn a_changed_deck_finds_no_receipt() {
    let loaded = oracle_cases::load(&repo()).expect("load deck-create-v1");
    let held = String::from_utf8(brief(&loaded, "long-title")).expect("UTF-8 brief");
    let changed = held.replacen("Fourth-quarter", "Third-quarter", 1);
    assert_ne!(
        changed, held,
        "the long-title brief names the fourth quarter"
    );
    let candidate = emit(
        &loaded,
        "long-title",
        changed.as_bytes(),
        FitEvidence::stored(),
    );
    let fit = candidate.fit.as_ref().expect_err("fit stays unverified");
    assert_eq!(keys(&fit.units), undecided(&candidate));
    assert!(!fit.units.is_empty());
    assert!(fit.overflows.is_empty());
    assert_eq!(candidate.fit_receipt, None);
}

/// A unit PowerPoint measured running past its frame stays unverified and is named; the receipt's other units still
/// certify. The stored run measured no overflow, so this receipt is the long-title one with its claim row changed.
#[test]
fn a_measured_overflow_is_named_and_never_certified() {
    let loaded = oracle_cases::load(&repo()).expect("load deck-create-v1");
    let receipt = edited_receipt(|held| {
        let rows = held
            .get_mut("fit")
            .and_then(Value::as_array_mut)
            .expect("fit rows");
        let claim = rows
            .iter_mut()
            .find(|row| row.get("block").and_then(Value::as_str) == Some("t-claim"))
            .expect("t-claim row");
        claim["verdict"] = Value::from("overflows");
    });
    let evidence = FitEvidence::from_receipts(&[receipt.as_slice()]).expect("read receipt");
    let candidate = emit(
        &loaded,
        "long-title",
        &brief(&loaded, "long-title"),
        &evidence,
    );
    let fit: &FitUnverified = candidate.fit.as_ref().expect_err("the claim overflows");
    let blocks: Vec<&str> = fit.units.iter().map(|unit| unit.block.as_str()).collect();
    assert_eq!(blocks, ["t-claim"]);
    assert_eq!(fit.overflows, fit.units);
    assert_eq!(candidate.fit_receipt, Some(sha256(&receipt)));
}

/// A receipt whose candidate did not open clean certifies nothing and is not named.
#[test]
fn a_receipt_that_is_not_clean_certifies_nothing() {
    let loaded = oracle_cases::load(&repo()).expect("load deck-create-v1");
    let receipt = edited_receipt(|held| held["status"] = Value::from("repaired"));
    let evidence = FitEvidence::from_receipts(&[receipt.as_slice()]).expect("read receipt");
    let candidate = emit(
        &loaded,
        "long-title",
        &brief(&loaded, "long-title"),
        &evidence,
    );
    let fit = candidate.fit.as_ref().expect_err("fit stays unverified");
    assert_eq!(keys(&fit.units), undecided(&candidate));
    assert!(fit.overflows.is_empty());
    assert_eq!(candidate.fit_receipt, None);
}

/// Two receipts naming one candidate are ambiguous evidence.
#[test]
fn receipts_naming_one_candidate_twice_are_refused() {
    let receipt = receipt_bytes("long-title");
    assert_eq!(
        FitEvidence::from_receipts(&[receipt.as_slice(), receipt.as_slice()]),
        Err(EvidenceError::Duplicate {
            first: 0,
            second: 1
        })
    );
}

/// Two rows of one receipt for one unit are ambiguous evidence: the receipt does not read, so a first row that fits
/// never certifies a unit a later row measured running past its frame.
#[test]
fn a_receipt_naming_one_unit_twice_is_refused() {
    let receipt = edited_receipt(|held| {
        let rows = held
            .get_mut("fit")
            .and_then(Value::as_array_mut)
            .expect("fit rows");
        let mut repeat = rows.first().cloned().expect("a fit row");
        repeat["verdict"] = Value::from("overflows");
        rows.push(repeat);
    });
    assert_eq!(
        FitEvidence::from_receipts(&[receipt.as_slice()]),
        Err(EvidenceError::Receipt {
            index: 0,
            detail: "two fit rows name slide 1, shape 2, block t-title".to_owned()
        })
    );
}

/// A `DeckCreated` reply written before receipts were read has no `fit_overflows` and no `fit_receipt`; it still
/// reads, with no overflow and no receipt.
#[test]
fn a_deck_created_reply_from_before_receipts_still_reads() {
    let reply = serde_json::json!({
        "hash": "00",
        "slides": [],
        "write_set": [],
        "omitted": [],
        "fit_unverified": [{ "slide": "ppt/slides/slide1.xml", "block": "t-title", "shape": 2 }],
    });
    let read: DeckCreated = serde_json::from_value(reply).expect("read the older reply");
    assert_eq!(read.fit_unverified.len(), 1);
    assert!(read.fit_overflows.is_empty());
    assert_eq!(read.fit_receipt, None);
}
