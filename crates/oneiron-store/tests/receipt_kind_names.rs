//! `ReceiptKind`'s names, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only crates/oneiron-store/src/receipt_row.rs` on
//! main before `ReceiptKind` became a Register (Fable pass 25, R2a): the names its hand `as_str`
//! table wrote. Green on main (the hand table) and on the adoption (the derive), so no stored or
//! queried receipt kind changed its name (M-1 keep). The second test pins each name to serde's.

use oneiron_store::receipt_row::ReceiptKind;
use serde_json::Value;

/// Every row, as the hand table spelled it.
const ROWS: [(ReceiptKind, &str); 16] = [
    (ReceiptKind::Outbound, "outbound"),
    (ReceiptKind::Gate, "gate"),
    (ReceiptKind::IdentityLifecycle, "identity_lifecycle"),
    (ReceiptKind::ScopedRead, "scoped_read"),
    (ReceiptKind::Share, "share"),
    (ReceiptKind::ArtifactSettle, "artifact_settle"),
    (ReceiptKind::ProposalOutcome, "proposal_outcome"),
    (ReceiptKind::CommitmentLifecycle, "commitment_lifecycle"),
    (ReceiptKind::Extraction, "extraction"),
    (ReceiptKind::ServedForm, "served_form"),
    (ReceiptKind::Hook, "hook"),
    (ReceiptKind::ReferenceRefusal, "reference_refusal"),
    (ReceiptKind::TaskLifecycle, "task_lifecycle"),
    (ReceiptKind::RunHoldOverride, "run_hold_override"),
    (ReceiptKind::CheckIn, "check_in"),
    (ReceiptKind::Inquiry, "inquiry"),
];

#[test]
fn every_receipt_kind_keeps_its_name() {
    assert_eq!(ReceiptKind::Outbound.as_str(), "outbound");
    assert_eq!(ReceiptKind::Gate.as_str(), "gate");
    assert_eq!(
        ReceiptKind::IdentityLifecycle.as_str(),
        "identity_lifecycle"
    );
    assert_eq!(ReceiptKind::ScopedRead.as_str(), "scoped_read");
    assert_eq!(ReceiptKind::Share.as_str(), "share");
    assert_eq!(ReceiptKind::ArtifactSettle.as_str(), "artifact_settle");
    assert_eq!(ReceiptKind::ProposalOutcome.as_str(), "proposal_outcome");
    assert_eq!(
        ReceiptKind::CommitmentLifecycle.as_str(),
        "commitment_lifecycle"
    );
    assert_eq!(ReceiptKind::Extraction.as_str(), "extraction");
    assert_eq!(ReceiptKind::ServedForm.as_str(), "served_form");
    assert_eq!(ReceiptKind::Hook.as_str(), "hook");
    assert_eq!(ReceiptKind::ReferenceRefusal.as_str(), "reference_refusal");
    assert_eq!(ReceiptKind::TaskLifecycle.as_str(), "task_lifecycle");
    assert_eq!(ReceiptKind::RunHoldOverride.as_str(), "run_hold_override");
    assert_eq!(ReceiptKind::CheckIn.as_str(), "check_in");
    assert_eq!(ReceiptKind::Inquiry.as_str(), "inquiry");
}

#[test]
fn every_receipt_kind_name_is_its_serde_name() {
    for (kind, name) in ROWS {
        let written = serde_json::to_value(kind).expect("a receipt kind serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{kind:?}");
        let read: ReceiptKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, kind, "{name}");
    }
}
