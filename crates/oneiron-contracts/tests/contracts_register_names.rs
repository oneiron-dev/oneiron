//! The names of 8 name lists in `oneiron-contracts`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-contracts/src/claim/confidence.rs`
//! - `crates/oneiron-contracts/src/claim/status.rs`
//! - `crates/oneiron-contracts/src/edge.rs`
//! - `crates/oneiron-contracts/src/error/legal_hold.rs`
//! - `crates/oneiron-contracts/src/secret_custody.rs`
//! - `crates/oneiron-contracts/src/temporal.rs`

use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::claim::ConfidenceBand;
use oneiron_contracts::claim::VerdictBasis;
use oneiron_contracts::edge::EdgeActorClass;
use oneiron_contracts::error::LegalHoldState;
use oneiron_contracts::secret_custody::CustodyClass;
use oneiron_contracts::temporal::TemporalHintStatus;
use serde_json::Value;

/// Every row of `ConfidenceBand`, as its hand table spelled it.
const CONFIDENCE_BAND_ROWS: [(ConfidenceBand, &str); 4] = [
    (ConfidenceBand::Low, "low"),
    (ConfidenceBand::Medium, "medium"),
    (ConfidenceBand::High, "high"),
    (ConfidenceBand::Certain, "certain"),
];

#[test]
fn every_confidence_band_keeps_its_name() {
    assert_eq!(ConfidenceBand::Low.as_str(), "low");
    assert_eq!(ConfidenceBand::Medium.as_str(), "medium");
    assert_eq!(ConfidenceBand::High.as_str(), "high");
    assert_eq!(ConfidenceBand::Certain.as_str(), "certain");
}

#[test]
fn every_confidence_band_name_is_its_serde_name() {
    for (row, name) in CONFIDENCE_BAND_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ConfidenceBand =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn confidence_band_parse_reads_each_name_back() {
    for (row, name) in CONFIDENCE_BAND_ROWS {
        assert_eq!(ConfidenceBand::parse(name), Some(row), "{name}");
    }
    assert_eq!(ConfidenceBand::parse("not.a.row"), None);
}

/// Every row of `VerdictBasis`, as its hand table spelled it.
const VERDICT_BASIS_ROWS: [(VerdictBasis, &str); 2] = [
    (VerdictBasis::CalibratedModel, "calibrated_model"),
    (
        VerdictBasis::DeterministicFallback,
        "deterministic_fallback",
    ),
];

#[test]
fn every_verdict_basis_keeps_its_name() {
    assert_eq!(VerdictBasis::CalibratedModel.as_str(), "calibrated_model");
    assert_eq!(
        VerdictBasis::DeterministicFallback.as_str(),
        "deterministic_fallback"
    );
}

#[test]
fn every_verdict_basis_name_is_its_serde_name() {
    for (row, name) in VERDICT_BASIS_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: VerdictBasis =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn verdict_basis_parse_reads_each_name_back() {
    for (row, name) in VERDICT_BASIS_ROWS {
        assert_eq!(VerdictBasis::parse(name), Some(row), "{name}");
    }
    assert_eq!(VerdictBasis::parse("not.a.row"), None);
}

/// Every row of `ClaimApprovalStatus`, as its hand table spelled it.
const CLAIM_APPROVAL_STATUS_ROWS: [(ClaimApprovalStatus, &str); 4] = [
    (ClaimApprovalStatus::Auto, "auto"),
    (ClaimApprovalStatus::Proposed, "proposed"),
    (ClaimApprovalStatus::Approved, "approved"),
    (ClaimApprovalStatus::Rejected, "rejected"),
];

#[test]
fn every_claim_approval_status_keeps_its_name() {
    assert_eq!(ClaimApprovalStatus::Auto.as_str(), "auto");
    assert_eq!(ClaimApprovalStatus::Proposed.as_str(), "proposed");
    assert_eq!(ClaimApprovalStatus::Approved.as_str(), "approved");
    assert_eq!(ClaimApprovalStatus::Rejected.as_str(), "rejected");
}

#[test]
fn every_claim_approval_status_name_is_its_serde_name() {
    for (row, name) in CLAIM_APPROVAL_STATUS_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ClaimApprovalStatus =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn claim_approval_status_parse_reads_each_name_back() {
    for (row, name) in CLAIM_APPROVAL_STATUS_ROWS {
        assert_eq!(ClaimApprovalStatus::parse(name), Some(row), "{name}");
    }
    assert_eq!(ClaimApprovalStatus::parse("not.a.row"), None);
}

/// Every row of `ClaimSource`, as its hand table spelled it.
const CLAIM_SOURCE_ROWS: [(ClaimSource, &str); 6] = [
    (ClaimSource::UserStated, "user_stated"),
    (ClaimSource::Observed, "observed"),
    (ClaimSource::Inferred, "inferred"),
    (ClaimSource::Imported, "imported"),
    (ClaimSource::ToolOutput, "tool_output"),
    (ClaimSource::Generated, "generated"),
];

#[test]
fn every_claim_source_keeps_its_name() {
    assert_eq!(ClaimSource::UserStated.as_str(), "user_stated");
    assert_eq!(ClaimSource::Observed.as_str(), "observed");
    assert_eq!(ClaimSource::Inferred.as_str(), "inferred");
    assert_eq!(ClaimSource::Imported.as_str(), "imported");
    assert_eq!(ClaimSource::ToolOutput.as_str(), "tool_output");
    assert_eq!(ClaimSource::Generated.as_str(), "generated");
}

#[test]
fn every_claim_source_name_is_its_serde_name() {
    for (row, name) in CLAIM_SOURCE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ClaimSource =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn claim_source_parse_reads_each_name_back() {
    for (row, name) in CLAIM_SOURCE_ROWS {
        assert_eq!(ClaimSource::parse(name), Some(row), "{name}");
    }
    assert_eq!(ClaimSource::parse("not.a.row"), None);
}

/// Every row of `EdgeActorClass`, as its hand table spelled it.
const EDGE_ACTOR_CLASS_ROWS: [(EdgeActorClass, &str); 3] = [
    (EdgeActorClass::Human, "human"),
    (EdgeActorClass::Agent, "agent"),
    (EdgeActorClass::System, "system"),
];

#[test]
fn every_edge_actor_class_keeps_its_name() {
    assert_eq!(EdgeActorClass::Human.gate_actor_class(), "human");
    assert_eq!(EdgeActorClass::Agent.gate_actor_class(), "agent");
    assert_eq!(EdgeActorClass::System.gate_actor_class(), "system");
}

#[test]
fn every_edge_actor_class_name_is_its_serde_name() {
    for (row, name) in EDGE_ACTOR_CLASS_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: EdgeActorClass =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `LegalHoldState`, as its hand table spelled it.
const LEGAL_HOLD_STATE_ROWS: [(LegalHoldState, &str); 2] = [
    (LegalHoldState::RetainedForLaw, "retained_for_law"),
    (LegalHoldState::UseRestricted, "use_restricted"),
];

#[test]
fn every_legal_hold_state_keeps_its_name() {
    assert_eq!(LegalHoldState::RetainedForLaw.as_str(), "retained_for_law");
    assert_eq!(LegalHoldState::UseRestricted.as_str(), "use_restricted");
}

#[test]
fn every_legal_hold_state_name_is_its_serde_name() {
    for (row, name) in LEGAL_HOLD_STATE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: LegalHoldState =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `CustodyClass`, as its hand table spelled it.
const CUSTODY_CLASS_ROWS: [(CustodyClass, &str); 3] = [
    (CustodyClass::CustodyPortable, "custody-portable"),
    (CustodyClass::CustodyDeviceBound, "custody-device-bound"),
    (CustodyClass::CrossVault, "cross-vault"),
];

#[test]
fn every_custody_class_keeps_its_name() {
    assert_eq!(CustodyClass::CustodyPortable.as_str(), "custody-portable");
    assert_eq!(
        CustodyClass::CustodyDeviceBound.as_str(),
        "custody-device-bound"
    );
    assert_eq!(CustodyClass::CrossVault.as_str(), "cross-vault");
}

#[test]
fn every_custody_class_name_is_its_serde_name() {
    for (row, name) in CUSTODY_CLASS_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: CustodyClass =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn custody_class_parse_reads_each_name_back() {
    for (row, name) in CUSTODY_CLASS_ROWS {
        assert_eq!(CustodyClass::parse(name), Some(row), "{name}");
    }
    assert_eq!(CustodyClass::parse("not.a.row"), None);
}

/// Every row of `TemporalHintStatus`, as its hand table spelled it.
const TEMPORAL_HINT_STATUS_ROWS: [(TemporalHintStatus, &str); 3] = [
    (TemporalHintStatus::Used, "used"),
    (TemporalHintStatus::Unresolved, "unresolved"),
    (TemporalHintStatus::Future, "future"),
];

#[test]
fn every_temporal_hint_status_keeps_its_name() {
    assert_eq!(TemporalHintStatus::Used.as_str(), "used");
    assert_eq!(TemporalHintStatus::Unresolved.as_str(), "unresolved");
    assert_eq!(TemporalHintStatus::Future.as_str(), "future");
}

#[test]
fn every_temporal_hint_status_name_is_its_serde_name() {
    for (row, name) in TEMPORAL_HINT_STATUS_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: TemporalHintStatus =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}
