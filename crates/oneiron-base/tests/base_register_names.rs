//! The names of 3 name lists in `oneiron-base`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-base/src/config.rs`
//! - `crates/oneiron-base/src/learning_estimate.rs`

use oneiron_base::config::HostingPrivacyPosture;
use oneiron_base::learning_estimate::EstimateForm;
use oneiron_base::learning_estimate::PriorOrigin;
use serde_json::Value;

/// Every row of `HostingPrivacyPosture`, as its hand table spelled it.
const HOSTING_PRIVACY_POSTURE_ROWS: [(HostingPrivacyPosture, &str); 3] = [
    (HostingPrivacyPosture::Hosted, "managed"),
    (HostingPrivacyPosture::Relay, "relay"),
    (HostingPrivacyPosture::SelfHostLocal, "self-host"),
];

#[test]
fn every_hosting_privacy_posture_keeps_its_name() {
    assert_eq!(HostingPrivacyPosture::Hosted.as_str(), "managed");
    assert_eq!(HostingPrivacyPosture::Relay.as_str(), "relay");
    assert_eq!(HostingPrivacyPosture::SelfHostLocal.as_str(), "self-host");
}

#[test]
fn every_hosting_privacy_posture_name_is_its_serde_name() {
    for (row, name) in HOSTING_PRIVACY_POSTURE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: HostingPrivacyPosture =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn hosting_privacy_posture_from_str_reads_each_name_back() {
    for (row, name) in HOSTING_PRIVACY_POSTURE_ROWS {
        assert_eq!(
            name.parse::<HostingPrivacyPosture>().ok(),
            Some(row),
            "{name}"
        );
    }
    assert!("not.a.row".parse::<HostingPrivacyPosture>().is_err());
}

#[test]
fn hosting_privacy_posture_from_str_keeps_its_refusal() {
    assert_eq!(
        "Managed".parse::<HostingPrivacyPosture>(),
        Err("expected one of managed, relay, self-host; got \"Managed\"".to_owned())
    );
}

/// Every row of `EstimateForm`, as its hand table spelled it.
const ESTIMATE_FORM_ROWS: [(EstimateForm, &str); 3] = [
    (EstimateForm::Beta, "beta"),
    (EstimateForm::Mean, "mean"),
    (EstimateForm::Counts, "counts"),
];

#[test]
fn every_estimate_form_keeps_its_name() {
    assert_eq!(EstimateForm::Beta.as_str(), "beta");
    assert_eq!(EstimateForm::Mean.as_str(), "mean");
    assert_eq!(EstimateForm::Counts.as_str(), "counts");
}

#[test]
fn every_estimate_form_name_is_its_serde_name() {
    for (row, name) in ESTIMATE_FORM_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: EstimateForm =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `PriorOrigin`, as its hand table spelled it.
const PRIOR_ORIGIN_ROWS: [(PriorOrigin, &str); 6] = [
    (PriorOrigin::Shipped, "shipped"),
    (PriorOrigin::Provenance, "provenance"),
    (PriorOrigin::Carried, "carried"),
    (PriorOrigin::Parent, "parent"),
    (PriorOrigin::Model, "model"),
    (PriorOrigin::Seed, "seed"),
];

#[test]
fn every_prior_origin_keeps_its_name() {
    assert_eq!(PriorOrigin::Shipped.as_str(), "shipped");
    assert_eq!(PriorOrigin::Provenance.as_str(), "provenance");
    assert_eq!(PriorOrigin::Carried.as_str(), "carried");
    assert_eq!(PriorOrigin::Parent.as_str(), "parent");
    assert_eq!(PriorOrigin::Model.as_str(), "model");
    assert_eq!(PriorOrigin::Seed.as_str(), "seed");
}

#[test]
fn every_prior_origin_name_is_its_serde_name() {
    for (row, name) in PRIOR_ORIGIN_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: PriorOrigin =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}
