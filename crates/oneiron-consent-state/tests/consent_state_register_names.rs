//! The names of 4 name lists in `oneiron-consent-state`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-consent-state/src/consent/code_wait_state.rs`
//! - `crates/oneiron-consent-state/src/gate/code_consent_settlement.rs`
//! - `crates/oneiron-consent-state/src/verbs/voice_records/consent.rs`

use oneiron_consent_state::consent::code_wait_state::CodeConsentChoice;
use oneiron_consent_state::consent::code_wait_state::CodeConsentSettleOutcome;
use oneiron_consent_state::gate::code_consent_settlement::CodeConsentSettlementOrigin;
use oneiron_consent_state::verbs::voice_records::consent::VoiceConsentState;
use serde::Deserialize;
use serde::de::IntoDeserializer;
use serde::de::value::{Error as ValueError, StrDeserializer};

/// Every row of `CodeConsentChoice`, as its hand table spelled it.
const CODE_CONSENT_CHOICE_ROWS: [(CodeConsentChoice, &str); 3] = [
    (CodeConsentChoice::ApproveOnce, "approve_once"),
    (
        CodeConsentChoice::ApproveAndStopAsking,
        "approve_and_stop_asking",
    ),
    (CodeConsentChoice::Deny, "deny"),
];

#[test]
fn every_code_consent_choice_keeps_its_name() {
    assert_eq!(CodeConsentChoice::ApproveOnce.as_str(), "approve_once");
    assert_eq!(
        CodeConsentChoice::ApproveAndStopAsking.as_str(),
        "approve_and_stop_asking"
    );
    assert_eq!(CodeConsentChoice::Deny.as_str(), "deny");
}

#[test]
fn every_code_consent_choice_name_is_its_serde_name() {
    for (row, name) in CODE_CONSENT_CHOICE_ROWS {
        let reader: StrDeserializer<'_, ValueError> = name.into_deserializer();
        let read = CodeConsentChoice::deserialize(reader).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn code_consent_choice_from_option_reads_each_name_back() {
    for (row, name) in CODE_CONSENT_CHOICE_ROWS {
        assert_eq!(CodeConsentChoice::from_option(name), Some(row), "{name}");
    }
    assert_eq!(CodeConsentChoice::from_option("not.a.row"), None);
}

/// Every row of `CodeConsentSettleOutcome`, as its hand table spelled it.
const CODE_CONSENT_SETTLE_OUTCOME_ROWS: [(CodeConsentSettleOutcome, &str); 3] = [
    (CodeConsentSettleOutcome::Delivered, "delivered"),
    (CodeConsentSettleOutcome::Refused, "refused"),
    (
        CodeConsentSettleOutcome::DeliveryUnknown,
        "delivery_unknown",
    ),
];

#[test]
fn every_code_consent_settle_outcome_keeps_its_name() {
    assert_eq!(CodeConsentSettleOutcome::Delivered.as_str(), "delivered");
    assert_eq!(CodeConsentSettleOutcome::Refused.as_str(), "refused");
    assert_eq!(
        CodeConsentSettleOutcome::DeliveryUnknown.as_str(),
        "delivery_unknown"
    );
}

#[test]
fn every_code_consent_settle_outcome_name_is_its_serde_name() {
    for (row, name) in CODE_CONSENT_SETTLE_OUTCOME_ROWS {
        let reader: StrDeserializer<'_, ValueError> = name.into_deserializer();
        let read = CodeConsentSettleOutcome::deserialize(reader).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `CodeConsentSettlementOrigin`, as its hand table spelled it.
const CODE_CONSENT_SETTLEMENT_ORIGIN_ROWS: [(CodeConsentSettlementOrigin, &str); 3] = [
    (CodeConsentSettlementOrigin::Seeded, "seeded"),
    (CodeConsentSettlementOrigin::Authored, "authored"),
    (CodeConsentSettlementOrigin::Narrowing, "narrowing"),
];

#[test]
fn every_code_consent_settlement_origin_keeps_its_name() {
    assert_eq!(CodeConsentSettlementOrigin::Seeded.as_str(), "seeded");
    assert_eq!(CodeConsentSettlementOrigin::Authored.as_str(), "authored");
    assert_eq!(CodeConsentSettlementOrigin::Narrowing.as_str(), "narrowing");
}

#[test]
fn every_code_consent_settlement_origin_name_is_its_serde_name() {
    for (row, name) in CODE_CONSENT_SETTLEMENT_ORIGIN_ROWS {
        let reader: StrDeserializer<'_, ValueError> = name.into_deserializer();
        let read = CodeConsentSettlementOrigin::deserialize(reader).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `VoiceConsentState`, as its hand table spelled it.
const VOICE_CONSENT_STATE_ROWS: [(VoiceConsentState, &str); 2] = [
    (VoiceConsentState::Granted, "granted"),
    (VoiceConsentState::Withdrawn, "withdrawn"),
];

#[test]
fn every_voice_consent_state_keeps_its_name() {
    assert_eq!(VoiceConsentState::Granted.as_str(), "granted");
    assert_eq!(VoiceConsentState::Withdrawn.as_str(), "withdrawn");
}

#[test]
fn every_voice_consent_state_name_is_its_serde_name() {
    for (row, name) in VOICE_CONSENT_STATE_ROWS {
        let reader: StrDeserializer<'_, ValueError> = name.into_deserializer();
        let read = VoiceConsentState::deserialize(reader).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn voice_consent_state_parse_reads_each_name_back() {
    for (row, name) in VOICE_CONSENT_STATE_ROWS {
        assert_eq!(VoiceConsentState::parse(name), Some(row), "{name}");
    }
    assert_eq!(VoiceConsentState::parse("not.a.row"), None);
}
