//! UC-03 PR 0: `GateReceiptOutcome`, the closed outcome a Gate receipt records (DESIGN fable/21 §2).
//! Each of the 12 words round-trips through MessagePack and JSON; each of the 11 words the ledger
//! already writes keeps the bytes of the plain string the `outcome` field holds today, so a row a
//! vault holds decodes unchanged once the field is typed; and `admits()` is true for exactly
//! `allow`, `approved` and `approved_amended`. Red on main: main has no `GateReceiptOutcome`, so this
//! file does not build. Kept as a guard through UC-03 stage 3.

use oneiron_store::gate_reason::{GateOutcome, GateReceiptOutcome};
use serde::{Deserialize, Serialize};

/// Every word with its stored token, in the order of DESIGN §2.1's table.
const TOKENS: [(GateReceiptOutcome, &str); 12] = [
    (GateReceiptOutcome::Allow, "allow"),
    (GateReceiptOutcome::Pending, "pending"),
    (GateReceiptOutcome::Deny, "deny"),
    (GateReceiptOutcome::Approved, "approved"),
    (GateReceiptOutcome::ApprovedAmended, "approved_amended"),
    (GateReceiptOutcome::Rejected, "rejected"),
    (GateReceiptOutcome::LetGo, "let_go"),
    (GateReceiptOutcome::Superseded, "superseded"),
    (GateReceiptOutcome::Retracted, "retracted"),
    (GateReceiptOutcome::Invalidated, "invalidated"),
    (GateReceiptOutcome::Revoked, "revoked"),
    (GateReceiptOutcome::Noted, "noted"),
];

/// The 11 words Gate rows already hold as plain strings (DESIGN §2.3, "Kept"). `noted` is the one
/// new word.
const KEPT: [&str; 11] = [
    "allow",
    "pending",
    "deny",
    "approved",
    "approved_amended",
    "rejected",
    "let_go",
    "superseded",
    "retracted",
    "invalidated",
    "revoked",
];

/// The `outcome` field as the ledger row holds it today.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct StringRow {
    version: u8,
    outcome: String,
}

/// The same row once the field is typed.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TypedRow {
    version: u8,
    outcome: GateReceiptOutcome,
}

#[test]
fn the_table_names_every_outcome_once() {
    assert_eq!(
        TOKENS.map(|(outcome, _)| outcome),
        GateReceiptOutcome::ALL,
        "TOKENS lists ALL in order"
    );
    for (outcome, token) in TOKENS {
        assert_eq!(outcome.as_str(), token, "{outcome:?}");
    }
}

#[test]
fn every_token_round_trips_through_msgpack_and_json() {
    for (outcome, token) in TOKENS {
        let array = rmp_serde::to_vec(&outcome).unwrap();
        let named = rmp_serde::to_vec_named(&outcome).unwrap();
        assert_eq!(array, named, "{token}: one MessagePack form");
        assert_eq!(
            rmp_serde::from_slice::<GateReceiptOutcome>(&array).unwrap(),
            outcome,
            "{token}"
        );
        let json = serde_json::to_string(&outcome).unwrap();
        assert_eq!(
            json,
            format!("\"{token}\""),
            "{token}: JSON is the bare token"
        );
        assert_eq!(
            serde_json::from_str::<GateReceiptOutcome>(&json).unwrap(),
            outcome,
            "{token}"
        );
    }
}

#[test]
fn a_kept_word_keeps_the_bytes_of_the_string_written_today() {
    for token in KEPT {
        let (outcome, _) = TOKENS.into_iter().find(|(_, t)| *t == token).unwrap();
        // The bare value.
        assert_eq!(
            rmp_serde::to_vec(&outcome).unwrap(),
            rmp_serde::to_vec(&token).unwrap(),
            "{token}: MessagePack"
        );
        assert_eq!(
            serde_json::to_string(&outcome).unwrap(),
            serde_json::to_string(&token).unwrap(),
            "{token}: JSON"
        );
        // A row in both MessagePack struct forms the store writes, and in JSON.
        let string_row = StringRow {
            version: 0,
            outcome: token.to_owned(),
        };
        let typed_row = TypedRow {
            version: 0,
            outcome,
        };
        let string_array = rmp_serde::to_vec(&string_row).unwrap();
        let string_map = rmp_serde::to_vec_named(&string_row).unwrap();
        assert_eq!(
            rmp_serde::to_vec(&typed_row).unwrap(),
            string_array,
            "{token}"
        );
        assert_eq!(
            rmp_serde::to_vec_named(&typed_row).unwrap(),
            string_map,
            "{token}"
        );
        assert_eq!(
            serde_json::to_string(&typed_row).unwrap(),
            serde_json::to_string(&string_row).unwrap(),
            "{token}: JSON row"
        );
        // A row held today reads into the typed field, and back.
        assert_eq!(
            rmp_serde::from_slice::<TypedRow>(&string_map).unwrap(),
            typed_row,
            "{token}"
        );
        assert_eq!(
            rmp_serde::from_slice::<StringRow>(&rmp_serde::to_vec_named(&typed_row).unwrap())
                .unwrap(),
            string_row,
            "{token}"
        );
    }
}

#[test]
fn a_word_outside_the_set_does_not_decode() {
    for word in [
        "denied",
        "owner_plane_block",
        "bundle_approved",
        "Allow",
        "",
    ] {
        let bytes = rmp_serde::to_vec(&word).unwrap();
        assert!(
            rmp_serde::from_slice::<GateReceiptOutcome>(&bytes).is_err(),
            "{word:?} is not an outcome"
        );
    }
}

#[test]
fn admits_is_true_for_exactly_allow_approved_and_approved_amended() {
    let admitting: Vec<&str> = GateReceiptOutcome::ALL
        .into_iter()
        .filter(|outcome| outcome.admits())
        .map(GateReceiptOutcome::as_str)
        .collect();
    assert_eq!(admitting, ["allow", "approved", "approved_amended"]);
}

#[test]
fn a_gate_evaluation_maps_onto_its_own_word() {
    for (verdict, outcome) in [
        (GateOutcome::Allow, GateReceiptOutcome::Allow),
        (GateOutcome::Pending, GateReceiptOutcome::Pending),
        (GateOutcome::Deny, GateReceiptOutcome::Deny),
    ] {
        assert_eq!(GateReceiptOutcome::from(verdict), outcome);
        assert_eq!(outcome.as_str(), verdict.as_str());
    }
}
