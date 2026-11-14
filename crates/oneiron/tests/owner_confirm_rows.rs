//! The owner-confirm table: every gated verb, its proof, and its keep.
//!
//! The table names each verb the shared confirm gates, each row's proof
//! matches its verb row's `host_door_proof`, and only the hold keeps until
//! used. Only one-way acts but sign take the confirm: erase and vault
//! delete.
//!
//! Head only: it uses the new table and its proof and keep types.
//!
//! `cargo test --locked -p oneiron --all-features --test owner_confirm_rows`

use std::collections::BTreeSet;

use oneiron::check_in::{ActClass, verb_needs_owner_confirm};
use oneiron::task_verb::sdk::{OWNER_CONFIRM_ROWS, OwnerConfirmProof, PreviewKeep};
use oneiron::verb_names::VERB_ACT_CLASSES;
use serde_json::Value;

#[test]
fn the_confirm_table_names_every_owner_confirmed_verb() {
    let mut confirmed: BTreeSet<&str> = BTreeSet::new();
    for row in &VERB_ACT_CLASSES {
        if verb_needs_owner_confirm(row.0) {
            confirmed.insert(row.0);
        }
    }
    let mut table: BTreeSet<&str> = BTreeSet::new();
    for row in &OWNER_CONFIRM_ROWS {
        table.insert(row.verb);
    }
    assert_eq!(
        table, confirmed,
        "the table names every owner-confirmed verb"
    );
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/sdk/verbs");
    for row in &OWNER_CONFIRM_ROWS {
        let verb = row.verb;
        let path = format!("{dir}/{verb}.json");
        let text = std::fs::read_to_string(&path).expect("the verb row reads");
        let json: Value = serde_json::from_str(&text).expect("the verb row parses");
        let proof = json
            .get("host_door_proof")
            .and_then(Value::as_str)
            .expect("the verb row names its proof");
        let expected = match row.proof {
            OwnerConfirmProof::Owner => "owner",
            OwnerConfirmProof::SharedPerson => "shared_person",
        };
        assert_eq!(proof, expected, "the {verb} proof matches its row");
    }
    let mut until_used: BTreeSet<&str> = BTreeSet::new();
    for row in &OWNER_CONFIRM_ROWS {
        if row.keep == PreviewKeep::UntilUsed {
            until_used.insert(row.verb);
        }
    }
    assert_eq!(
        until_used,
        BTreeSet::from(["vault.legal_holds.lift_and_erase"]),
        "only the hold keeps until used"
    );
}

#[test]
fn only_one_way_acts_but_sign_take_the_owner_confirm() {
    let mut confirming: BTreeSet<ActClass> = BTreeSet::new();
    for act in ActClass::ALL {
        let expected = act.row().undo.is_one_way() && act != ActClass::Sign;
        assert_eq!(
            act.owner_confirms(),
            expected,
            "the {act:?} confirm matches its undo"
        );
        if act.owner_confirms() {
            confirming.insert(act);
        }
    }
    assert_eq!(
        confirming,
        BTreeSet::from([ActClass::Erase, ActClass::VaultDelete]),
        "only erase and vault delete take the confirm"
    );
}
