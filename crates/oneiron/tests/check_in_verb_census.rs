//! ROLES-CHECKIN PR 2, P2.1 (ONEIRON-ARCH-0082 #act-table): every verb row
//! states its act class, by the ruled names, and core looks a verb's class up
//! from its own row. Nothing reads the class to decide an act yet.
//!
//! Rulings: PR2-SPLIT = B with (a) reads take `read`, a value outside the act
//! table, on Read rows only, and (b) a row with no proven undo class states
//! `unstated` (Engine 11 Nov 16:19); VS-CHECKIN-NAMES = A and VS-OLD-NAMES = A
//! (Engine 11 Nov 11:38).
//!
//! `cargo test --locked -p oneiron --all-features --test check_in_verb_census`.

use std::collections::BTreeMap;
use std::path::Path;

use oneiron::check_in::{
    ActClass, CheckInMode, ModelCheck, RoleDefault, RolePreset, UndoClass, VerbActClass,
    verb_act_class,
};
use oneiron::verb_names::VERB_ACT_CLASSES;

/// The 20 act-class names VS-CHECKIN-NAMES = A rules, in table order.
const RULED_NAMES: [&str; 20] = [
    "reversible_work",
    "spawn",
    "spend_over_cap",
    "outbound_send",
    "room_add",
    "member_add",
    "member_remove",
    "legal_send",
    "sign",
    "billing",
    "delete",
    "vault_delete",
    "erase",
    "ownership_transfer",
    "key_recovery",
    "security_control_disable",
    "mass_secret_export",
    "world_widen",
    "grant_widen",
    "grant_widen_own",
];

/// Every verb file: its name, its `scope` and its `act_class`, as written.
fn verb_files() -> Vec<(String, String, Option<String>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/sdk/verbs");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .expect("the verb table folder")
        .map(|entry| entry.expect("a folder entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path).expect("a verb file");
            let row: serde_json::Value = serde_json::from_str(&text).expect("a JSON verb row");
            let field = |key: &str| {
                row.get(key)
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            };
            let name = field("name").expect("a verb row names its verb");
            let scope = field("scope").expect("a verb row states its scope");
            (name, scope, field("act_class"))
        })
        .collect()
}

#[test]
fn every_verb_file_states_its_act_class_and_core_reads_the_same() {
    let files = verb_files();
    assert!(
        files.len() > 1000,
        "the census read {} verb files",
        files.len()
    );
    let mut missing = Vec::new();
    let mut by_value = BTreeMap::new();
    for (name, scope, token) in &files {
        let Some(value) = token.as_deref().and_then(VerbActClass::from_token) else {
            missing.push(format!("{name}: {token:?}"));
            continue;
        };
        if value == VerbActClass::Read {
            assert_eq!(scope, "Read", "{name}: `read` is on a Read row only");
        }
        assert_eq!(verb_act_class(name), Some(value), "{name}");
        *by_value.entry(value.as_str()).or_insert(0_usize) += 1;
    }
    assert_eq!(missing, Vec::<String>::new(), "rows with no act class");
    assert_eq!(VERB_ACT_CLASSES.len(), files.len());
    eprintln!(
        "act_class census over {} verb files: {by_value:?}",
        files.len()
    );
}

#[test]
fn the_lookup_is_in_verb_name_order_and_knows_only_verb_rows() {
    for pair in VERB_ACT_CLASSES.windows(2) {
        assert!(pair[0].0 < pair[1].0, "{} before {}", pair[0].0, pair[1].0);
    }
    assert_eq!(verb_act_class("no.such.verb"), None);
    assert_eq!(verb_act_class(""), None);
}

#[test]
fn class_names_are_the_ruled_ones_and_old_names_are_refused() {
    let names: Vec<_> = ActClass::ALL.into_iter().map(ActClass::as_str).collect();
    assert_eq!(names, RULED_NAMES);
    for act in ActClass::ALL {
        assert_eq!(ActClass::from_token(act.as_str()), Some(act));
        assert_eq!(
            VerbActClass::from_token(act.as_str()),
            Some(VerbActClass::Act(act))
        );
        let wire = serde_json::to_string(&act).expect("an act class serialises");
        assert_eq!(wire, format!("\"{}\"", act.as_str()), "one name per class");
    }
    for value in [VerbActClass::Read, VerbActClass::Unstated] {
        assert_eq!(VerbActClass::from_token(value.as_str()), Some(value));
        assert_eq!(ActClass::from_token(value.as_str()), None);
    }
    for old in [
        "spend_above_cap",
        "add_or_raise_member",
        "remove_or_demote_member",
        "legal_prepare_and_send",
        "delete_items",
        "widen_anothers_grant",
        "widen_own_grant",
        "READ",
        "Read",
        "",
    ] {
        assert_eq!(VerbActClass::from_token(old), None, "{old:?}");
    }
}

/// ARCH-0082 #agent-room-add: an agent's add to a room or thread checks in,
/// in AskWhenUnsure; canon states no undo class, so an unsure add holds on
/// silence.
#[test]
fn room_add_asks_when_unsure_and_holds_on_silence() {
    let row = ActClass::RoomAdd.row();
    assert_eq!(row.act, ActClass::RoomAdd);
    assert_eq!(row.undo, UndoClass::Unstated);
    assert_eq!(row.model_check, ModelCheck::UnsureTest);
    assert!(!row.catastrophe && !row.fixed && row.floor_class.is_none());
    for role in RolePreset::ALL {
        let expected = match role {
            RolePreset::Delegate => RoleDefault::IfNamed(CheckInMode::AskWhenUnsure),
            RolePreset::Guest => RoleDefault::NoVerb,
            _ => RoleDefault::Mode(CheckInMode::AskWhenUnsure),
        };
        assert_eq!(role.default_for(ActClass::RoomAdd), expected, "{role:?}");
    }
}
