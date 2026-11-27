//! HOUSE-SCHEMA-SWITCH stage 1: the answer-schema switch the owner controls and the
//! engine can pause. The setting `dreamer.extraction.answer_schema` ships on; the engine's
//! hold pauses it without writing the setting; the owner's write (or clear) re-arms; TURN
//! requests carry the schema only while in force; NOTE reviews never do; each event shows
//! once in the morning report with its receipt id.
//! Reaches the engine through `oneiron::test_doors::dreamer_answer_schema`, built only
//! under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::dreamer_answer_schema as door;
use serde_json::{Value, json};

const ANSWER_SCHEMA: &str = "dreamer.extraction.answer_schema";
const OTHER_BOOL: &str = "deletion.brief_share.require_confirmed";
const T0: u64 = 1_790_000_000;
const PERIOD: u64 = 86_400;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = open_dreamer_vault(dir.path(), "test-reader").expect("dreamer vault");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _dir: dir,
            owner_proof,
        }
    }

    fn set_as_owner(&self, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.vault.set_setting(
            SettingCaller::Owner(&self.owner_proof),
            SetSetting::vault_value(key, value),
        )
    }
}

#[test]
fn the_schema_is_in_force_by_default() {
    let fixture = Fixture::new();
    assert_eq!(
        door::setting(&fixture.vault).expect("setting reads"),
        true,
        "the setting ships on"
    );
    assert_eq!(
        door::in_force(&fixture.vault).expect("in-force reads"),
        true,
        "in force by default"
    );
    assert_eq!(
        door::hold(&fixture.vault).expect("hold reads"),
        None,
        "no hold"
    );
    assert!(
        door::events(&fixture.vault)
            .expect("events read")
            .is_empty(),
        "no events"
    );
}

#[test]
fn the_owner_turning_it_off_takes_it_out_of_force() {
    let fixture = Fixture::new();
    let outcome = fixture
        .set_as_owner(ANSWER_SCHEMA, json!(false))
        .expect("owner turns it off");
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the owner's change applies and is recorded: {outcome:?}"
    );
    assert_eq!(door::setting(&fixture.vault).expect("setting"), false);
    assert_eq!(door::in_force(&fixture.vault).expect("in-force"), false);
}

#[test]
fn a_suspension_takes_it_out_of_force_without_writing_the_owners_setting() {
    let fixture = Fixture::new();
    let id = door::suspend_window(&fixture.vault, -0.5, -0.8, -0.2, 100, 7, T0).expect("suspend");
    assert_eq!(door::hold(&fixture.vault).expect("hold"), Some(id));
    assert_eq!(door::in_force(&fixture.vault).expect("in-force"), false);
    assert_eq!(
        door::setting(&fixture.vault).expect("setting"),
        true,
        "the setting still reads true"
    );
    let events = door::events(&fixture.vault).expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, id);
    assert_eq!(events[0].kind, "suspended_window");
}

#[test]
fn suspending_twice_keeps_one_hold_and_one_event() {
    let fixture = Fixture::new();
    let first =
        door::suspend_window(&fixture.vault, -0.5, -0.8, -0.2, 100, 7, T0).expect("first suspend");
    let second = door::suspend_grammar_faults(&fixture.vault, "2026-11-20", 3, T0 + 1)
        .expect("second suspend");
    assert_eq!(second, first, "the second returns the live hold's id");
    assert_eq!(door::hold(&fixture.vault).expect("hold"), Some(first));
    let events = door::events(&fixture.vault).expect("events");
    assert_eq!(events.len(), 1, "one hold and one event");
    assert_eq!(events[0].id, first);
}

#[test]
fn the_owners_equal_value_write_re_arms_it_and_records_one_rearmed_event() {
    let fixture = Fixture::new();
    let first = fixture
        .set_as_owner(ANSWER_SCHEMA, json!(true))
        .expect("row already true");
    assert!(
        matches!(
            first,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the first write records: {first:?}"
    );
    let suspended =
        door::suspend_window(&fixture.vault, -0.5, -0.8, -0.2, 100, 7, T0).expect("suspend");
    assert_eq!(door::in_force(&fixture.vault).expect("in-force"), false);
    let outcome = fixture
        .set_as_owner(ANSWER_SCHEMA, json!(true))
        .expect("write true again");
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the equal write records: {outcome:?}"
    );
    assert_eq!(
        door::hold(&fixture.vault).expect("hold"),
        None,
        "the hold clears"
    );
    assert_eq!(door::in_force(&fixture.vault).expect("in-force"), true);
    let events = door::events(&fixture.vault).expect("events");
    assert_eq!(events.len(), 2, "one suspend and one rearmed");
    assert_eq!(events[0].id, suspended);
    assert_eq!(events[0].kind, "suspended_window");
    assert_eq!(events[1].kind, "rearmed", "one rearmed event");
    assert!(events[1].id > events[0].id, "time-ordered");
}

#[test]
fn the_owner_turning_it_off_while_paused_clears_the_hold_with_no_rearm_line() {
    let fixture = Fixture::new();
    let suspended =
        door::suspend_window(&fixture.vault, -0.5, -0.8, -0.2, 100, 7, T0).expect("suspend");
    let outcome = fixture
        .set_as_owner(ANSWER_SCHEMA, json!(false))
        .expect("owner turns it off");
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the owner's change records: {outcome:?}"
    );
    assert_eq!(
        door::hold(&fixture.vault).expect("hold"),
        None,
        "the hold clears"
    );
    assert_eq!(door::in_force(&fixture.vault).expect("in-force"), false);
    assert_eq!(door::setting(&fixture.vault).expect("setting"), false);
    let events = door::events(&fixture.vault).expect("events");
    assert_eq!(events.len(), 1, "no rearm event");
    assert_eq!(events[0].id, suspended);
    let view = fixture
        .vault
        .proactivity_digest(&fixture.owner_proof, T0, None)
        .expect("digest assembles")
        .expect("digest due");
    let line = view.answer_schema.expect("answer-schema line");
    assert_eq!(line.items.len(), 1, "no rearm line");
    assert_eq!(line.items[0].event, suspended.to_hex());
    assert_eq!(line.items[0].kind, "paused");
}

#[test]
fn an_equal_value_write_on_another_key_still_changes_nothing() {
    let fixture = Fixture::new();
    assert_eq!(
        door::in_force(&fixture.vault).expect("in-force"),
        true,
        "the door reads"
    );
    let first = fixture
        .set_as_owner(OTHER_BOOL, json!(true))
        .expect("first true");
    assert!(
        matches!(
            first,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the first write records: {first:?}"
    );
    let second = fixture
        .set_as_owner(OTHER_BOOL, json!(true))
        .expect("equal true");
    assert!(
        matches!(second, SetSettingOutcome::Applied { sequence: None, .. }),
        "an equal write on another key changes nothing: {second:?}"
    );
}

#[test]
fn a_turn_request_carries_the_schema_only_while_in_force() {
    let fixture = Fixture::new();
    assert!(
        door::turn_params(&fixture.vault)
            .expect("params")
            .contains_key("answer_schema"),
        "carries by default"
    );
    fixture
        .set_as_owner(ANSWER_SCHEMA, json!(false))
        .expect("owner turns it off");
    assert!(
        !door::turn_params(&fixture.vault)
            .expect("params")
            .contains_key("answer_schema"),
        "absent while off"
    );
    fixture
        .set_as_owner(ANSWER_SCHEMA, json!(true))
        .expect("owner turns it on");
    assert!(
        door::turn_params(&fixture.vault)
            .expect("params")
            .contains_key("answer_schema"),
        "carries while on"
    );
    door::suspend_window(&fixture.vault, -0.5, -0.8, -0.2, 100, 7, T0).expect("suspend");
    assert_eq!(door::setting(&fixture.vault).expect("setting"), true);
    assert!(
        !door::turn_params(&fixture.vault)
            .expect("params")
            .contains_key("answer_schema"),
        "absent while paused"
    );
    fixture
        .set_as_owner(ANSWER_SCHEMA, json!(true))
        .expect("re-arm");
    assert!(
        door::turn_params(&fixture.vault)
            .expect("params")
            .contains_key("answer_schema"),
        "carries after re-arm"
    );
}

#[test]
fn a_note_review_request_never_carries_it() {
    let fixture = Fixture::new();
    assert_eq!(door::in_force(&fixture.vault).expect("in-force"), true);
    assert!(
        door::turn_params(&fixture.vault)
            .expect("turn params")
            .contains_key("answer_schema"),
        "a TURN call carries it while in force"
    );
    assert!(
        !door::note_params(false)
            .expect("note params")
            .contains_key("answer_schema"),
        "a NOTE review does not, while in force"
    );
    assert!(
        door::note_params(true).is_err(),
        "a NOTE review that asks for it is refused"
    );
}

#[test]
fn the_owner_clearing_the_row_while_paused_re_arms_it_with_a_line() {
    let fixture = Fixture::new();
    fixture
        .set_as_owner(ANSWER_SCHEMA, json!(true))
        .expect("the owner's row");
    let suspended =
        door::suspend_window(&fixture.vault, -0.5, -0.8, -0.2, 100, 7, T0).expect("suspend");
    let clear = SetSetting {
        value: None,
        ..SetSetting::vault_value(ANSWER_SCHEMA, json!(true))
    };
    let outcome = fixture
        .vault
        .set_setting(SettingCaller::Owner(&fixture.owner_proof), clear)
        .expect("owner clears the row");
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the clear records: {outcome:?}"
    );
    assert_eq!(
        door::setting(&fixture.vault).expect("setting"),
        true,
        "reads the default"
    );
    assert_eq!(
        door::hold(&fixture.vault).expect("hold"),
        None,
        "the hold clears"
    );
    assert_eq!(door::in_force(&fixture.vault).expect("in-force"), true);
    let events = door::events(&fixture.vault).expect("events");
    assert_eq!(events.len(), 2, "one suspend and one rearmed");
    assert_eq!(events[0].id, suspended);
    assert_eq!(
        events[1].kind, "rearmed",
        "the schema back on shows as a line"
    );
}

#[test]
fn the_digest_shows_each_answer_schema_event_once_with_its_receipt_id() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;

    let window = door::suspend_window(vault, -0.5, -0.8, -0.2, 100, 7, T0).expect("suspend window");

    let view1 = vault
        .proactivity_digest(&fixture.owner_proof, T0, None)
        .expect("assemble 1")
        .expect("digest 1 due");
    let line1 = view1.answer_schema.clone().expect("line 1");
    assert_eq!(line1.items.len(), 1);
    assert_eq!(line1.items[0].event, window.to_hex());
    assert_eq!(line1.items[0].kind, "paused");
    assert_eq!(
        line1.items[0].summary,
        "Answer schema paused: schema nights scored lower than without it over the last 7 \
         nights (d=-0.500, n=100). Turn it back on in Settings."
    );
    assert_eq!(line1.through, window);
    assert!(
        view1.rendered.contains(&line1.items[0].summary),
        "rendered carries the line"
    );
    assert!(
        view1.rendered.contains(&window.to_hex()),
        "rendered carries the ref"
    );

    fixture
        .set_as_owner(ANSWER_SCHEMA, json!(true))
        .expect("re-arm");
    let events = door::events(vault).expect("events");
    assert_eq!(events.len(), 2);
    let rearmed = events
        .iter()
        .find(|event| event.kind == "rearmed")
        .expect("rearmed event")
        .id;
    assert!(rearmed > window, "time-ordered");

    let grammar =
        door::suspend_grammar_faults(vault, "2026-11-20", 3, T0 + PERIOD).expect("suspend grammar");
    assert!(grammar > rearmed, "time-ordered");

    let view2 = vault
        .proactivity_digest(&fixture.owner_proof, T0 + PERIOD, None)
        .expect("assemble 2")
        .expect("digest 2 due");
    let line2 = view2.answer_schema.clone().expect("line 2");
    assert_eq!(line2.items.len(), 2, "rearmed then grammar, in order");
    assert_eq!(line2.items[0].event, rearmed.to_hex());
    assert_eq!(line2.items[0].kind, "rearmed");
    assert_eq!(
        line2.items[0].summary,
        "Answer schema turned back on by you in Settings."
    );
    assert_eq!(line2.items[1].event, grammar.to_hex());
    assert_eq!(line2.items[1].kind, "paused");
    assert_eq!(
        line2.items[1].summary,
        "Answer schema paused: on 2026-11-20, 3 schema replies did not come back whole \
         while the same calls without it did. Turn it back on in Settings."
    );
    assert_eq!(line2.through, grammar);
    assert!(view2.rendered.contains(&line2.items[0].summary));
    assert!(view2.rendered.contains(&line2.items[1].summary));

    let view3 = vault
        .proactivity_digest(&fixture.owner_proof, T0 + 2 * PERIOD, None)
        .expect("assemble 3");
    assert!(
        view3.is_none()
            || view3
                .as_ref()
                .and_then(|view| view.answer_schema.clone())
                .is_none(),
        "nothing repeated: {view3:?}"
    );
}
