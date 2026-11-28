//! Partial results on the public `vault.hydrate` verb and its room door.

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, Memory};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

const ABSENT: &str = "0123456789abcdef0123456789abcdef";
const MALFORMED: &str = "not a ref";
const UNRETAINED_REVISION: &str = "00000000000000000000000000000000";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_id: EntityId,
    claim: String,
    note: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
        oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
        let owner_id = vault.ensure_embedded_owner_actor().expect("the owner");
        let (claim, note) = {
            let owner = door::owner(&vault).expect("the embedded owner");
            let remembered = call(
                &owner,
                "vault.remember",
                json!({
                    "predicate": "project.deadline",
                    "subject_ref": owner_id.to_hex(),
                    "value": "The harbour survey is due on Friday.",
                    "confidence": 0.9,
                    "source": "user_stated",
                }),
            );
            let note = call(
                &owner,
                "vault.notes.create",
                json!({"kind": "research", "markdown": "Harbour survey notes."}),
            );
            (
                remembered["claim"]["id"]
                    .as_str()
                    .expect("claim id")
                    .to_owned(),
                note["id_hex"].as_str().expect("note id").to_owned(),
            )
        };
        Self {
            vault,
            _dir: dir,
            owner_id,
            claim,
            note,
        }
    }

    fn owner(&self) -> Memory<'_> {
        door::owner(&self.vault).expect("the embedded owner")
    }

    fn mixed_input(&self) -> Value {
        json!({
            "refs": [self.claim, ABSENT, MALFORMED, self.owner_id.to_hex(), self.note],
            "filter": {"entity_types": ["CLAIM", "NOTE"]},
        })
    }

    fn mixed_misses(&self) -> Value {
        json!([
            {"ref": ABSENT, "reason": "not_found"},
            {"ref": MALFORMED, "reason": "malformed"},
            {"ref": self.owner_id.to_hex(), "reason": "not_found"},
        ])
    }
}

fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    door::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

#[test]
fn hydrate_returns_only_the_found_records_and_lists_misses_in_request_order() {
    let f = Fixture::new();
    let owner = f.owner();
    let unfiltered = call(
        &owner,
        "vault.hydrate",
        json!({"refs": [f.owner_id.to_hex()]}),
    );
    assert_eq!(unfiltered["value"][0]["kind"], "PERSON");
    assert_eq!(unfiltered["missing"], json!([]));

    let answer = call(&owner, "vault.hydrate", f.mixed_input());
    let ids: Vec<_> = answer["value"]
        .as_array()
        .expect("found views")
        .iter()
        .map(|row| row["id_hex"].as_str().expect("view id"))
        .collect();
    assert_eq!(ids, [f.claim.as_str(), f.note.as_str()]);
    assert_eq!(answer["missing"], f.mixed_misses());
    assert!(answer["narrowing"].is_object());
}

#[test]
fn absent_and_filter_withheld_refs_have_the_same_miss_shape_and_reason() {
    let f = Fixture::new();
    let answer = call(&f.owner(), "vault.hydrate", f.mixed_input());
    let missing = answer["missing"].as_array().expect("misses");
    let absent = missing[0].as_object().expect("absent miss");
    let withheld = missing[2].as_object().expect("withheld miss");
    assert_eq!(absent.len(), 2);
    assert!(absent.contains_key("ref") && absent.contains_key("reason"));
    assert_eq!(
        absent.keys().collect::<Vec<_>>(),
        withheld.keys().collect::<Vec<_>>()
    );
    assert_eq!(absent["reason"], "not_found");
    assert_eq!(absent["reason"], withheld["reason"]);
}

#[test]
fn an_invalid_revision_suffix_is_malformed_but_an_unretained_pin_is_not_found() {
    let f = Fixture::new();
    let malformed = format!("{}@not-hex", f.claim);
    let unretained = format!("{}@{UNRETAINED_REVISION}", f.claim);
    let answer = call(
        &f.owner(),
        "vault.hydrate",
        json!({"refs": [malformed, unretained]}),
    );
    assert_eq!(
        answer["missing"],
        json!([
            {"ref": malformed, "reason": "malformed"},
            {"ref": unretained, "reason": "not_found"},
        ])
    );
}

#[test]
fn a_hydrate_with_only_misses_returns_an_empty_value_list() {
    let f = Fixture::new();
    let answer = call(
        &f.owner(),
        "vault.hydrate",
        json!({"refs": [ABSENT, MALFORMED]}),
    );
    assert_eq!(answer["value"], json!([]));
    assert_eq!(
        answer["missing"],
        json!([
            {"ref": ABSENT, "reason": "not_found"},
            {"ref": MALFORMED, "reason": "malformed"},
        ])
    );
    assert!(answer["narrowing"].is_object());
}

#[test]
fn strict_hydrate_still_refuses_the_same_refs_instead_of_returning_partial_views() {
    let f = Fixture::new();
    let owner = f.owner();
    let refs = vec![f.claim.clone(), ABSENT.to_owned(), f.note.clone()];
    let answer = call(&owner, "vault.hydrate", json!({"refs": refs}));
    assert_eq!(
        answer["missing"],
        json!([{"ref": ABSENT, "reason": "not_found"}])
    );
    assert_eq!(
        owner.hydrate(&refs).unwrap_err().code,
        MEMORY_CODE_NOT_FOUND
    );

    // The strict door resolves every target before reading any slot, so a
    // syntactically bad ref still fails the call before a read can miss.
    let mixed_refs =
        serde_json::from_value::<Vec<String>>(f.mixed_input()["refs"].clone()).expect("mixed refs");
    assert_eq!(
        owner.hydrate(&mixed_refs).unwrap_err().code,
        MEMORY_CODE_BAD_REQUEST
    );
}

#[test]
fn a_pinned_ref_with_one_leading_space_hydrates_to_its_view_and_lists_no_miss() {
    let f = Fixture::new();
    let owner = f.owner();
    let probe = call(&owner, "vault.hydrate", json!({"refs": [f.claim]}));
    let short = probe["value"][0]["short_ref"]
        .as_str()
        .expect("the claim's short ref")
        .to_owned();
    let id = EntityId::from_hex(&f.claim).expect("claim id");
    let revision = f.vault.pin_entity_revision(&id).expect("retained revision");
    let pinned = format!("{short}@{}", revision.to_hex());
    let answer = call(
        &owner,
        "vault.hydrate",
        json!({"refs": [format!(" {pinned}")]}),
    );
    assert_eq!(
        answer["value"].as_array().expect("views").len(),
        1,
        "{answer}"
    );
    assert_eq!(answer["value"][0]["id_hex"], json!(f.claim), "{answer}");
    assert_eq!(answer["missing"], json!([]), "{answer}");
}

#[test]
fn a_pinned_ref_with_an_uppercase_hex_id_hydrates_to_its_view_and_lists_no_miss() {
    let f = Fixture::new();
    let owner = f.owner();
    assert_ne!(
        f.claim,
        f.claim.to_uppercase(),
        "the fixture id must spell a hex letter for this test"
    );
    let id = EntityId::from_hex(&f.claim).expect("claim id");
    let revision = f.vault.pin_entity_revision(&id).expect("retained revision");
    let pinned = format!("{}@{}", f.claim.to_uppercase(), revision.to_hex());
    let answer = call(&owner, "vault.hydrate", json!({"refs": [pinned]}));
    assert_eq!(
        answer["value"].as_array().expect("views").len(),
        1,
        "{answer}"
    );
    assert_eq!(answer["value"][0]["id_hex"], json!(f.claim), "{answer}");
    assert_eq!(answer["missing"], json!([]), "{answer}");
}

#[cfg(oneiron_test_support)]
#[test]
fn the_room_hydrate_door_lists_the_same_misses_as_the_facade() {
    use oneiron::off_record::OffRecordBackendClass;
    use oneiron::test_doors::hydrate_missing::hydrate_as_owner;
    use oneiron::{EdgeActorClass, WriteActor};

    let f = Fixture::new();
    let session = f
        .vault
        .off_record_session_vault()
        .enter("hydrate-missing", OffRecordBackendClass::Local)
        .expect("off-record session");
    let input = f.mixed_input();
    let facade = call(&f.owner(), "vault.hydrate", input.clone());
    let room = hydrate_as_owner(
        &session,
        WriteActor::new(f.owner_id, EdgeActorClass::Human),
        &input,
    )
    .expect("room hydrate");
    assert_eq!(room["missing"], f.mixed_misses());
    assert_eq!(room["missing"], facade["missing"]);
    assert_eq!(room["value"], facade["value"]);
    assert!(room["narrowing"].is_object());
}
