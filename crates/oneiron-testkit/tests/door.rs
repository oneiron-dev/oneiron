//! A verb run through the in-process door leaves a receipt the receipt
//! reader reads back through `vault.receipts`.

use oneiron_testkit::fixture::jsonl_seed;
use oneiron_testkit::receipt::ReceiptReader;
use oneiron_testkit::{FixtureVault, door, fixture_cache};
use serde_json::json;

#[test]
fn an_owner_write_through_the_door_leaves_a_receipt_the_owner_can_read() {
    let fixture = FixtureVault::empty(&fixture_cache!()).expect("the empty fixture");
    let copy = fixture.copy().expect("copy");
    let vault = copy.open().expect("open");
    let owner = door::owner(&vault).expect("the owner");
    let receipts = ReceiptReader::new(&owner);
    let before = receipts.all(&[]).expect("read the ledger").len();

    let put = json!({
        "namespace": ["testkit"],
        "key": "greeting",
        "value": {"text": "hello"},
        "request_id": "testkit-door-1"
    });
    let first = door::invoke(&owner, "vault.kv.put", put.clone()).expect("the owner may put");
    assert_eq!(first["replayed"], false);
    assert!(first["receipt_ref"].as_str().is_some_and(|reference| !reference.is_empty()));

    let after = receipts.all(&[]).expect("read the ledger");
    assert!(after.len() > before, "the put left a receipt ({before} -> {})", after.len());
    assert!(receipts.latest(&[]).expect("read the newest").is_some());

    let again = door::invoke(&owner, "vault.kv.put", put).expect("the same request again");
    assert_eq!(again["replayed"], true, "a repeated request id replays");
}

/// A fixture seeded from JSONL through public verbs serves what it was
/// seeded with to every copy.
const SEED: &str = r#"
# One owner value, then an hour.
{"verb": "vault.kv.put", "input": {"namespace": ["seed"], "key": "city", "value": {"name": "Lisbon"}, "request_id": "seed-1"}}
{"advance_secs": 3600}
"#;

#[test]
fn a_fixture_seeded_through_verbs_serves_its_seed_to_each_copy() {
    let fixture = FixtureVault::build(&fixture_cache!(), "door-jsonl", jsonl_seed(SEED)).expect("seeded");
    assert_eq!(fixture.ended_at(), oneiron_testkit::FAKE_EPOCH + 3600);
    let copy = fixture.copy().expect("copy");
    let vault = copy.open().expect("open");
    let owner = door::owner(&vault).expect("the owner");
    let item = door::invoke(&owner, "vault.kv.get", json!({"namespace": ["seed"], "key": "city"}))
        .expect("the owner reads the seeded value");
    assert_eq!(item["value"], json!({"name": "Lisbon"}));
}

#[test]
fn a_seed_line_that_fails_names_its_line() {
    let seed = "{\"verb\": \"vault.no_such_verb\", \"input\": {}}\n";
    let error = FixtureVault::build(&fixture_cache!(), "door-bad-seed", jsonl_seed(seed)).expect_err("refused");
    assert!(error.to_string().contains("seed line 1 (vault.no_such_verb)"), "{error}");
}

#[test]
fn an_unknown_verb_is_refused_at_the_door() {
    let copy = FixtureVault::empty(&fixture_cache!()).expect("fixture").copy().expect("copy");
    let vault = copy.open().expect("open");
    let owner = door::owner(&vault).expect("the owner");
    assert!(door::invoke(&owner, "vault.no_such_verb", json!({})).is_err());
}
