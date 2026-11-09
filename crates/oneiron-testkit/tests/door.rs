//! A verb run through the in-process door leaves a receipt the receipt
//! reader reads back through `vault.receipts`.

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

#[test]
fn an_unknown_verb_is_refused_at_the_door() {
    let copy = FixtureVault::empty(&fixture_cache!()).expect("fixture").copy().expect("copy");
    let vault = copy.open().expect("open");
    let owner = door::owner(&vault).expect("the owner");
    assert!(door::invoke(&owner, "vault.no_such_verb", json!({})).is_err());
}
