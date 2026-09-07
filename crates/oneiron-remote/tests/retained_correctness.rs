//! Retained admission regressions through the actual shared SDK dispatcher.

use oneiron::memory::{ClaimInput, MEMORY_CODE_BAD_REQUEST};
use oneiron_remote::{MAX_ENTITY_PAYLOAD_BYTES, OneironClient, OpenOptions};

#[cfg(unix)]
#[test]
fn registry_rejects_replaced_directory_and_accepts_restored_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault");
    let moved = dir.path().join("moved");
    let replacement = dir.path().join("replacement");
    let options = OpenOptions::default();
    let first = OneironClient::open(Some(&path), &options).expect("first owner");
    std::fs::rename(&path, &moved).expect("rename old vault");
    std::fs::create_dir(&path).expect("replacement directory");
    let error = OneironClient::open(Some(&path), &options).expect_err("must not join old inode");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        !path.join("data.mdb").exists(),
        "replacement was not opened"
    );
    std::fs::rename(&path, &replacement).expect("move replacement aside");
    std::fs::rename(&moved, &path).expect("restore original inode");
    let restored = OneironClient::open(Some(&path), &options).expect("same directory again");
    assert_eq!(first.shared_vault_addr(), restored.shared_vault_addr());
}

#[test]
fn both_backends_refuse_complete_claim_payload_before_dispatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let embedded = OneironClient::open(Some(dir.path()), &OpenOptions::default()).expect("open");
    let remote = OneironClient::connect("http://127.0.0.1:9", "unused").expect("connect config");
    let before = embedded.receipts(10).expect("receipts before refusals");
    let mut claim = ClaimInput {
        id: None,
        predicate: "test.payload".to_owned(),
        subject_ref: embedded.actor_ref().expect("owner"),
        value: serde_json::json!("small"),
        confidence: 1.0,
        source: "user_stated".to_owned(),
        world_ref: None,
        scope: Some(serde_json::json!({"opaque": "x".repeat(MAX_ENTITY_PAYLOAD_BYTES)})),
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    };
    for client in [&embedded, &remote] {
        let error = client.claim_upsert(&claim).expect_err("over-cap scope");
        assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
        assert!(error.message.contains("claim payload"));
    }
    claim.scope = None;
    claim.world_ref = Some("x".repeat(MAX_ENTITY_PAYLOAD_BYTES));
    for client in [&embedded, &remote] {
        assert_eq!(
            client.claim_upsert(&claim).expect_err("over-cap ref").code,
            MEMORY_CODE_BAD_REQUEST,
        );
    }
    assert_eq!(embedded.receipts(10).expect("no writes"), before);
}
