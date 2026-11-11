//! The dispatcher exposes exact keyed memory, not recall reconstruction.
use oneiron::memory::{KeyValueAddress, KeyValueNamespaces, KeyValuePut, KeyValueSearch};
use oneiron_remote::{OneironClient, OpenOptions};
use serde_json::json;

#[test]
fn embedded_keyed_catalog_round_trip_and_replay() {
    let dir = tempfile::tempdir().unwrap();
    let client =
        OneironClient::open(Some(&dir.path().join("vault")), &OpenOptions::default()).unwrap();
    let address = KeyValueAddress {
        namespace: vec!["facts".into()],
        key: "preference".into(),
    };
    let request = KeyValuePut {
        namespace: address.namespace.clone(),
        key: address.key.clone(),
        value: json!({"theme":"dark"}),
        request_id: "request-one".into(),
        source: "user_stated".into(),
    };
    assert!(client.vault_kv_get(&address).unwrap().is_none());
    let receipt = client.vault_kv_put(&request).unwrap();
    assert!(!receipt.replayed);
    assert_eq!(
        client.vault_kv_get(&address).unwrap(),
        Some(receipt.item.clone())
    );
    assert!(client.vault_kv_put(&request).unwrap().replayed);
    assert_eq!(
        client.vault_kv_search(&KeyValueSearch::default()).unwrap(),
        vec![receipt.item]
    );
    assert_eq!(
        client
            .vault_kv_namespaces(&KeyValueNamespaces::default())
            .unwrap(),
        vec![address.namespace.clone()]
    );
    assert!(client.vault_kv_delete(&address).unwrap().existed);
    assert!(client.vault_kv_get(&address).unwrap().is_none());
    assert!(client.vault_kv_put(&request).is_err());
}
