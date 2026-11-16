//! FIX 22392 CONNECTOR-KEY: the one writer of a connector key's suspension
//! admits Active -> Suspended alone. On main its callers each checked for an
//! Active key first, but the writer itself turned a key in any state into
//! Suspended, so a key already suspended took a new reason and time, and a
//! Revoked one came back as Suspended.
//!
//! The writer is crate-private: `oneiron::test_doors::connector_key_suspend`
//! calls it as a budget exhaustion does. The vault and the owner's door are
//! the public ones.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test connector_key_suspend_admission`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::sync::Arc;

use oneiron::connector_key::{ConnectorKeyRecord, ConnectorKeyStatus};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::connector_key_suspend::suspend_on_budget_exhaustion;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const OWNER_REASON: &str = "the owner pauses the key";

/// A vault with a device keystore and install signing, and one Active
/// connector key for a person, as `tests/gate_pins_put_pipeline.rs` G433
/// registers one.
struct Fixture {
    vault: Vault,
    key: EntityId,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temp dir");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("open owned");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let person = EntityId::now();
        let body =
            rmp_serde::to_vec_named(&json!({ "name": "connector person" })).expect("a person body");
        vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .expect("put the person");
        let key = EntityId::now();
        vault
            .register_connector_key(
                &key,
                ConnectorKeyRecord::active("email", Some(person), Vec::new(), 10),
            )
            .expect("register the connector key");
        Self {
            vault,
            key,
            _dir: dir,
        }
    }

    fn stored(&self) -> ConnectorKeyRecord {
        self.vault
            .get_connector_key(&self.key)
            .expect("read the key")
            .expect("the key exists")
    }
}

#[test]
fn exhaust_suspend_core_rejects_non_active_keys() {
    let fixture = Fixture::new();
    fixture
        .vault
        .suspend_connector_key(&fixture.key, OWNER_REASON, 20)
        .expect("the owner suspends the Active key");

    let second = suspend_on_budget_exhaustion(&fixture.vault, &fixture.key, 30);

    assert!(
        second.is_err(),
        "the writer refuses a key that is already Suspended, got {second:?}"
    );
    let stored = fixture.stored();
    assert_eq!(stored.status, ConnectorKeyStatus::Suspended);
    assert_eq!(
        stored.suspended_reason.as_deref(),
        Some(OWNER_REASON),
        "the owner's reason stands"
    );
    assert_eq!(
        stored.status_changed_at,
        Some(20),
        "the owner's time stands"
    );
}

#[test]
fn a_revoked_key_stays_revoked_under_an_exhaust_suspend() {
    let fixture = Fixture::new();
    fixture
        .vault
        .revoke_connector_key(&fixture.key, 20)
        .expect("the key is revoked");

    let suspended = suspend_on_budget_exhaustion(&fixture.vault, &fixture.key, 30);

    assert!(
        suspended.is_err(),
        "the writer refuses a Revoked key, got {suspended:?}"
    );
    assert_eq!(fixture.stored().status, ConnectorKeyStatus::Revoked);
}

#[test]
fn exhaust_suspend_core_still_suspends_an_active_key() {
    let fixture = Fixture::new();

    let suspended = suspend_on_budget_exhaustion(&fixture.vault, &fixture.key, 30)
        .expect("the writer suspends an Active key");

    assert_eq!(suspended.status, ConnectorKeyStatus::Suspended);
    let stored = fixture.stored();
    assert_eq!(stored.status, ConnectorKeyStatus::Suspended);
    assert_eq!(stored.status_changed_at, Some(30));
    assert!(
        stored
            .suspended_reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("budget_exhausted:key:")),
        "the reason names the exhausted row, got {:?}",
        stored.suspended_reason
    );
}
