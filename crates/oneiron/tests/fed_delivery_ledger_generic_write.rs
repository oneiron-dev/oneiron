//! FIX FED-DELIVERY-LEDGER-GENERIC-WRITE: a pact's delivery ledger
//! (`feddelivered:<pact>:<epoch>:<record>`) is what makes a present record
//! that pact's recipient copy, for a courtesy deletion ask and for the
//! owner's candidate list (FIX 321, 2927). A delivery intent
//! (`fedintent:<record>:<pact>`) becomes a ledger row when bytes with its
//! digest land at its record (FIX 3498). Both are declared `SyncState`
//! tables, so the generic host doors (`Vault::sync_state_put` and its
//! siblings) wrote and deleted their rows as they do a host's own: a host
//! could make any present record a covered copy. Those doors now refuse both
//! prefixes, as they refuse the deletion markers and the federation world
//! registrations; only the import writes either.
//!
//! Public doors only.
//!
//! `cargo test --locked -p oneiron --all-features --test fed_delivery_ledger_generic_write`

use oneiron::{Vault, VaultConfig};

/// A delivery ledger row's key: pact (hex64), consent epoch (hex16), record (hex32).
fn delivery_key() -> String {
    format!(
        "feddelivered:{}:{:016x}:{}",
        "a1".repeat(32),
        1_u64,
        "b2".repeat(16)
    )
}

/// A delivery intent's key: record (hex32), pact (hex64).
fn intent_key() -> String {
    format!("fedintent:{}:{}", "b2".repeat(16), "a1".repeat(32))
}

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    (dir, vault)
}

/// Every generic put door refuses `key`, and none leaves a row at it.
fn assert_no_generic_put(vault: &Vault, key: &str, value: &[u8]) {
    assert!(
        vault.sync_state_put(key, value).is_err(),
        "sync_state_put wrote {key}"
    );
    assert!(
        vault
            .try_with_write_txn(|wtxn| vault.sync_state_put_in_write_txn(wtxn, key, value))
            .is_err(),
        "sync_state_put_in_write_txn wrote {key}"
    );
    assert!(
        vault
            .sync_state_put_telemetry_batch(&[(key, value)])
            .is_err(),
        "sync_state_put_telemetry_batch wrote {key}"
    );
    assert!(
        vault
            .sync_state_put_telemetry_batch_if_absent(&[(key, value)])
            .is_err(),
        "sync_state_put_telemetry_batch_if_absent wrote {key}"
    );
    assert_eq!(
        vault.sync_state_get(key).expect("a declared key reads"),
        None,
        "a generic door left a row at {key}"
    );
}

#[test]
fn the_generic_host_doors_write_no_federation_delivery_record() {
    let (_dir, vault) = open();
    // The value names the world the record sits in (16 raw bytes).
    assert_no_generic_put(&vault, &delivery_key(), &[0x5a; 16]);
}

#[test]
fn the_generic_host_doors_write_no_federation_delivery_intent() {
    let (_dir, vault) = open();
    // Pact, epoch, time, grant, source vault, then the digest the landing bytes must match.
    assert_no_generic_put(&vault, &intent_key(), &[0x5a; 32 + 8 + 8 + 16 + 32 + 32]);
}

#[test]
fn the_generic_host_delete_removes_no_federation_delivery_row() {
    let (_dir, vault) = open();
    for key in [delivery_key(), intent_key()] {
        assert!(
            vault.sync_state_delete(&key).is_err(),
            "sync_state_delete took {key}"
        );
        assert!(
            vault
                .try_with_write_txn(|wtxn| vault.sync_state_delete_in_write_txn(wtxn, &key))
                .is_err(),
            "sync_state_delete_in_write_txn took {key}"
        );
    }
}

/// Control: a host's own declared row still writes and reads back through the same doors.
#[test]
fn the_generic_host_doors_still_write_a_hosts_own_row() {
    let (_dir, vault) = open();
    let key = format!("pm:2026-03:{}", "c3".repeat(16));
    vault.sync_state_put(&key, &[1]).expect("a host row writes");
    assert_eq!(
        vault.sync_state_get(&key).expect("a host row reads"),
        Some(vec![1])
    );
    assert!(
        vault.sync_state_delete(&key).expect("a host row deletes"),
        "the host row was there"
    );
}
