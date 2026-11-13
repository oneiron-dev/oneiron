//! Census L3-28B (ARCH-0044 H336): the endpoint lookup is served from a
//! derived endpoint-to-MACHINE index instead of reading every MACHINE row's
//! body. Below the walk's bound the index changes no answer: through an
//! address write, its move to a new key, a second MACHINE on one key (both
//! refuse), an address rewritten away, a delete, and a reopen that rebuilds
//! the dropped index, the index answers each lookup (no fallback) as the
//! walk answers it. An owner's lookup the index serves reads no MACHINE row
//! past its own, so it raises no `MachineRows` check; with the index
//! dropped it walks and raises one, as before.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test mesh_machine_endpoint_index`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;
use oneiron::authority::{MeshMachineAddress, MeshMachineAddressEnvelope};
use oneiron::registry::ENTITY_TYPE_MACHINE;
use oneiron::scan_check::EngineScan;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::mesh_machine_endpoint_index::{self as doors, IndexedEndpoint};
use oneiron::{EntityId, Vault, VaultConfig};

fn endpoint_key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

fn address_body(endpoint_key: [u8; 32]) -> Vec<u8> {
    rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(MeshMachineAddress {
        endpoint_key,
        direct_addrs: vec![],
        relay_url: None,
    }))
    .expect("address envelope")
}

fn put_machine(vault: &Vault, machine: &EntityId, body: &[u8]) {
    vault
        .put_entity(
            machine,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .expect("a MACHINE row");
}

/// The lookup of `key`: the index answers it (no fallback), its answer is
/// the walk's, and the public lookup gives the same MACHINE.
fn assert_index_answers_as_walk(vault: &Vault, key: [u8; 32], expected: Option<EntityId>) {
    assert_eq!(
        doors::indexed_machine(vault, key).expect("index read"),
        IndexedEndpoint::Found(expected),
        "the index serves the lookup"
    );
    assert_eq!(
        doors::walked_machine(vault, key).expect("walk"),
        expected,
        "the walk gives the index's answer"
    );
    assert_eq!(
        vault
            .mesh_machine_by_endpoint(key)
            .expect("lookup")
            .map(|(id, _)| id),
        expected
    );
}

#[test]
fn index_answers_as_the_walk_through_writes_a_delete_and_a_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    assert!(
        doors::index_complete(&vault).expect("flag"),
        "open builds the index"
    );
    let (a, b, c) = (endpoint_key(0x51), endpoint_key(0x52), endpoint_key(0x53));
    let first = EntityId::now();
    put_machine(&vault, &first, &address_body(a));
    put_machine(&vault, &EntityId::now(), b"calendar actor");
    assert_index_answers_as_walk(&vault, a, Some(first));
    assert_index_answers_as_walk(&vault, b, None);

    // The address moves to a new key: the old key names no MACHINE.
    put_machine(&vault, &first, &address_body(b));
    assert_index_answers_as_walk(&vault, a, None);
    assert_index_answers_as_walk(&vault, b, Some(first));

    // Two MACHINE rows on one key: the index refuses, as the walk does.
    let second = EntityId::now();
    put_machine(&vault, &second, &address_body(b));
    assert_eq!(
        doors::indexed_machine(&vault, b).expect("index read"),
        IndexedEndpoint::Refused
    );
    assert!(doors::walked_machine(&vault, b).is_err());
    assert!(vault.mesh_machine_by_endpoint(b).is_err());

    // The second row's address is rewritten away; the first is deleted.
    put_machine(&vault, &second, b"other actor");
    assert_index_answers_as_walk(&vault, b, Some(first));
    assert!(vault.delete_entity(&first).expect("delete"));
    assert_index_answers_as_walk(&vault, b, None);

    // A vault older than the index: the lookup walks, and the reopen
    // rebuilds the index from the MACHINE rows.
    let third = EntityId::now();
    put_machine(&vault, &third, &address_body(c));
    doors::drop_index(&vault).expect("drop the index");
    assert_eq!(
        doors::indexed_machine(&vault, c).expect("index read"),
        IndexedEndpoint::Walk
    );
    assert_eq!(
        vault
            .mesh_machine_by_endpoint(c)
            .expect("the walk answers")
            .map(|(id, _)| id),
        Some(third)
    );
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen");
    assert!(
        doors::index_complete(&vault).expect("flag"),
        "the reopen rebuilds the index"
    );
    assert_index_answers_as_walk(&vault, a, None);
    assert_index_answers_as_walk(&vault, b, None);
    assert_index_answers_as_walk(&vault, c, Some(third));
}

#[test]
fn an_owner_lookup_counts_machine_rows_only_when_it_walks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    for _ in 0..3 {
        put_machine(&vault, &EntityId::now(), b"calendar actor");
    }
    let machine = EntityId::now();
    let key = endpoint_key(0x61);
    put_machine(&vault, &machine, &address_body(key));
    let scan = EngineScan::MachineRows;
    vault.set_scan_threshold(scan, 2).expect("threshold");
    let person = vault.ensure_embedded_owner_actor().expect("owner");
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");

    let found = vault
        .mesh_machine_by_endpoint_as_owner(&owner, key)
        .expect("owner lookup")
        .map(|(id, _)| id);
    assert_eq!(found, Some(machine));
    assert!(
        vault.scan_checks().expect("checks").is_empty(),
        "the index reads no MACHINE row past the one naming the key"
    );

    doors::drop_index(&vault).expect("drop the index");
    let found = vault
        .mesh_machine_by_endpoint_as_owner(&owner, key)
        .expect("owner lookup")
        .map(|(id, _)| id);
    assert_eq!(found, Some(machine));
    let checks = vault.scan_checks().expect("checks");
    assert_eq!(checks.len(), 1, "the walk reads past its threshold row");
    assert_eq!(checks[0].scan, scan.code());
}
