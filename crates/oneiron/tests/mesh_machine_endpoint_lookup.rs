//! Census L3-28B (ARCH-0044 H336): the lookup any endpoint key can make
//! used to walk every MACHINE row's body and refused past 1,024 rows, so a
//! vault holding more MACHINE rows answered every mesh peer's lookup with a
//! refusal. The endpoint-to-MACHINE index reads only the rows that name the
//! key: past the old bound the lookup finds the MACHINE whose address names
//! the key, and answers none for a key no MACHINE names.
//!
//! Runs on public paths: `cargo test --locked -p oneiron --all-features
//! --test mesh_machine_endpoint_lookup`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;
use oneiron::authority::{MeshMachineAddress, MeshMachineAddressEnvelope, PeerMachine};
use oneiron::registry::ENTITY_TYPE_MACHINE;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault, VaultConfig};

/// One row past the 1,024 MACHINE rows the walk reads before it refuses.
const PAST_THE_WALK_BOUND: usize = 1_025;

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

#[test]
fn a_stranger_finds_the_machine_past_the_walk_bound() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    for _ in 0..PAST_THE_WALK_BOUND {
        put_machine(&vault, &EntityId::now(), b"calendar actor");
    }
    // Written last, so a walk in id order reaches it past the bound.
    let machine = EntityId::now();
    let key = endpoint_key(0x41);
    put_machine(&vault, &machine, &address_body(key));

    let found = vault
        .mesh_machine_by_endpoint(key)
        .expect("a lookup past 1,024 MACHINE rows answers");
    assert_eq!(
        found.map(|(id, address)| (id, address.endpoint_key)),
        Some((machine, key)),
        "the MACHINE whose address names the key"
    );
    let unknown = endpoint_key(0x42);
    assert!(
        vault
            .mesh_machine_by_endpoint(unknown)
            .expect("a lookup past 1,024 MACHINE rows answers")
            .is_none(),
        "no MACHINE names this key"
    );
    assert_eq!(
        vault
            .mesh_peer_machine(unknown, b"mesh/sync")
            .expect("a peer lookup past 1,024 MACHINE rows answers"),
        PeerMachine::Unknown
    );
}
