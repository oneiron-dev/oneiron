//! A vault MACHINE row is an address hint only when it carries the exact versioned envelope.
use oneiron::{EntityId, TimeRange, Vault, VaultConfig, registry::ENTITY_TYPE_MACHINE};
use oneiron_mesh_transport::{
    MachineAddress, MachineAddressEnvelope, MachineRoster, MeshError, VaultMachineRoster,
};
use std::{net::SocketAddr, sync::Arc};

#[test]
fn vault_roster_ignores_other_machine_actors_and_reads_live_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).unwrap());
    let roster = VaultMachineRoster(Arc::clone(&vault));
    let other = EntityId::now();
    vault
        .put_entity(
            &other,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            1,
            b"calendar actor",
        )
        .unwrap();
    assert!(roster.by_machine(other).unwrap().is_none());
    let machine = EntityId::now();
    let key = [9u8; 32];
    let addr: SocketAddr = "127.0.0.1:4242".parse().unwrap();
    let row = MachineAddress {
        endpoint_key: key,
        direct_addrs: vec![addr],
        relay_url: None,
    };
    let bytes = rmp_serde::to_vec_named(&MachineAddressEnvelope::new(row)).unwrap();
    vault
        .put_entity(
            &machine,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            2,
            &bytes,
        )
        .unwrap();
    assert_eq!(
        roster.by_machine(machine).unwrap().unwrap().direct_addrs,
        vec![addr]
    );
    assert_eq!(roster.by_endpoint(key).unwrap().unwrap().0, machine);
    let duplicate = EntityId::now();
    vault
        .put_entity(
            &duplicate,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            3,
            &bytes,
        )
        .unwrap();
    assert!(matches!(
        roster.by_endpoint(key),
        Err(MeshError::InvalidRoster)
    ));
    // A generic rewrite of both rows cannot preserve the old endpoint authorization.
    vault
        .put_entity(
            &machine,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            4,
            b"other actor",
        )
        .unwrap();
    vault
        .put_entity(
            &duplicate,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            5,
            b"other actor",
        )
        .unwrap();
    assert!(roster.by_endpoint(key).unwrap().is_none());
}
