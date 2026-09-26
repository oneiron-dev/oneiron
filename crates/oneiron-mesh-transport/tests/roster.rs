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

#[test]
fn paired_machine_grants_are_independent_of_address_hints() {
    use ed25519_dalek::{Signer, SigningKey};
    use oneiron::{
        authority::{HostSlipIssuer, pairing_binding_transcript},
        federation::Scope,
    };
    use oneiron_mesh_transport::{
        AcceptPolicy, MachineGrants, VaultMachineGrants, transport_key::TransportKey,
    };
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).unwrap());
    let host = HostSlipIssuer::from_secret(b"roster integration host key").unwrap();
    vault.ensure_host_root_slip(&host).unwrap();
    let machine = EntityId::now();
    let device = SigningKey::from_bytes(&[73; 32]);
    let transport = TransportKey::derive(&device);
    let key = transport.endpoint_key();
    let link = vault.issue_pairing_link(&host, Scope::top(), 3600).unwrap();
    let device_key = device.verifying_key().to_bytes();
    let proof = device
        .sign(&pairing_binding_transcript(&link.code, &device_key, &machine.to_hex()).unwrap())
        .to_bytes();
    let pair = vault
        .redeem_pairing_link(&host, &link.code, &machine.to_hex(), device_key, &proof)
        .unwrap();
    let address = MachineAddress {
        endpoint_key: key,
        direct_addrs: vec![],
        relay_url: None,
    };
    let (device_proof, transport_proof) = transport.binding_proofs(&device, machine);
    vault
        .bind_mesh_machine(
            &host,
            machine,
            address,
            device_key,
            pair.claims.slip_id,
            [&device_proof, &transport_proof],
        )
        .unwrap();
    let grants = VaultMachineGrants(Arc::clone(&vault));
    let policy = AcceptPolicy {
        roster: Arc::new(VaultMachineRoster(Arc::clone(&vault))),
        grants: Arc::new(grants.clone()),
    };
    assert!(matches!(
        policy.inbound(key, b"mesh/test"),
        Err(MeshError::Refused)
    ));
    vault
        .set_mesh_alpn_grant(&host, machine, key, b"mesh/test", true)
        .unwrap();
    assert_eq!(policy.inbound(key, b"mesh/test").unwrap(), machine);
    assert!(!grants.permits(machine, key, b"mesh/other").unwrap());
    vault
        .set_mesh_alpn_grant(&host, machine, key, b"mesh/test", false)
        .unwrap();
    assert!(matches!(
        policy.inbound(key, b"mesh/test"),
        Err(MeshError::Refused)
    ));
}
