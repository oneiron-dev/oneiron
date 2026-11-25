//! MESH-AUTHORITY-REPLICATION (R6 P0, Engine 26 Nov 02:16): a replica that joined its home
//! proves the machines the owner bound on the home.
//!
//! A binding and the MACHINE address it binds are the home's own rows: no window carries them,
//! and a joined replica holds no host issuer to sign its own (FIX 10770). So a node on such a
//! replica proved no peer, however the owner bound and granted it on the home. The home now
//! serves each binding as signed, with its MACHINE address (`Vault::mesh_authority_page`, behind
//! `residence.authority.mesh`), and the replica imports it (`Vault::import_mesh_authority_rows`)
//! once a live owner host of its own fold signed it. The pairing, the grants and the machine's
//! proof key stay judged on the replica's fold.
//!
//! Each test's replica takes the home's signed authority history only, as a joined machine's
//! authority catch-up brings it, and no window.
//!
//! Red: the stub branch, where the replica refuses every binding the home serves: the first two
//! tests fail, and the refusal and serving tests pass.
use super::machine_identity::{Host, host, pair_and_bind, request_for};
use super::support::ed_key;
use super::*;
use crate::{Vault, VaultConfig};

/// The ALPN `pair_and_bind` grants.
const GRANTED: &[u8] = b"mesh/sync";

/// A replica of `host`'s vault: a fresh install that took the home's signed authority history
/// and nothing else. It holds no host issuer, no MACHINE row and no binding.
fn replica(host: &Host) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let history = host.vault.export_signed_authority_history().unwrap();
    vault.import_signed_authority_history(&history).unwrap();
    (dir, vault)
}

/// Every page of the home's bindings, as `residence.authority.mesh` serves them to a proven
/// machine of the owner's.
fn served(host: &Host) -> Vec<MeshAuthorityRow> {
    let mut rows = Vec::new();
    let mut after = None;
    loop {
        let page = host.vault.mesh_authority_page(after).unwrap();
        after = page.rows.last().map(|row| row.machine);
        rows.extend(page.rows);
        if !page.more {
            return rows;
        }
    }
}

/// A machine the owner paired, bound and granted on the home: its id, its proof as a node's
/// gate reads it, and its endpoint key.
fn bound_machine(host: &Host, seed: u8) -> (EntityId, PeerMachine, [u8; 32]) {
    let install_key = ed_key(seed);
    let machine = EntityId::now();
    let request = request_for(host.vault_id, machine, &install_key);
    let address = pair_and_bind(host, machine, &request, &install_key, &ed_key(seed + 1));
    let proven = PeerMachine::Proven {
        machine,
        key: request.machine_key,
    };
    assert_eq!(
        host.vault
            .mesh_peer_machine(address.endpoint_key, GRANTED)
            .unwrap(),
        proven,
        "control: the home proves the machine it bound"
    );
    (machine, proven, address.endpoint_key)
}

#[test]
fn a_replica_proves_the_machine_the_owner_bound_on_the_home() {
    let host = host();
    let (machine, proven, endpoint_key) = bound_machine(&host, 71);
    let (_dir, replica) = replica(&host);
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        PeerMachine::Unknown,
        "the authority history alone carries no binding and no MACHINE address"
    );

    let rows = served(&host);
    assert_eq!(
        rows.iter().map(|row| row.machine).collect::<Vec<_>>(),
        vec![machine],
        "the home serves the binding it holds"
    );
    let import = replica.import_mesh_authority_rows(rows.clone()).unwrap();
    assert_eq!(import.written, BTreeSet::from([machine]), "{import:?}");
    assert!(
        import.refused.is_empty() && import.held.is_empty(),
        "{import:?}"
    );
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        proven,
        "the replica proves the machine on the home's signed binding"
    );
    assert!(
        replica
            .mesh_grant_permits(machine, endpoint_key, GRANTED)
            .unwrap()
    );
    assert_eq!(
        replica
            .mesh_peer_machine(endpoint_key, b"mesh/other")
            .unwrap(),
        PeerMachine::Unknown,
        "only on the ALPN the owner granted"
    );

    let again = replica.import_mesh_authority_rows(rows).unwrap();
    assert_eq!(
        again.held,
        BTreeSet::from([machine]),
        "a second round finds it held: {again:?}"
    );
    assert!(again.written.is_empty() && again.refused.is_empty());
}

#[test]
fn a_revoke_on_the_home_crosses_and_an_older_row_never_undoes_it() {
    let host = host();
    let (machine, proven, endpoint_key) = bound_machine(&host, 73);
    let (_dir, replica) = replica(&host);
    let before = served(&host);
    replica.import_mesh_authority_rows(before.clone()).unwrap();
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        proven,
        "precondition: the replica proves the machine"
    );

    host.vault
        .revoke_mesh_machine(&host.issuer, machine)
        .unwrap();
    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.written, BTreeSet::from([machine]), "{import:?}");
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        PeerMachine::Unknown,
        "the revoked binding crossed"
    );
    assert!(replica.mesh_grant_withdrawn(machine, GRANTED).unwrap());

    // The row from before the revoke, served again before this replica folded the grant's
    // revoke, never makes the machine live again.
    let replay = replica.import_mesh_authority_rows(before).unwrap();
    assert_eq!(
        replay.refused,
        BTreeSet::from([machine]),
        "a revoked binding stays revoked: {replay:?}"
    );
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        PeerMachine::Unknown
    );
}

#[test]
fn a_forged_or_misplaced_row_never_lands() {
    let host = host();
    let (machine, _, endpoint_key) = bound_machine(&host, 75);
    let (other, _, _) = bound_machine(&host, 77);
    let (_dir, replica) = replica(&host);
    let rows = served(&host);
    let row = rows.iter().find(|row| row.machine == machine).unwrap();
    let other_row = rows.iter().find(|row| row.machine == other).unwrap();

    let mut forged = row.clone();
    *forged.authority.last_mut().unwrap() ^= 1;
    let mut misnamed = row.clone();
    misnamed.machine = EntityId::now();
    let mut readdressed = row.clone();
    readdressed.address = other_row.address.clone();
    for (case, bad) in [
        ("a signature that is not the host's", forged),
        ("a binding served under another MACHINE", misnamed),
        ("an address at another endpoint", readdressed),
    ] {
        let import = replica
            .import_mesh_authority_rows(vec![bad.clone()])
            .unwrap();
        assert_eq!(
            import.refused,
            BTreeSet::from([bad.machine]),
            "{case}: {import:?}"
        );
        assert!(import.written.is_empty(), "{case}");
    }
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        PeerMachine::Unknown,
        "nothing refused proves the machine"
    );
}

#[test]
fn the_home_serves_no_peer_that_proves_nothing() {
    let host = host();
    bound_machine(&host, 79);
    assert!(
        crate::sync::residence::mesh_authority_for(&host.vault, PeerMachine::Unknown, None)
            .is_err(),
        "an unproven peer is refused, as the authority tail refuses it"
    );
    assert_eq!(
        served(&host).len(),
        1,
        "control: the home holds the binding"
    );
}
