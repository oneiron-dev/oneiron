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
//! Red r3: the stub branch, where the replica refuses every binding the home serves. The tests
//! that need a binding to land fail (1, 2, 5, 6 and 7); the refusal and serving tests (3 and 4)
//! pass. Red r4: this head with the round-2 fixes of the pager, the importer and the grant check
//! undone. Tests 8, 9 and 10 fail; 1 to 7 pass.
use super::machine_identity::{Host, host, host_with, pair_and_bind, request_for};
use super::support::ed_key;
use super::*;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::{Vault, VaultConfig};

/// The ALPN `pair_and_bind` grants.
const GRANTED: &[u8] = b"mesh/sync";

/// A replica of `host`'s vault: a fresh install that took the home's signed authority history
/// and nothing else. It holds no host issuer, no MACHINE row and no binding.
fn replica(host: &Host) -> (tempfile::TempDir, Vault) {
    replica_with(host, VaultConfig::default())
}

/// [`replica`] over a vault opened with `config`.
fn replica_with(host: &Host, config: VaultConfig) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), config).unwrap();
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let history = host.vault.export_signed_authority_history().unwrap();
    vault.import_signed_authority_history(&history).unwrap();
    (dir, vault)
}

/// Every page of the home's bindings, as `residence.authority.mesh` serves them to a proven
/// machine of the owner's.
fn served(host: &Host) -> Vec<MeshAuthorityRow> {
    served_within(host, usize::MAX, usize::MAX).concat()
}

/// The pages of the home's bindings within `budget` base64 bytes each, a page's first row
/// within `lone`.
fn served_within(host: &Host, budget: usize, lone: usize) -> Vec<Vec<MeshAuthorityRow>> {
    let mut pages = Vec::new();
    let mut after = None;
    loop {
        let page = host
            .vault
            .mesh_authority_page_within(after, budget, lone)
            .unwrap();
        pages.push(page.rows);
        match page.next {
            Some(next) => after = Some(next),
            None => return pages,
        }
    }
}

/// The base64 bytes a page reply spends on `row`.
fn reply_bytes(row: &MeshAuthorityRow) -> usize {
    row.authority.len().div_ceil(3) * 4 + row.address.len().div_ceil(3) * 4
}

/// Gives `machine`'s MACHINE row on the home 200 direct addresses at `endpoint_key`, so its
/// address alone passes a page that fits every other row.
fn crowd(host: &Host, machine: EntityId, endpoint_key: [u8; 32]) {
    let crowded = MeshMachineAddress {
        endpoint_key,
        direct_addrs: (0..200u16)
            .map(|port| std::net::SocketAddr::from(([10, 0, 0, 1], 4000 + port)))
            .collect(),
        relay_url: None,
    };
    host.vault
        .put_entity(
            &machine,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            2,
            &rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(crowded)).unwrap(),
        )
        .unwrap();
}

/// How many direct addresses `vault`'s MACHINE row of `machine` holds.
fn direct_addrs(vault: &Vault, machine: EntityId) -> usize {
    vault
        .mesh_machine(machine)
        .unwrap()
        .map_or(0, |address| address.direct_addrs.len())
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

/// A row older than the one a replica holds never replaces it, so a replayed row from before a
/// rebind cannot bring its pairing back (review round 1 of #10536). Every write of a binding by
/// its host signs a higher revision.
#[test]
fn an_older_row_of_the_same_host_never_replaces_a_newer_one() {
    let host = host();
    let (machine, proven, endpoint_key) = bound_machine(&host, 81);
    let (_dir, replica) = replica(&host);
    let older = served(&host);
    replica.import_mesh_authority_rows(older.clone()).unwrap();

    host.vault
        .set_mesh_alpn_grant(&host.issuer, machine, endpoint_key, b"mesh/other", true)
        .unwrap();
    let newer = served(&host);
    assert_ne!(newer, older, "the home's write signed a new row");
    let import = replica.import_mesh_authority_rows(newer.clone()).unwrap();
    assert_eq!(import.written, BTreeSet::from([machine]), "{import:?}");

    let replay = replica.import_mesh_authority_rows(older).unwrap();
    assert_eq!(
        replay.refused,
        BTreeSet::from([machine]),
        "an older revision is refused: {replay:?}"
    );
    let again = replica.import_mesh_authority_rows(newer).unwrap();
    assert_eq!(
        again.held,
        BTreeSet::from([machine]),
        "the replica kept the newer row: {again:?}"
    );
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        proven
    );
}

/// An endpoint two MACHINE rows on the replica name refuses that binding alone; the rest of the
/// page lands (review round 1 of #10536).
#[test]
fn an_endpoint_two_machine_rows_name_refuses_that_row_alone() {
    let host = host();
    let (machine, _, endpoint_key) = bound_machine(&host, 83);
    let (other, other_proven, other_key) = bound_machine(&host, 85);
    let (_dir, replica) = replica(&host);
    let named = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(MeshMachineAddress {
        endpoint_key,
        direct_addrs: vec![],
        relay_url: None,
    }))
    .unwrap();
    for _ in 0..2 {
        replica
            .put_entity(
                &EntityId::now(),
                ENTITY_TYPE_MACHINE,
                TimeRange { start: 1, end: 1 },
                1,
                &named,
            )
            .unwrap();
    }

    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.refused, BTreeSet::from([machine]), "{import:?}");
    assert_eq!(import.written, BTreeSet::from([other]), "{import:?}");
    assert_eq!(
        replica.mesh_peer_machine(other_key, GRANTED).unwrap(),
        other_proven,
        "the unrelated binding on the same page landed"
    );
}

/// A row whose address alone passes the page's bytes is served without its direct addresses,
/// which the binding's signature does not cover, and the scan goes on past it (review round 1 of
/// #10536). The replica proves the machine on that row.
#[test]
fn a_row_past_the_page_bytes_is_served_bare_and_the_scan_goes_on() {
    let host = host();
    let (machine, proven, endpoint_key) = bound_machine(&host, 87);
    bound_machine(&host, 89);
    let budget = served(&host).iter().map(reply_bytes).max().unwrap() + 1;
    crowd(&host, machine, endpoint_key);
    assert!(
        served(&host)
            .iter()
            .any(|row| row.machine == machine && reply_bytes(row) > budget),
        "control: the crowded address alone passes the budget"
    );

    let pages = served_within(&host, budget, budget);
    assert_eq!(
        pages.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![1, 1],
        "each row in a page of its own, none left behind"
    );
    let row = pages
        .concat()
        .into_iter()
        .find(|row| row.machine == machine)
        .unwrap();
    assert!(reply_bytes(&row) <= budget, "served within the budget");
    assert!(row.bare, "served without its direct addresses");

    let (_dir, replica) = replica(&host);
    let import = replica.import_mesh_authority_rows(pages.concat()).unwrap();
    assert_eq!(import.written.len(), 2, "{import:?}");
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        proven,
        "the bare address proves the machine"
    );
}

/// A row past the page's bytes but within the lone row's is served whole, on a page of its own,
/// so a binding of many grants or addresses still syncs (review round 2 of #10536).
#[test]
fn a_row_past_the_page_bytes_is_served_whole_on_a_page_of_its_own() {
    let host = host();
    let (machine, proven, endpoint_key) = bound_machine(&host, 91);
    bound_machine(&host, 93);
    let budget = served(&host).iter().map(reply_bytes).max().unwrap() + 1;
    crowd(&host, machine, endpoint_key);

    let pages = served_within(&host, budget, usize::MAX);
    assert_eq!(
        pages.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![1, 1],
        "the crowded row alone on its page, none left behind"
    );
    let row = pages
        .concat()
        .into_iter()
        .find(|row| row.machine == machine)
        .unwrap();
    assert!(!row.bare, "served whole");
    assert!(reply_bytes(&row) > budget, "control: past the page's bytes");

    let (_dir, replica) = replica(&host);
    let import = replica.import_mesh_authority_rows(pages.concat()).unwrap();
    assert_eq!(import.written.len(), 2, "{import:?}");
    assert_eq!(
        direct_addrs(&replica, machine),
        200,
        "every direct address crossed"
    );
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        proven
    );
}

/// A bare row never takes the direct addresses a replica holds at that endpoint: they may be its
/// only route to the machine (review round 2 of #10536).
#[test]
fn a_bare_row_keeps_the_direct_addresses_the_replica_holds() {
    let host = host();
    let (machine, proven, endpoint_key) = bound_machine(&host, 95);
    bound_machine(&host, 97);
    let budget = served(&host).iter().map(reply_bytes).max().unwrap() + 1;
    crowd(&host, machine, endpoint_key);
    let (_dir, replica) = replica(&host);
    let whole = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(whole.written.len(), 2, "{whole:?}");
    assert_eq!(
        direct_addrs(&replica, machine),
        200,
        "control: the whole address crossed"
    );

    let pages = served_within(&host, budget, budget);
    assert!(
        pages
            .concat()
            .iter()
            .any(|row| row.machine == machine && row.bare),
        "control: the home serves that row bare now"
    );
    let import = replica.import_mesh_authority_rows(pages.concat()).unwrap();
    assert!(import.held.contains(&machine), "{import:?}");
    assert_eq!(
        direct_addrs(&replica, machine),
        200,
        "the route the replica held stays"
    );
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        proven
    );
}

/// A replica judges the home's grants as it judges their pairings: a grant's start is its
/// presence in the signed fold, and its end comes no later than the newest time a live owner
/// signed into it. A replica whose clock stood still while the home went on neither keeps a grant
/// the home expired nor refuses one the home has just minted (review round 2 of #10536, FIX
/// MESH-GRANT-REPLICA-CLOCK).
#[test]
fn a_replica_behind_the_home_judges_the_grants_on_the_signed_time() {
    const MINTED: u64 = 1_790_000_000;
    let clock = crate::ports::ManualClock::new(MINTED);
    let mut config = VaultConfig::default();
    config.store_clock = clock.bundle();
    let host = host_with(config);
    let (expiring, _, expiring_key) = bound_machine(&host, 101);
    // The owner's grant ceiling drops to an hour, and that machine's grant is minted again under
    // it: it now ends before the pairing it rides on.
    host.vault
        .set_setting(
            crate::setting::SettingCaller::Owner(&host.owner),
            crate::setting::SetSetting::vault_value(
                "mesh.grant.max_ttl_secs",
                serde_json::json!(3600),
            ),
        )
        .unwrap();
    host.vault
        .set_mesh_alpn_grant(&host.issuer, expiring, expiring_key, GRANTED, true)
        .unwrap();
    clock.set(MINTED + 7200);
    let (_, fresh, fresh_key) = bound_machine(&host, 103);
    assert_eq!(
        host.vault.mesh_peer_machine(expiring_key, GRANTED).unwrap(),
        PeerMachine::Unknown,
        "control: the home's grant expired"
    );

    let mut behind = VaultConfig::default();
    behind.store_clock = crate::ports::ManualClock::new(MINTED + 100).bundle();
    let (_dir, replica) = replica_with(&host, behind);
    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.written.len(), 2, "{import:?}");
    assert_eq!(
        replica.mesh_peer_machine(expiring_key, GRANTED).unwrap(),
        PeerMachine::Unknown,
        "the grant the home expired admits nothing here"
    );
    assert_eq!(
        replica.mesh_peer_machine(fresh_key, GRANTED).unwrap(),
        fresh,
        "the grant the home has just minted admits at once"
    );
}
