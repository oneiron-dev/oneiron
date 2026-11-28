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
//!
//! MESH-AUTHORITY-OWN-BINDING (R6 P0, Engine 26 Nov 12:35): the replica's own binding. The home
//! serves it like any other, but the importer skipped it whole, and nothing else on a joined
//! replica can write it, so a node there never proved its own job grant (`own_grant_ended`).
//! Tests 11 to 14 make the replica a machine of its own: a fresh install that minted its machine
//! identity, which the owner paired as "yours", bound and granted on the home. Red: the importer
//! skipping this install's own row again (main's behaviour); 11 to 14 fail, 1 to 10 pass.
//!
//! REVIEW-10537 P1: the importer read its own keys through `Vault::mesh_transport_seed`, which
//! loads them, and on a keystore slot found empty forgets this machine and mints a new one before
//! the import opens. Test 15 holds such a slot. Red: that read put back (the PR's first head,
//! a73d590d); 15 fails, 1 to 14 pass.
//!
//! REVIEW-10537 round 2 (P1=2). The import still read the keystore slot when no keys were loaded,
//! and on an Apple Secure Enclave keystore that `get` can make a sealing key and write its
//! selector; and an own row replaced any MACHINE body that was not a mesh address, one this
//! install wrote included. The own keys now come only from the signer loaded on the handle, and
//! the own MACHINE row is filled only when it is absent or holds the empty body enrolment writes.
//! Test 16 holds a `{"label":"local"}` body, test 17 the enrolment's empty row, test 18 a sealed
//! slot behind a keystore that counts each call, on a handle with no keys loaded. Red, one fix
//! undone at a time on this head: the MACHINE body rule (16 fails, the rest pass), and the slot
//! read (18 fails, the rest pass).
//!
//! MESH-GRANT-TEST10-HOME-CONTROL-RED: test 10 stepped only its test clock's wall, which moves no
//! lifetime (the authority clock follows a source's monotonic reading, and `ManualClock` gives
//! none), so its home still proved the grant the test meant to expire; and that grant ended with
//! its pairing, not before it. The test now moves the authority floor with the wall and ends the
//! grant half an hour before its pairing. Red, one rule of the grant check undone at a time on
//! this head: the end judged on the replica's own clock alone (10 fails at "the grant the home
//! expired admits nothing here", the rest pass), and the start judged on it again (10 fails at
//! "the grant the home has just minted admits at once", the rest pass).
//!
//! MESH-AUTHORITY-ROW-PARTS (review round 2 of #10536): a signed row past the bytes a page's
//! first row may take alone (24 MiB of base64, about 60,000 grants at the longest ALPN) was left
//! out of every page, so no replica proved that machine. The page now names it by reference and
//! the machine reads it in parts (`Vault::mesh_authority_part`), joins them and checks the length
//! and content hash (`MeshAuthorityRowJoin`). Test 19 sends a binding of 70,000 255-byte grants
//! across; test 20 refuses a row the home signed again after its page, and a reference past the
//! longest row a machine joins.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron_keystore::{DeviceKeystore, KeystoreLocality, KeystoreSlot, MemoryKeystore, SlotKind};

use super::machine_identity::{Host, host, host_with, pair_and_bind, request_for};
use super::support::ed_key;
use super::*;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::{Vault, VaultConfig};

/// The ALPN `pair_and_bind` grants.
const GRANTED: &[u8] = b"mesh/sync";

/// The job protocol an execution node proves its own grant on (`gpu_execution_node`'s
/// `authority_for`).
const JOB: &[u8] = b"oneiron/job/1";

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

/// The ALPN of the `n`th grant [`Vault::add_unminted_mesh_grants`] adds in test 19: 255 bytes,
/// the longest an ALPN may be.
fn longest_alpn(n: u32) -> Vec<u8> {
    format!("{n:0>255}").into_bytes()
}

/// The parts of the row `reference` names, read from `host` until it is whole: each part taken,
/// and how many there were.
fn join_parts(host: &Host, reference: &MeshAuthorityRowRef) -> (MeshAuthorityRowJoin, usize) {
    let mut join = MeshAuthorityRowJoin::start(reference.clone()).expect("a join starts");
    let mut parts = 0;
    while !join.is_whole() {
        let part = host
            .vault
            .mesh_authority_part(reference.machine, join.offset())
            .unwrap()
            .expect("the home serves the next part");
        assert!(join.take(part), "each part continues the row");
        parts += 1;
    }
    (join, parts)
}

/// 19. A binding of 70,000 grants at the longest ALPN passes the bytes a page's first row may
/// take alone, so the home names it by reference; the machine reads it in parts, the joined row
/// matches its length and content hash, and the replica proves the machine on it. The 69,999
/// grants beside the one `pair_and_bind` minted name ids no slip holds: the home signs them in one
/// write (minting each would sign a growing row 70,000 times), an import judges no grant, and a
/// read judges only the one it asks for.
#[test]
fn a_binding_of_seventy_thousand_grants_crosses_whole_in_parts() {
    let host = host();
    let (machine, proven, endpoint_key) = bound_machine(&host, 105);
    let (other, _, _) = bound_machine(&host, 107);
    host.vault
        .add_unminted_mesh_grants(
            &host.issuer,
            machine,
            (1..70_000u32).map(|n| (longest_alpn(n), [7; 32])),
        )
        .unwrap();

    let page = host.vault.mesh_authority_page(None).unwrap();
    assert_eq!(page.next, None, "one page serves both bindings");
    assert_eq!(
        page.rows.iter().map(|row| row.machine).collect::<Vec<_>>(),
        vec![other],
        "the small binding rides whole, as a machine older than the parts reads it"
    );
    let [reference] = page.parted.as_slice() else {
        panic!("one binding named by reference: {:?}", page.parted.len());
    };
    assert_eq!(reference.machine, machine);
    assert!(
        reference.total.div_ceil(3) * 4 > 24 * 1024 * 1024,
        "control: the signed row alone passes the lone row's bytes: {} bytes",
        reference.total
    );
    assert!(
        !reference.bare,
        "its address rides whole beside the reference"
    );

    let (join, parts) = join_parts(&host, reference);
    assert!(parts > 1, "control: the row came in {parts} parts");
    assert_eq!(
        host.vault
            .mesh_authority_part(machine, reference.total)
            .unwrap(),
        None,
        "nothing past its end"
    );
    let joined = join
        .finish()
        .expect("the joined row matches its length and content hash");

    let (_dir, replica) = replica(&host);
    let mut rows = page.rows.clone();
    rows.push(joined);
    rows.sort_by_key(|row| row.machine);
    let import = replica.import_mesh_authority_rows(rows).unwrap();
    assert_eq!(
        import.written,
        BTreeSet::from([machine, other]),
        "{import:?}"
    );
    assert_eq!(
        replica.mesh_peer_machine(endpoint_key, GRANTED).unwrap(),
        proven,
        "the replica proves the machine on the row that came in parts"
    );
}

/// 20. A row the home signs again between the page that named it and its parts never joins: its
/// parts carry another length, or other bytes under the length the page named. A part of a
/// shorter row is refused for its length even where its bytes fit. A reference past the longest
/// row a machine joins, or to an empty row, never starts a join.
#[test]
fn a_row_signed_again_after_its_page_or_past_the_cap_never_joins() {
    let host = host();
    let (machine, _, _) = bound_machine(&host, 109);
    let budget = reply_bytes(&served(&host)[0]) - 1;
    let page = host
        .vault
        .mesh_authority_page_within(None, budget, budget)
        .unwrap();
    assert!(
        page.rows.is_empty(),
        "control: past the bytes it may take whole"
    );
    let [reference] = page.parted.as_slice() else {
        panic!("one binding named by reference: {:?}", page.parted.len());
    };
    assert_eq!(
        MeshAuthorityRowRef::digest_from_text(&reference.digest_text()),
        Some(reference.digest),
        "the wire names the content hash and spells it back"
    );
    assert!(reference.digest_text().starts_with("blake3:"));
    let (join, _) = join_parts(&host, reference);
    assert!(
        join.finish().is_some(),
        "control: the row the page named joins"
    );
    let named_row_part = host.vault.mesh_authority_part(machine, 0).unwrap().unwrap();
    assert_eq!(
        named_row_part.total, reference.total,
        "control: the first part of the row the page named"
    );

    host.vault
        .add_unminted_mesh_grants(&host.issuer, machine, [(b"mesh/later".to_vec(), [9; 32])])
        .unwrap();
    let signed_again = host.vault.mesh_authority_part(machine, 0).unwrap().unwrap();
    assert_ne!(signed_again.total, reference.total, "control: the row grew");
    let mut join = MeshAuthorityRowJoin::start(reference.clone()).unwrap();
    assert!(
        !join.take(signed_again.clone()),
        "a part of another length does not continue the row"
    );
    let named_its_length = MeshAuthorityRowRef {
        total: signed_again.total,
        ..reference.clone()
    };
    // A part of the shorter row against a reference that names the longer one: its bytes fit
    // under that length, so only the length the part carries refuses it.
    assert!(
        named_row_part.total < named_its_length.total
            && named_row_part.part.len() as u64 <= named_its_length.total,
        "control: the shorter row's first part fits under the longer length"
    );
    let mut join = MeshAuthorityRowJoin::start(named_its_length.clone()).unwrap();
    assert!(
        !join.take(named_row_part),
        "a part of a shorter row does not continue a longer one"
    );
    let mut join = MeshAuthorityRowJoin::start(named_its_length).unwrap();
    assert!(join.take(signed_again), "control: the length matches");
    assert!(
        join.finish().is_none(),
        "bytes other than the ones the page named do not join"
    );

    for total in [0, MESH_AUTHORITY_ROW_MAX as u64 + 1] {
        let reference = MeshAuthorityRowRef {
            total,
            ..reference.clone()
        };
        assert!(
            MeshAuthorityRowJoin::start(reference).is_none(),
            "no join of a {total}-byte row"
        );
    }
}

/// A replica judges the home's grants as it judges their pairings: a grant's start is its
/// presence in the signed fold, and its end comes no later than the newest time a live owner
/// signed into it. A replica whose clock stood still while the home went on neither keeps a grant
/// the home expired nor refuses one the home has just minted (review round 2 of #10536, FIX
/// MESH-GRANT-REPLICA-CLOCK). The expired grant's pairing still stands, so the replica refuses
/// that grant for the grant's own end (FIX MESH-GRANT-TEST10-HOME-CONTROL-RED).
#[test]
fn a_replica_behind_the_home_judges_the_grants_on_the_signed_time() {
    const MINTED: u64 = 1_790_000_000;
    // The grant ceiling the owner sets: half the hour that `pair_and_bind`'s pairing runs.
    const CEILING: u64 = 1800;
    // The home's time once it has gone on: past the re-minted grant's end, before its pairing's.
    const LATER: u64 = MINTED + 2700;
    let clock = crate::ports::ManualClock::new(MINTED);
    let mut config = VaultConfig::default();
    config.store_clock = clock.bundle();
    let host = host_with(config);
    let (expiring, expiring_proven, expiring_key) = bound_machine(&host, 101);
    // The owner's grant ceiling drops to half an hour, and that machine's grant is minted again
    // under it: it now ends half an hour before the pairing it rides on.
    host.vault
        .set_setting(
            crate::setting::SettingCaller::Owner(&host.owner),
            crate::setting::SetSetting::vault_value(
                "mesh.grant.max_ttl_secs",
                serde_json::json!(CEILING),
            ),
        )
        .unwrap();
    host.vault
        .set_mesh_alpn_grant(&host.issuer, expiring, expiring_key, GRANTED, true)
        .unwrap();
    // The home's time goes on. Lifetimes run on the vault's authority clock, which a step of a
    // test clock's wall alone never moves (`ManualClock` gives no monotonic reading), so its
    // floor is moved with it, as a serving home's clock moves while it runs.
    clock.set(LATER);
    host.vault.advance_authority_clock_for_test(LATER).unwrap();
    assert!(
        host.vault.capability_slip_now().unwrap() >= LATER,
        "FIXTURE: the home's clock reads the later time"
    );
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
    assert!(
        replica.capability_slip_now().unwrap() < MINTED + CEILING,
        "FIXTURE: the replica's own clock still reads before the expired grant's end"
    );
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

    // The pairing the expired grant rode on still stands on the home at the later time: a grant
    // minted on it again admits there. The replica refused the expired grant for its own end.
    host.vault
        .set_mesh_alpn_grant(&host.issuer, expiring, expiring_key, GRANTED, true)
        .unwrap();
    assert_eq!(
        host.vault.mesh_peer_machine(expiring_key, GRANTED).unwrap(),
        expiring_proven,
        "control: the expired grant's pairing still stands on the home"
    );
}

/// A fresh install that is about to join a home: its vault with its machine identity minted, its
/// enrolment request, the machine key it pairs with and the transport key it serves its mesh
/// endpoint under, derived as its listener derives it.
struct JoiningInstall {
    _dir: tempfile::TempDir,
    vault: Vault,
    /// The keystore its vault holds its slots in.
    keystore: Arc<MemoryKeystore>,
    request: crate::authority::MachineEnrolmentRequest,
    machine_key: ed25519_dalek::SigningKey,
    transport: ed25519_dalek::SigningKey,
}

/// [`JoiningInstall`] for `host`'s vault.
fn joining_install(host: &Host) -> JoiningInstall {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let keystore = Arc::new(MemoryKeystore::new());
    vault.install_device_keystore(keystore.clone());
    vault.prepare_install_signing().expect("install signing");
    let encryption_key = vault.machine_encryption_key(host.vault_id).unwrap();
    let request = vault
        .machine_enrolment_request(host.vault_id, encryption_key)
        .unwrap();
    let machine_key = {
        let txn = vault.store.env.read_txn().unwrap();
        crate::identity::read_machine_signing_key_in_txn(&vault, &txn)
            .unwrap()
            .expect("the machine key the request signed with")
    };
    assert_eq!(machine_key.verifying_key().to_bytes(), request.machine_key);
    let (machine, seed) = vault
        .mesh_transport_seed()
        .unwrap()
        .expect("a transport seed");
    assert_eq!(machine, request.machine);
    JoiningInstall {
        _dir: dir,
        vault,
        keystore,
        request,
        machine_key,
        transport: ed25519_dalek::SigningKey::from_bytes(&seed),
    }
}

impl JoiningInstall {
    /// Its MACHINE id.
    fn machine(&self) -> EntityId {
        self.request.machine
    }

    /// The mesh endpoint key it serves under.
    fn endpoint_key(&self) -> [u8; 32] {
        self.transport.verifying_key().to_bytes()
    }

    /// Takes `host`'s signed authority history, as its first sync brings it, and no window.
    fn join(&self, host: &Host) {
        let history = host.vault.export_signed_authority_history().unwrap();
        self.vault
            .import_signed_authority_history(&history)
            .unwrap();
        assert_eq!(
            self.vault.local_machine().unwrap().map(|own| own.id),
            Some(self.machine()),
            "control: the replica is the machine the home paired"
        );
    }
}

/// The owner pairs `install` as "yours" on the home, binds it with `device_key` at `transport`'s
/// endpoint and grants it the job protocol there; `install` then joins.
fn pair_bind_and_join(
    host: &Host,
    install: &JoiningInstall,
    device_key: &ed25519_dalek::SigningKey,
    transport: &ed25519_dalek::SigningKey,
) -> MeshMachineAddress {
    let machine = install.machine();
    let address = pair_and_bind(host, machine, &install.request, device_key, transport);
    host.vault
        .set_mesh_alpn_grant(&host.issuer, machine, address.endpoint_key, JOB, true)
        .unwrap();
    install.join(host);
    address
}

/// What a replica holds of `machine`: its MACHINE address and how its endpoint proves on `JOB`.
fn holds(replica: &Vault, machine: EntityId, endpoint_key: [u8; 32]) -> (bool, PeerMachine) {
    (
        replica.mesh_machine(machine).unwrap().is_some(),
        replica.mesh_peer_machine(endpoint_key, JOB).unwrap(),
    )
}

/// A replica whose own MACHINE the owner paired, bound and granted on the home proves itself on
/// the job protocol after the import, as a node's own check reads it (`grant_live`: its own MACHINE
/// row's endpoint proves this machine).
#[test]
fn a_replica_proves_its_own_machine_on_the_binding_the_home_signed() {
    let host = host();
    let install = joining_install(&host);
    let machine = install.machine();
    let address = pair_bind_and_join(&host, &install, &install.machine_key, &install.transport);
    let proven = PeerMachine::Proven {
        machine,
        key: install.request.machine_key,
    };
    assert_eq!(
        host.vault
            .mesh_peer_machine(address.endpoint_key, JOB)
            .unwrap(),
        proven,
        "control: the home proves the machine it bound"
    );
    let replica = &install.vault;
    assert_eq!(
        holds(replica, machine, address.endpoint_key),
        (false, PeerMachine::Unknown),
        "control: the authority history alone carries no binding and no MACHINE address"
    );

    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.written, BTreeSet::from([machine]), "{import:?}");
    assert!(import.refused.is_empty(), "{import:?}");
    let own = replica
        .mesh_machine(machine)
        .unwrap()
        .expect("its own MACHINE address, which nothing else on a replica writes");
    assert_eq!(own.endpoint_key, install.endpoint_key());
    assert_eq!(
        replica.mesh_peer_machine(own.endpoint_key, JOB).unwrap(),
        proven,
        "the replica proves its own machine on the job protocol"
    );
    assert!(
        replica
            .mesh_grant_permits(machine, own.endpoint_key, JOB)
            .unwrap()
    );

    let again = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(
        again.held,
        BTreeSet::from([machine]),
        "a second round finds it held: {again:?}"
    );
}

/// A binding the home signed for this install's MACHINE at another endpoint than the one this
/// install serves under is refused, and changes nothing here.
#[test]
fn an_own_row_at_another_endpoint_is_refused_and_changes_nothing() {
    let host = host();
    let install = joining_install(&host);
    let machine = install.machine();
    let elsewhere = ed_key(111);
    let address = pair_bind_and_join(&host, &install, &install.machine_key, &elsewhere);
    assert_ne!(address.endpoint_key, install.endpoint_key());
    let replica = &install.vault;

    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.refused, BTreeSet::from([machine]), "{import:?}");
    assert!(
        import.written.is_empty() && import.held.is_empty(),
        "{import:?}"
    );
    for endpoint_key in [address.endpoint_key, install.endpoint_key()] {
        assert_eq!(
            holds(replica, machine, endpoint_key),
            (false, PeerMachine::Unknown),
            "nothing refused lands"
        );
    }
}

/// A binding the home signed for this install's MACHINE under another device key than this
/// install's machine key is refused, and changes nothing here.
#[test]
fn an_own_row_under_another_device_key_is_refused_and_changes_nothing() {
    let host = host();
    let install = joining_install(&host);
    let machine = install.machine();
    let stranger = ed_key(113);
    let address = pair_bind_and_join(&host, &install, &stranger, &install.transport);
    assert_eq!(address.endpoint_key, install.endpoint_key());
    let replica = &install.vault;

    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.refused, BTreeSet::from([machine]), "{import:?}");
    assert!(
        import.written.is_empty() && import.held.is_empty(),
        "{import:?}"
    );
    assert_eq!(
        holds(replica, machine, address.endpoint_key),
        (false, PeerMachine::Unknown),
        "nothing refused lands"
    );
}

/// The own binding lands beside a MACHINE address this install already holds for itself, and
/// never replaces it: that row is this install's own to write.
#[test]
fn an_own_address_the_replica_holds_is_never_replaced() {
    let host = host();
    let install = joining_install(&host);
    let machine = install.machine();
    pair_bind_and_join(&host, &install, &install.machine_key, &install.transport);
    let replica = &install.vault;
    let route = std::net::SocketAddr::from(([10, 0, 0, 9], 7000));
    let held = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(MeshMachineAddress {
        endpoint_key: install.endpoint_key(),
        direct_addrs: vec![route],
        relay_url: None,
    }))
    .unwrap();
    replica
        .put_entity(
            &machine,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            1,
            &held,
        )
        .unwrap();

    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.written, BTreeSet::from([machine]), "{import:?}");
    assert_eq!(
        replica
            .mesh_machine(machine)
            .unwrap()
            .map(|own| own.direct_addrs),
        Some(vec![route]),
        "the address this install wrote stays"
    );
    assert_eq!(
        replica
            .mesh_peer_machine(install.endpoint_key(), JOB)
            .unwrap(),
        PeerMachine::Proven {
            machine,
            key: install.request.machine_key,
        }
    );
}

/// An install whose keystore slot holds no seed for the machine its vault names (a lost keychain,
/// a raw copy), on a handle with no keys loaded: an import, of an empty page or of one that
/// carries its own binding, reads no slot and provisions nothing. It keeps its
/// machine id, its device key's public half, its pin and its choices, refuses its own binding
/// alone and takes every other row (REVIEW-10537 P1).
#[test]
fn an_import_with_an_empty_key_slot_keeps_this_install_and_refuses_its_own_row_alone() {
    let host = host();
    let (other, proven, other_endpoint) = bound_machine(&host, 81);
    let install = joining_install(&host);
    let machine = install.machine();
    let address = pair_bind_and_join(&host, &install, &install.machine_key, &install.transport);
    let replica = &install.vault;
    // A residence choice, which a machine forgotten here would lose with it.
    replica
        .sync_state_put("rs:mode", &[1, 0, 0, 0, 0, 0, 0, 0, 0])
        .unwrap();
    // A keystore with an empty slot: the keys loaded from the one before are dropped.
    replica.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let standing = |vault: &Vault| {
        let mode = vault.sync_state_get("rs:mode").unwrap();
        let txn = vault.store.env.read_txn().unwrap();
        (
            crate::identity::read_machine_id_in_txn(vault, &txn).unwrap(),
            crate::identity::read_device_verifying_key_in_txn(vault, &txn).unwrap(),
            crate::authority::read_pin_row_in_txn(&vault.store, &txn).unwrap(),
            crate::setting::live_install_rows_in(&vault.store, &txn).unwrap(),
            mode,
        )
    };
    let before = standing(replica);
    assert_eq!(
        before.0,
        Some(machine),
        "control: the vault names this install's machine"
    );
    assert!(
        before.1.is_some() && before.4.is_some(),
        "control: it holds its device key's public half and a residence mode"
    );

    let empty = replica.import_mesh_authority_rows(Vec::new()).unwrap();
    assert_eq!(empty, MeshAuthorityImport::default());
    assert_eq!(
        standing(replica),
        before,
        "an empty page changes nothing here"
    );

    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.written, BTreeSet::from([other]), "{import:?}");
    assert_eq!(import.refused, BTreeSet::from([machine]), "{import:?}");
    assert_eq!(
        standing(replica),
        before,
        "nor does a page that carries its own binding"
    );
    assert_eq!(
        replica.mesh_peer_machine(other_endpoint, GRANTED).unwrap(),
        proven,
        "every other row still lands"
    );
    assert_eq!(
        holds(replica, machine, address.endpoint_key),
        (false, PeerMachine::Unknown),
        "its own binding is refused alone"
    );
}

/// The stored body of `vault`'s MACHINE row of `machine`.
fn machine_body(vault: &Vault, machine: EntityId) -> Option<Vec<u8>> {
    let txn = vault.store.env.read_txn().unwrap();
    crate::ports::EntityStoreRead::port_entity_record(&vault.store, &txn, &machine)
        .unwrap()
        .map(|row| row.body)
}

/// A MACHINE row this install holds for itself whose body is no mesh address (here
/// `{"label":"local"}`, through the public MACHINE put) stays as it is: the own binding is refused
/// and nothing replaces that body (REVIEW-10537 round 2 P1).
#[test]
fn an_own_machine_body_that_is_no_mesh_address_stays_and_refuses_its_binding() {
    let host = host();
    let install = joining_install(&host);
    let machine = install.machine();
    let address = pair_bind_and_join(&host, &install, &install.machine_key, &install.transport);
    let replica = &install.vault;
    let local = rmp_serde::to_vec_named(&BTreeMap::from([("label", "local")])).unwrap();
    replica
        .put_entity(
            &machine,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            1,
            &local,
        )
        .unwrap();
    assert_eq!(
        machine_body(replica, machine),
        Some(local.clone()),
        "control: this install's MACHINE row holds the body it wrote"
    );

    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.refused, BTreeSet::from([machine]), "{import:?}");
    assert!(
        import.written.is_empty() && import.held.is_empty(),
        "{import:?}"
    );
    assert_eq!(
        machine_body(replica, machine),
        Some(local),
        "the body this install wrote stays"
    );
    assert_eq!(
        holds(replica, machine, address.endpoint_key),
        (false, PeerMachine::Unknown),
        "nothing refused lands"
    );
}

/// The empty MACHINE row enrolment writes for this install (`EMPTY_MACHINE_BODY`) takes its own
/// address, and the replica proves itself on the job protocol, as with no row at all.
#[test]
fn the_empty_row_enrolment_wrote_takes_the_own_address() {
    let host = host();
    let install = joining_install(&host);
    let machine = install.machine();
    pair_bind_and_join(&host, &install, &install.machine_key, &install.transport);
    let replica = &install.vault;
    let mut txn = replica.store.env.write_txn().unwrap();
    replica
        .ensure_machine_row_in_txn(&mut txn, machine)
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(
        machine_body(replica, machine),
        Some(crate::authority::machine_identity::EMPTY_MACHINE_BODY.to_vec()),
        "control: this install's MACHINE row is the empty one enrolment writes"
    );

    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(import.written, BTreeSet::from([machine]), "{import:?}");
    assert_eq!(
        replica
            .mesh_machine(machine)
            .unwrap()
            .map(|own| own.endpoint_key),
        Some(install.endpoint_key()),
        "the served address fills the empty row"
    );
    assert_eq!(
        replica
            .mesh_peer_machine(install.endpoint_key(), JOB)
            .unwrap(),
        PeerMachine::Proven {
            machine,
            key: install.request.machine_key,
        }
    );
}

/// A keystore over `inner` that counts every call that reaches a slot. On an Apple Secure
/// Enclave keystore a `get` can make a sealing key and write its selector, so an import that must
/// read no slot makes none of these calls.
struct CountingKeystore {
    inner: Arc<MemoryKeystore>,
    calls: AtomicUsize,
}

impl CountingKeystore {
    fn call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl DeviceKeystore for CountingKeystore {
    fn get(
        &self,
        slot: &KeystoreSlot,
    ) -> oneiron_keystore::Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
        self.call();
        self.inner.get(slot)
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<()> {
        self.call();
        self.inner.create(slot, secret)
    }

    fn delete(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<()> {
        self.call();
        self.inner.delete(slot)
    }

    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<bool> {
        self.call();
        self.inner.replace(slot, secret)
    }

    fn locality(&self) -> KeystoreLocality {
        self.inner.locality()
    }
}

/// An install whose keystore slot holds its sealed seed, on a handle with no keys loaded (as
/// after a restart, before its keystore loads them): an import of a page that carries its own
/// binding makes no keystore call at all, so no enclave key or selector can be made. It refuses
/// its own binding alone, takes every other row, and keeps the slot, its machine id and its
/// device key's public half, with no keys loaded (REVIEW-10537 round 2 P1; Engine 13:09: the own
/// keys come only from the signer already loaded).
#[test]
fn an_import_on_a_handle_with_no_keys_loaded_reads_no_slot_and_refuses_its_own_row_alone() {
    let host = host();
    let (other, proven, other_endpoint) = bound_machine(&host, 91);
    let install = joining_install(&host);
    let machine = install.machine();
    let address = pair_bind_and_join(&host, &install, &install.machine_key, &install.transport);
    let replica = &install.vault;
    let slot = KeystoreSlot {
        vault_id: *replica.vault_id().as_bytes(),
        install: *machine.as_bytes(),
        kind: SlotKind::DeviceSigning,
    };
    let sealed = install.keystore.get(&slot).unwrap().map(|seed| *seed);
    assert!(
        sealed.is_some(),
        "control: the slot holds this install's sealed seed"
    );
    // The same slots behind a keystore that counts each call. Installing it drops the keys loaded
    // on the handle.
    let counting = Arc::new(CountingKeystore {
        inner: install.keystore.clone(),
        calls: AtomicUsize::new(0),
    });
    replica.install_device_keystore(counting.clone());
    assert!(
        replica.loaded_install_signer().is_none(),
        "control: no keys loaded"
    );
    let identity = |vault: &Vault| {
        let txn = vault.store.env.read_txn().unwrap();
        (
            crate::identity::read_machine_id_in_txn(vault, &txn).unwrap(),
            crate::identity::read_device_verifying_key_in_txn(vault, &txn).unwrap(),
        )
    };
    let before = identity(replica);

    let import = replica.import_mesh_authority_rows(served(&host)).unwrap();
    assert_eq!(
        counting.calls.load(Ordering::SeqCst),
        0,
        "the import reads no slot"
    );
    assert_eq!(import.written, BTreeSet::from([other]), "{import:?}");
    assert_eq!(import.refused, BTreeSet::from([machine]), "{import:?}");
    assert_eq!(
        install.keystore.get(&slot).unwrap().map(|seed| *seed),
        sealed,
        "the slot stays"
    );
    assert_eq!(identity(replica), before, "the identity stays");
    assert!(
        replica.loaded_install_signer().is_none(),
        "nothing loads its keys"
    );
    assert_eq!(
        replica.mesh_peer_machine(other_endpoint, GRANTED).unwrap(),
        proven,
        "every other row still lands"
    );
    assert_eq!(
        holds(replica, machine, address.endpoint_key),
        (false, PeerMachine::Unknown),
        "its own binding is refused alone"
    );
}
