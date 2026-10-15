//! Honest rows of one machine arrive in any order (Astra #1422b F1). A key
//! record keeps a sequence scope of its own, apart from its world's settings
//! edits, and a machine's key records of a world each name its previous one.
//! So a receiver that stores a later row first still admits every earlier
//! one, and the kit still reaches the world's only key.
use super::machine_identity::{Host, host};
use super::world_chain_reads::hash;
use super::world_key_doors::{Fresh, enrol_own, fresh_install, keyed_machine, kit_seed, set};
use super::world_privacy::{settings, stored_entries, world_row};
use super::*;
use crate::world_keys::RecoveryRootSeed;
use crate::{Vault, VaultConfig};

const HERE: EditOrigin = EditOrigin::ThisMachine;
const AT: TimeRange = TimeRange { start: 3, end: 3 };

/// A host with this install's machine and an owner root, the root's kit
/// seed, and a world with a live WORLD row and no settings edit yet.
fn rooted() -> (Host, RecoveryRootSeed, EntityId) {
    let host = host();
    enrol_own(&host);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let seed = kit_seed(host.vault_id, prepared.seed());
    host.vault
        .activate_owner_root(&host.owner, HERE, prepared, &BTreeSet::new())
        .unwrap();
    let world = world_row(&host);
    (host, seed, world)
}

/// An ordinary settings edit that keeps the world on the owner's machines.
fn keep_mine(host: &Host, world: EntityId) {
    let edit = WorldPrivacy {
        sealed: SealedCopies::MyMachines,
        ..settings(ReadLocation::MyMachines)
    };
    host.vault
        .set_world_privacy_as(&host.owner, HERE, world, edit)
        .unwrap();
}

fn in_world(entry: &AuthorityLogEntry, world: EntityId) -> bool {
    match &entry.op {
        AuthorityOp::WorldPrivacy(edit) => edit.world == world,
        AuthorityOp::WorldKeyWraps(record) => record.key.world == world,
        _ => false,
    }
}

/// The world's settings edits and key records, in the order they were signed,
/// each marked true for a key record.
fn world_rows(vault: &Vault, world: EntityId) -> Vec<(AuthorityLogEntry, bool)> {
    let mut rows: Vec<_> = stored_entries(vault)
        .into_iter()
        .filter(|entry| in_world(entry, world))
        .map(|entry| {
            let record = matches!(entry.op, AuthorityOp::WorldKeyWraps(_));
            (entry, record)
        })
        .collect();
    rows.sort_by_key(|(entry, _)| entry.seq);
    rows
}

/// Astra #1422b F1, the named sequence. Machine A makes the world
/// `MyMachines` (E1; the door mints K and wraps it to A and the root in K2),
/// then edits its settings again (E3). A receiver stores E1, then E3, then
/// K2. A is lost; a fresh install restores the root from the kit, recovers K
/// and opens the world with it. Fails before: K2 shared E3's sequence scope,
/// so the receiver refused it as a rollback and the kit never saw K.
#[test]
fn a_key_record_that_arrives_after_a_later_edit_still_restores_from_the_kit() {
    let (host, seed, world) = rooted();
    let Fresh {
        _backups,
        vault: fresh,
        owner,
        ..
    } = fresh_install(&host);
    set(&host, world, ReadLocation::MyMachines);
    keep_mine(&host, world);
    let key = host
        .vault
        .authority_fold()
        .unwrap()
        .current_world_key(world)
        .unwrap()
        .id;
    let rows = world_rows(&host.vault, world);
    let kinds: Vec<_> = rows.iter().map(|(_, record)| *record).collect();
    assert_eq!(kinds, [false, true, false]);
    drop(host);

    for (row, _) in [&rows[0], &rows[2], &rows[1]] {
        fresh.put_authority_log_entry(row, AT, 3).unwrap();
    }
    let restore = fresh.restore_world_keys(&owner, HERE, &seed, None).unwrap();
    assert_eq!(restore.usable, vec![key]);
    assert_eq!(fresh.world_key(world).unwrap().id(), &key);
}

/// The Engine's table over the rows one machine signs in one world: its
/// settings edits and its key records. A signs E1 (the door mints K, in
/// record K2), then E3, then, once machine B joins, K3 (K's wrap to B). For
/// every ordered pair, a receiver that stores the later row first, then the
/// earlier one, then the rest in order, admits all four. Fails before: K2
/// was refused whenever E3 or K3 arrived first.
#[test]
fn every_arrival_order_of_one_machines_world_rows_keeps_each_row() {
    let (host, _, world) = rooted();
    let history = host.vault.export_signed_authority_history().unwrap();
    let known: BTreeSet<_> = stored_entries(&host.vault).iter().map(hash).collect();
    set(&host, world, ReadLocation::MyMachines);
    keep_mine(&host, world);
    keyed_machine(&host, 171);
    host.vault.ensure_world_key(&host.owner, world).unwrap();
    let rows = world_rows(&host.vault, world);
    let kinds: Vec<_> = rows.iter().map(|(_, record)| *record).collect();
    assert_eq!(kinds, [false, true, false, true]);
    // B's mark and the other main-log rows since the export.
    let main: Vec<_> = stored_entries(&host.vault)
        .into_iter()
        .filter(|entry| !in_world(entry, world) && !known.contains(&hash(entry)))
        .map(|entry| (entry, AT, 3))
        .collect();

    for later in 1..rows.len() {
        for earlier in 0..later {
            let dir = tempfile::tempdir().unwrap();
            let receiver = Vault::open(dir.path(), VaultConfig::default()).unwrap();
            receiver.import_signed_authority_history(&history).unwrap();
            receiver.put_authority_log_entries(&main).unwrap();
            let rest = (0..rows.len()).filter(|at| *at != earlier && *at != later);
            for at in [later, earlier].into_iter().chain(rest) {
                receiver
                    .put_authority_log_entry(&rows[at].0, AT, 3)
                    .unwrap();
            }
            let fold = receiver.authority_fold().unwrap();
            for (at, (row, _)) in rows.iter().enumerate() {
                assert!(
                    fold.valid_entries.contains(&hash(row)),
                    "row {at} lost when row {later} arrived before row {earlier}"
                );
            }
        }
    }
}
