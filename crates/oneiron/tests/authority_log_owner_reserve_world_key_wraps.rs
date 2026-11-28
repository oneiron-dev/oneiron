//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, part 2c: the key records
//! the vault owner's own work writes carry the owner key's proof. Past its
//! owner reserve, install B lands only the owner's work
//! (`authority/log_budget.rs` `owner_work`), and a key record install A
//! carries reaches B signed by A's install key. Since #9892 the fold takes
//! one owner key's proof beside that signature on a key record; here the
//! wrap writer signs it when the owner made the work in person (the owner's
//! settings edit, part 2b's witness, or the owner's ensure of a world's key),
//! on each record whose own parents' state takes the owner key
//! (`Vault::owner_proof_taken_at_in_txn`).
//!
//! Each test marks A the owner's own machine, so A reads the world and mints
//! its first key, takes A's history to a second install B, floods B until
//! its door holds a row at the reserve (`owner_reserve/two_installs.rs`),
//! then the owner's work on A writes the key, and B imports every row A
//! wrote since.
//!
//! Red at the base (#9910 head faf042c8, the edit carries its proof, the key
//! records none): A's key records carry no cosign, and B's import refuses
//! with `AuthorityLogFull`. The control, the same edit from an A that holds
//! no owner key, waits at B.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_world_key_wraps`.

use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityLogEntry, AuthorityOp, KeyWork, MachineOwnership,
    MachineRole, ReadLocation, WorldPrivacy, authority_entry_hash,
};
use oneiron::world_keys::WorldKeyStatus;
use oneiron::{EntityId, ErrorKind};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    Rooted, Second, admit_flooder, hold_owner_key, rooted, second_install_at_its_reserve,
    written_since,
};

/// A's own machine.
fn machine_of_a(rooted: &Rooted) -> EntityId {
    rooted
        .vault
        .local_machine()
        .expect("FIXTURE: A's machine")
        .expect("FIXTURE: A has a machine")
        .id
}

/// The owner marks A the owner's own machine, so A reads the worlds the
/// owner's machines read and holds their keys.
fn owner_marks_a_yours(rooted: &Rooted) {
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            machine_of_a(rooted),
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("FIXTURE: the owner marks A yours");
}

/// A world the owner creates on A, read everywhere until an edit narrows it.
fn world_on_a(rooted: &Rooted) -> EntityId {
    rooted
        .vault
        .create_world(
            &rooted.proof,
            "Owner reserve key world",
            rooted.vault.now_recorded_at(),
        )
        .expect("FIXTURE: the owner creates a world on A")
}

/// The owner narrows `world` to `read` on A, at the owner's own settings
/// door, and A's key work after it.
fn owner_narrows_on_a(rooted: &Rooted, world: EntityId, read: ReadLocation) -> KeyWork {
    rooted
        .vault
        .set_world_privacy_as(
            &rooted.proof,
            ActSurface::ThisInstall,
            world,
            WorldPrivacy {
                read,
                ..WorldPrivacy::default()
            },
            None,
        )
        .expect("the owner narrows the world on A")
        .key_work
}

/// The rows A stored since B took its history, and the key records among
/// them with their hashes.
fn the_rows_a_wrote(
    rooted: &Rooted,
    second: &Second,
) -> (Vec<Vec<u8>>, Vec<(AuthorityLogEntry, AuthorityEntryHash)>) {
    let written = written_since(rooted, second);
    let rows = written.iter().map(|(row, _)| row.clone()).collect();
    let records: Vec<(AuthorityLogEntry, AuthorityEntryHash)> = written
        .into_iter()
        .filter(|(_, entry)| matches!(entry.op, AuthorityOp::WorldKeyWraps(_)))
        .map(|(_, entry)| {
            let hash = authority_entry_hash(&entry).expect("hash");
            (entry, hash)
        })
        .collect();
    assert!(!records.is_empty(), "A wrote the world's key records");
    (rows, records)
}

/// B imports `rows` and counts each of `records`, which A signed with one
/// owner key's proof beside its install key, and B's current key of `world`
/// is A's.
fn b_lands_the_proven_key_records(
    rooted: &Rooted,
    second: &Second,
    rows: &[Vec<u8>],
    records: &[(AuthorityLogEntry, AuthorityEntryHash)],
    world: EntityId,
) {
    for (record, _) in records {
        assert_eq!(
            record.cosigns.len(),
            1,
            "A signed each key record with one owner key's proof beside its install key"
        );
        assert_ne!(
            record.cosigns[0].public_key, record.signer.public_key,
            "the proof is not A's install key"
        );
    }
    second
        .vault
        .import_signed_authority_history(rows, &std::collections::BTreeMap::new())
        .expect("B lands the key records A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    for (_, hash) in records {
        assert!(
            fold.valid_entries.contains(hash),
            "B's fold counts each key record"
        );
    }
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
    let at_a = rooted.vault.authority_fold().expect("A's fold");
    let commitment_at_a = at_a
        .current_world_key(world)
        .map(|key| key.commitment)
        .expect("A holds the world's key");
    let at_b = fold
        .current_world_key(world)
        .expect("B counts the world's key");
    assert_eq!(at_b.commitment, commitment_at_a, "B's key is A's");
    assert!(!at_b.wraps.is_empty(), "B counts the key's wraps");
}

/// The owner narrows a world to A on A, where A holds an owner key: A mints
/// the world's key in the edit's commit, its key records carry the edit's
/// proof, and B, past its owner reserve, lands the edit and the records.
#[test]
fn the_owners_world_edit_key_records_another_install_proves_land_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    owner_marks_a_yours(&rooted);
    let flooder = admit_flooder(&rooted);
    let world = world_on_a(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let key_work = owner_narrows_on_a(
        &rooted,
        world,
        ReadLocation::OneMachine(machine_of_a(&rooted)),
    );
    assert_eq!(
        key_work,
        KeyWork::Enacted,
        "FIXTURE: A minted and wrapped the world's key in the edit's commit"
    );
    let (rows, records) = the_rows_a_wrote(&rooted, &second);
    b_lands_the_proven_key_records(&rooted, &second, &rows, &records, world);
}

/// The same edit from an A that holds no owner key: A carries the edit and
/// its key records unproven, and they wait at B's door (`AuthorityLogFull`),
/// as before.
#[test]
fn the_owners_world_edit_key_records_carried_unproven_wait_past_this_installs_reserve() {
    let rooted = rooted();
    owner_marks_a_yours(&rooted);
    let flooder = admit_flooder(&rooted);
    let world = world_on_a(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let key_work = owner_narrows_on_a(
        &rooted,
        world,
        ReadLocation::OneMachine(machine_of_a(&rooted)),
    );
    assert_eq!(
        key_work,
        KeyWork::Enacted,
        "FIXTURE: A minted and wrapped the world's key in the edit's commit"
    );
    let (rows, records) = the_rows_a_wrote(&rooted, &second);
    assert!(
        records.iter().all(|(record, _)| record.cosigns.is_empty()),
        "A holds no owner key, so it carries the key records unproven"
    );
    let import = second
        .vault
        .import_signed_authority_history(&rows, &std::collections::BTreeMap::new());
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven key records at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        records
            .iter()
            .all(|(_, hash)| !fold.valid_entries.contains(hash)),
        "B counts none of them"
    );
}

/// The owner narrowed a world to the owner's machines on A before A was the
/// owner's, so no key was minted; B took that history. The owner then asks
/// A, now the owner's own machine and holding an owner key, to ensure the
/// world's key: A mints it, its key records carry the owner's proof, and B,
/// past its owner reserve, lands them.
#[test]
fn the_owners_ensured_world_key_records_another_install_proves_land_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let world = world_on_a(&rooted);
    let key_work = owner_narrows_on_a(&rooted, world, ReadLocation::MyMachines);
    assert_ne!(
        key_work,
        KeyWork::Enacted,
        "FIXTURE: A, not yet the owner's, minted no key in the edit's commit"
    );
    owner_marks_a_yours(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let status = rooted
        .vault
        .ensure_world_key(&rooted.proof, world)
        .expect("the owner ensures the world's key on A");
    assert!(
        matches!(status, WorldKeyStatus::Minted(_)),
        "FIXTURE: A minted the world's first key: {status:?}"
    );
    let (rows, records) = the_rows_a_wrote(&rooted, &second);
    b_lands_the_proven_key_records(&rooted, &second, &rows, &records, world);
}
