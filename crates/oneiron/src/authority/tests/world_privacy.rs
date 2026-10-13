//! World privacy P2 acceptance: a world's settings change only through the
//! owner's door, on a machine the owner marked "yours" that holds the world.
//! Concurrent edits fold stricter in every order, and no forged entry, generic
//! write, replayed edit, restore or machine that lost "yours" widens a world.
use super::machine_identity::{Host, encryption_key, host, request_for};
use super::support::{authority_key_from_ed, ed_key, sign_ed, unsigned_entry};
use super::*;
use crate::registry::ENTITY_TYPE_WORLD;
use crate::{Vault, VaultConfig};

pub(super) fn world_row(host: &Host) -> EntityId {
    let world = EntityId::now();
    host.vault
        .put_entity(
            &world,
            ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    world
}

/// Enrols this install as one of the owner's machines.
pub(super) fn enrol_here(host: &Host) -> EntityId {
    let request = host
        .vault
        .machine_enrolment_request(host.vault_id, encryption_key())
        .unwrap();
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    request.machine
}

/// Another machine of the owner's answer `role`, whose install key the test holds.
pub(super) fn other_machine(host: &Host, seed: u8, role: MachineRole) -> (EntityId, SigningKey) {
    let key = ed_key(seed);
    let machine = EntityId::now();
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request_for(host.vault_id, machine, &key),
            role,
        )
        .unwrap();
    (machine, key)
}

pub(super) fn settings(read: ReadLocation) -> WorldPrivacy {
    WorldPrivacy {
        read,
        ..WorldPrivacy::default()
    }
}

pub(super) fn set(
    host: &Host,
    origin: EditOrigin,
    world: EntityId,
    read: ReadLocation,
) -> crate::error::Result<()> {
    host.vault
        .set_world_privacy_as(&host.owner, origin, world, settings(read))
        .map(|_| ())
}

/// An edit `key` signs as `machine`, on the host's main-log heads and the
/// world's side heads: what that machine's own door would sign.
pub(super) fn edit_by(
    host: &Host,
    machine: EntityId,
    key: &SigningKey,
    world: EntityId,
    settings: WorldPrivacy,
) -> AuthorityLogEntry {
    let fold = host.vault.authority_fold().unwrap();
    let signer = authority_key_from_ed(key);
    let seq = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
    let mut parents = fold.append_heads.clone();
    if let Some(side) = fold.side_heads.get(&world) {
        parents.extend(side.iter().copied());
    }
    sign_ed(
        unsigned_entry(
            fold.vault_id,
            seq,
            parents.into_iter().collect(),
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                owner: host.owner.actor(),
                machine,
                settings,
            }),
            signer,
            2,
        ),
        key,
    )
}

pub(super) fn land(host: &Host, entries: &[AuthorityLogEntry]) {
    let at = TimeRange { start: 2, end: 2 };
    let rows: Vec<_> = entries.iter().map(|entry| (entry.clone(), at, 2)).collect();
    host.vault.put_authority_log_entries(&rows).unwrap();
}

pub(super) fn read_of(host: &Host, world: EntityId) -> EffectiveRead {
    host.vault.world_privacy(world).unwrap().read
}

pub(super) fn stored_entries(vault: &Vault) -> Vec<AuthorityLogEntry> {
    let txn = vault.store.env.read_txn().unwrap();
    authority_log_rows_in_txn(&vault.store, &txn)
        .unwrap()
        .into_iter()
        .map(|(_, body)| decode_authority_log_entry_body(&body).unwrap())
        .collect()
}

#[test]
fn only_the_owner_on_a_machine_holding_the_world_changes_it() {
    let host = host();
    let world = world_row(&host);
    // Not yet one of the owner's machines: nothing here may edit.
    assert!(
        set(
            &host,
            EditOrigin::ThisMachine,
            world,
            ReadLocation::MyMachines
        )
        .is_err()
    );
    let here = enrol_here(&host);
    let (other, other_key) = other_machine(&host, 61, MachineRole::Owned(MachineOwnership::Yours));
    let (rented, _) = other_machine(&host, 62, MachineRole::Owned(MachineOwnership::Rented));

    // A request from elsewhere never changes a world's settings, a proven
    // machine of the owner's included; only this machine speaks for itself.
    for origin in [
        EditOrigin::Peer(PeerMachine::Unknown),
        EditOrigin::Peer(PeerMachine::Proven(other)),
    ] {
        assert!(set(&host, origin, world, ReadLocation::Everywhere).is_err());
    }
    // A one-machine world lives only on one of the owner's machines, and
    // base reality has no settings.
    assert!(
        set(
            &host,
            EditOrigin::ThisMachine,
            world,
            ReadLocation::OneMachine(rented)
        )
        .is_err()
    );
    assert!(
        set(
            &host,
            EditOrigin::ThisMachine,
            crate::claim::base_world_id(),
            ReadLocation::OneMachine(here),
        )
        .is_err()
    );
    assert!(host.vault.world_privacy_change_log().unwrap().is_empty());

    let receipt = host
        .vault
        .set_world_privacy_as(
            &host.owner,
            EditOrigin::Peer(PeerMachine::Proven(here)),
            world,
            settings(ReadLocation::OneMachine(here)),
        )
        .unwrap();
    assert_eq!(receipt.previous.read, EffectiveRead::Everywhere);
    assert_eq!(receipt.next.read, EffectiveRead::OneMachine(here));
    assert_eq!(
        (receipt.world.as_str(), receipt.machine.as_str()),
        (world.to_hex().as_str(), here.to_hex().as_str())
    );
    assert_eq!(
        host.vault.world_privacy_change_log().unwrap(),
        vec![receipt]
    );
    let fold = host.vault.authority_fold().unwrap();
    assert!(fold.world_readable_on(world, Destination::Machine(here)));
    for destination in [Destination::Machine(other), Destination::Unknown] {
        assert!(!fold.world_readable_on(world, destination));
    }

    // Another of the owner's machines does not hold the world now. Its
    // well-signed widen (from home, or the cloud) is valid and has no effect.
    let widen = edit_by(
        &host,
        other,
        &other_key,
        world,
        settings(ReadLocation::Everywhere),
    );
    land(&host, &[widen.clone()]);
    let fold = host.vault.authority_fold().unwrap();
    assert!(
        fold.refused_world_edits
            .contains(&authority_entry_hash(&widen).unwrap())
    );
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(here));
}

#[test]
fn no_agent_writer_root_or_borrowed_key_signs_a_settings_edit() {
    let host = host();
    let world = world_row(&host);
    let (mine, mine_key) = other_machine(&host, 63, MachineRole::Owned(MachineOwnership::Yours));
    let (work, work_key) =
        other_machine(&host, 64, MachineRole::Owned(MachineOwnership::WorkSchool));
    let narrow = edit_by(
        &host,
        mine,
        &mine_key,
        world,
        settings(ReadLocation::OneMachine(mine)),
    );
    land(&host, &[narrow]);

    let writer = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    host.vault
        .put_entity(
            &writer,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            1,
            b"writer",
        )
        .unwrap();
    let writer_key = ed_key(65);
    host.vault
        .enroll_machine_identity(
            &host.issuer,
            writer,
            writer_key.verifying_key().to_bytes(),
            [9; 32],
            |transcript| Ok(writer_key.sign(transcript).to_bytes()),
        )
        .unwrap();
    let widen = settings(ReadLocation::Everywhere);
    let forged = [
        // An engine writer's agent key, naming the owner's machine.
        edit_by(&host, mine, &writer_key, world, widen.clone()),
        // A work machine's own key: not one of the owner's.
        edit_by(&host, work, &work_key, world, widen.clone()),
        // A key that is no machine's at all.
        edit_by(&host, mine, &ed_key(66), world, widen.clone()),
    ];
    land(&host, &forged);
    // The host root is the owner's roster key, not a machine.
    let fold = host.vault.authority_fold().unwrap();
    let root_edit = host
        .issuer
        .sign_entry(
            fold.vault_id,
            fold.append_sequences[&host.issuer.public_key()] + 1,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                owner: host.owner.actor(),
                machine: mine,
                settings: widen,
            }),
            2,
        )
        .unwrap();
    land(&host, &[root_edit.clone()]);

    let fold = host.vault.authority_fold().unwrap();
    for entry in forged.iter().chain([&root_edit]) {
        assert!(
            !fold
                .valid_entries
                .contains(&authority_entry_hash(entry).unwrap())
        );
    }
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(mine));

    // The WORLD body carries no settings: rewriting it changes nothing.
    host.vault
        .put_entity(
            &world,
            ENTITY_TYPE_WORLD,
            at,
            3,
            br#"{"read":"everywhere","sealed":"cloud_and_my_machines"}"#,
        )
        .unwrap();
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(mine));
}

#[test]
fn concurrent_edits_fold_stricter_in_both_orders() {
    let host = host();
    let world = world_row(&host);
    let (b, b_key) = other_machine(&host, 67, MachineRole::Owned(MachineOwnership::Yours));
    let (c, c_key) = other_machine(&host, 68, MachineRole::Owned(MachineOwnership::Yours));
    let (d, d_key) = other_machine(&host, 69, MachineRole::Owned(MachineOwnership::Yours));
    let base = stored_entries(&host.vault);

    // Neither saw the other: each built on the same heads.
    let pick_b = edit_by(
        &host,
        b,
        &b_key,
        world,
        WorldPrivacy {
            read: ReadLocation::OneMachine(b),
            sealed: SealedCopies::Off,
            models: ModelOrder::Ordered(vec!["route-a".into()]),
        },
    );
    let pick_c = edit_by(
        &host,
        c,
        &c_key,
        world,
        WorldPrivacy {
            read: ReadLocation::OneMachine(c),
            sealed: SealedCopies::CloudAndMyMachines,
            models: ModelOrder::Ordered(vec!["route-b".into()]),
        },
    );
    let everywhere = edit_by(&host, d, &d_key, world, settings(ReadLocation::Everywhere));
    let conflicted = EffectiveWorldPrivacy {
        read: EffectiveRead::Conflicted {
            contenders: BTreeSet::from([b, c]),
        },
        sealed: SealedCopies::Off,
        models: EffectiveModelOrder::Conflicted,
    };
    for order in [
        [&pick_b, &pick_c, &everywhere],
        [&everywhere, &pick_c, &pick_b],
        [&pick_c, &everywhere, &pick_b],
    ] {
        let mut entries = base.clone();
        entries.extend(order.into_iter().cloned());
        let fold = fold_authority_log(&entries);
        assert_eq!(fold.world_privacy(world), conflicted);
        // Readable nowhere, the contenders included, until the owner re-picks.
        for destination in [
            Destination::Machine(b),
            Destination::Machine(c),
            Destination::Unknown,
        ] {
            assert!(!fold.world_readable_on(world, destination));
        }
        // A one-machine pick against "everywhere" keeps the stricter pick.
        let mut pair = base.clone();
        pair.extend([order[0].clone(), everywhere.clone()]);
        if order[0] != &everywhere {
            let pick = if order[0] == &pick_b { b } else { c };
            assert_eq!(
                fold_authority_log(&pair).world_privacy(world).read,
                EffectiveRead::OneMachine(pick)
            );
        }
    }

    // The vault folds the same; a contender re-picks, a bystander cannot.
    land(&host, &[pick_c, everywhere, pick_b]);
    assert_eq!(host.vault.world_privacy(world).unwrap(), conflicted);
    let bystander = edit_by(
        &host,
        d,
        &d_key,
        world,
        settings(ReadLocation::OneMachine(d)),
    );
    let repick = edit_by(
        &host,
        c,
        &c_key,
        world,
        settings(ReadLocation::OneMachine(c)),
    );
    land(&host, &[bystander, repick]);
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(c));
}

#[test]
fn a_machine_removed_while_it_widened_never_widens() {
    let host = host();
    let world = world_row(&host);
    let (laptop, laptop_key) =
        other_machine(&host, 70, MachineRole::Owned(MachineOwnership::Yours));
    land(
        &host,
        &[edit_by(
            &host,
            laptop,
            &laptop_key,
            world,
            settings(ReadLocation::OneMachine(laptop)),
        )],
    );
    // An edit the owner's removal saw keeps its effect.
    let kept = world_row(&host);
    land(
        &host,
        &[edit_by(
            &host,
            laptop,
            &laptop_key,
            kept,
            settings(ReadLocation::MyMachines),
        )],
    );

    // The stolen laptop, offline, widens the world, while the owner removes
    // it without having seen that edit.
    let widen = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::Everywhere),
    );
    host.vault
        .set_machine_role(&host.issuer, &host.owner, laptop, MachineRole::Removed)
        .unwrap();
    land(&host, &[widen.clone()]);

    let fold = host.vault.authority_fold().unwrap();
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&widen).unwrap())
    );
    // Met with what it replaced: still the laptop's alone, now nowhere.
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(laptop));
    assert!(!fold.world_readable_on(world, Destination::Unknown));
    assert_eq!(read_of(&host, kept), EffectiveRead::MyMachines);
    // After the removal the laptop's edits are refused outright.
    let late = edit_by(
        &host,
        laptop,
        &laptop_key,
        kept,
        settings(ReadLocation::Everywhere),
    );
    land(&host, &[late.clone()]);
    assert!(
        !host
            .vault
            .authority_fold()
            .unwrap()
            .valid_entries
            .contains(&authority_entry_hash(&late).unwrap())
    );
    assert_eq!(read_of(&host, kept), EffectiveRead::MyMachines);
}

#[test]
fn a_machine_that_loses_standing_never_widens_a_world() {
    let host = host();
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let (b, b_key) = other_machine(&host, 77, yours);
    let (c, c_key) = other_machine(&host, 78, yours);
    let (laptop, laptop_key) = other_machine(&host, 79, yours);

    // The laptop narrows a world, and the owner demotes it without having
    // seen that edit: the narrowing stays.
    let narrowed = world_row(&host);
    let narrow = edit_by(
        &host,
        laptop,
        &laptop_key,
        narrowed,
        settings(ReadLocation::MyMachines),
    );
    host.vault
        .set_machine_role(
            &host.issuer,
            &host.owner,
            laptop,
            MachineRole::Owned(MachineOwnership::WorkSchool),
        )
        .unwrap();
    land(&host, &[narrow]);
    assert_eq!(read_of(&host, narrowed), EffectiveRead::MyMachines);

    // Another machine of the owner's widens a second world.
    let widened = world_row(&host);
    land(
        &host,
        &[edit_by(
            &host,
            b,
            &b_key,
            widened,
            settings(ReadLocation::MyMachines),
        )],
    );
    land(
        &host,
        &[edit_by(
            &host,
            c,
            &c_key,
            widened,
            settings(ReadLocation::Everywhere),
        )],
    );
    assert_eq!(read_of(&host, widened), EffectiveRead::Everywhere);

    // An install that does not count the laptop or that machine keeps the
    // narrowing and never takes the widening.
    let entries = stored_entries(&host.vault);
    let fold = fold_authority_log_with_machine_standing(&entries, &|_, folded| {
        ![laptop, c].contains(&folded.profile.machine)
    });
    assert_eq!(fold.world_privacy(narrowed).read, EffectiveRead::MyMachines);
    assert_eq!(fold.world_privacy(widened).read, EffectiveRead::MyMachines);
}

#[test]
fn a_replica_without_a_worlds_entries_folds_the_same_main_log() {
    let host = host();
    let here = enrol_here(&host);
    let world = world_row(&host);
    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::MyMachines,
    )
    .unwrap();
    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::OneMachine(here),
    )
    .unwrap();
    // The main log moves on after the edits.
    let (later, later_key) = other_machine(&host, 71, MachineRole::Owned(MachineOwnership::Yours));

    let entries = stored_entries(&host.vault);
    let (edits, main): (Vec<_>, Vec<_>) = entries
        .iter()
        .cloned()
        .partition(|entry| matches!(entry.op, AuthorityOp::WorldPrivacy(_)));
    assert_eq!(edits.len(), 2);
    let edit_hashes: BTreeSet<_> = edits
        .iter()
        .map(|entry| authority_entry_hash(entry).unwrap())
        .collect();
    let full = fold_authority_log(&entries);
    let without = fold_authority_log(&main);
    assert_eq!(full.append_heads, without.append_heads);
    assert_eq!(full.machines, without.machines);
    assert_eq!(full.roster, without.roster);
    assert_eq!(full.actor_bindings, without.actor_bindings);
    assert_eq!(
        full.valid_entries
            .difference(&edit_hashes)
            .copied()
            .collect::<BTreeSet<_>>(),
        without.valid_entries
    );
    assert!(without.machine(later).is_some_and(FoldedMachine::is_mine));
    assert!(without.side_heads.is_empty());
    // The second edit took the first as its parent: one side head, never a
    // main-log head.
    let edit = *full.side_heads[&world].first().unwrap();
    assert_eq!(full.side_heads[&world], BTreeSet::from([edit]));
    assert!(full.append_heads.is_disjoint(&edit_hashes));
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(here));

    // Another world's entry may not hang off this world's side head.
    let other_world = world_row(&host);
    let mut crossing = edit_by(
        &host,
        later,
        &later_key,
        other_world,
        settings(ReadLocation::MyMachines),
    );
    crossing.parent_hashes.push(edit);
    let crossing = sign_ed(crossing, &later_key);
    land(&host, &[crossing.clone()]);
    let fold = host.vault.authority_fold().unwrap();
    let crossing = authority_entry_hash(&crossing).unwrap();
    assert!(!fold.valid_entries.contains(&crossing));
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::InvalidEntry(crossing))
    );
    assert_eq!(read_of(&host, other_world), EffectiveRead::Everywhere);

    // A main-log entry may not hang off a world edit.
    let stray = EntityId::now();
    let request = request_for(host.vault_id, stray, &ed_key(72));
    let fold = host.vault.authority_fold().unwrap();
    let hanging = host
        .issuer
        .sign_entry(
            fold.vault_id,
            fold.append_sequences[&host.issuer.public_key()] + 1,
            vec![edit],
            AuthorityOp::MachineProfile(MachineProfile {
                machine: stray,
                owner: host.owner.actor(),
                machine_key: request.machine_key,
                encryption_key: request.encryption_key,
                role: MachineRole::Owned(MachineOwnership::Yours),
                revision: 1,
                machine_proof: request.machine_proof,
                seen_world_edits: BTreeSet::new(),
            }),
            2,
        )
        .unwrap();
    land(&host, &[hanging]);
    assert!(
        host.vault
            .authority_fold()
            .unwrap()
            .machine(stray)
            .is_none()
    );
}

#[test]
fn a_replayed_edit_or_a_restore_never_loosens_a_world() {
    let host = host();
    let here = enrol_here(&host);
    let world = world_row(&host);
    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::MyMachines,
    )
    .unwrap();
    let older: Vec<_> = stored_entries(&host.vault)
        .into_iter()
        .filter(|entry| matches!(entry.op, AuthorityOp::WorldPrivacy(_)))
        .collect();
    let backups = tempfile::tempdir().unwrap();
    let image = backups.path().join("backup");
    host.vault.snapshot_checkpoint(&image, 100).unwrap();
    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::OneMachine(here),
    )
    .unwrap();

    // Re-importing the older edit is a no-op: it is superseded.
    land(&host, &older);
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(here));

    // A restore that keeps the live authority keeps the live settings.
    match Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("restored"),
        VaultConfig::default(),
        &host.vault,
        200,
    ) {
        Err(_) => {}
        Ok((restored, _)) => assert_eq!(
            restored.world_privacy(world).unwrap().read,
            EffectiveRead::OneMachine(here)
        ),
    }
}
