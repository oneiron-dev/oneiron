//! World privacy P2 acceptance: a world's settings change only through the
//! owner's door, on a machine the owner marked "yours" that holds the world.
//! Concurrent edits fold stricter in every order, and no forged entry, generic
//! write, replayed edit, restore or machine that lost "yours" widens a world.
use super::super::slip_vault::next_entry;
use super::machine_identity::{Host, host, own_encryption_key, request_for};
use super::support::RosterHead;
use super::support::{
    authority_key_from_ed, device, ed_key, genesis_entry, owner_act, sign_ed, unsigned_entry,
};
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
        .machine_enrolment_request(
            host.vault_id,
            own_encryption_key(&host.vault, host.vault_id),
        )
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
    let surface = match origin {
        EditOrigin::Peer(PeerMachine::Proven { machine, .. }) => {
            ActSurface::LinkedDevice { machine }
        }
        _ => ActSurface::ThisInstall,
    };
    host.vault
        .set_world_privacy_as(&host.owner, surface, world, settings(read), None)
        .map(|_| ())
}

/// An edit `key` signs as `machine`, on the host's main-log heads and the
/// world's live edits: what that machine's own door would sign.
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
    if let Some(folded) = fold.worlds.get(&world) {
        parents.extend(folded.live.keys().copied());
    }
    sign_ed(
        unsigned_entry(
            fold.vault_id,
            seq,
            parents.into_iter().collect(),
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                act: owner_act(host.owner.actor(), world),
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

/// A machine of the owner's that floods a world with more concurrent edits
/// than one entry may name never locks the owner out of it: the door replaces
/// them a share at a time (Wonder P2 round 1, W5).
#[test]
fn a_flood_of_concurrent_edits_never_locks_the_door() {
    let host = host();
    let world = world_row(&host);
    let here = enrol_here(&host);
    let (flooder, flooder_key) =
        other_machine(&host, 63, MachineRole::Owned(MachineOwnership::Yours));
    let flood: Vec<_> = (0..40)
        .map(|ts| {
            let mut entry = edit_by(
                &host,
                flooder,
                &flooder_key,
                world,
                settings(ReadLocation::Everywhere),
            );
            entry.ts = ts;
            sign_ed(entry, &flooder_key)
        })
        .collect();
    land(&host, &flood);
    assert_eq!(
        host.vault.authority_fold().unwrap().worlds[&world]
            .live
            .len(),
        40
    );

    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::OneMachine(here),
    )
    .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    assert_eq!(fold.worlds[&world].live.len(), 1);
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(here));
}

/// The owner's door names only the rows its standing rests on, never an
/// unrelated main-log head. A replica that settled a handoff before a row the
/// old root signed beside it arrived refuses that row, and still takes the
/// owner's next edit: the world changes on both replicas (Engine ruling
/// 2026-10-14 on Wonder P2 round 1, W4).
#[test]
fn a_replica_that_refused_a_fenced_row_takes_the_next_edit() {
    let host = host();
    let world = world_row(&host);
    let here = enrol_here(&host);
    let before = host.vault.authority_fold().unwrap();
    let root = &before.roster[&host.issuer.public_key()];
    let successor = ed_key(64);
    let handoff = next_entry(
        &host.issuer,
        &before,
        AuthorityOp::ReRoot {
            new_device: device(authority_key_from_ed(&successor), root.roles, root.tier),
        },
        3,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    replica
        .import_signed_authority_history(&host.vault.export_signed_authority_history().unwrap())
        .unwrap();
    replica
        .put_authority_log_entry(&handoff, TimeRange { start: 3, end: 3 }, 3)
        .unwrap();

    // The old root marks another machine beside its handoff: the newest
    // main-log head here, which the replica refuses.
    let (other, _) = other_machine(&host, 65, MachineRole::Owned(MachineOwnership::Yours));
    let fenced = stored_entries(&host.vault)
        .into_iter()
        .find(|entry| {
            matches!(&entry.op, AuthorityOp::MachineProfile(profile) if profile.machine == other)
        })
        .unwrap();
    assert!(
        replica
            .put_authority_log_entry(&fenced, TimeRange { start: 3, end: 3 }, 3)
            .is_err()
    );

    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::OneMachine(here),
    )
    .unwrap();
    let edit = stored_entries(&host.vault)
        .into_iter()
        .find(|entry| matches!(entry.op, AuthorityOp::WorldPrivacy(_)))
        .unwrap();
    assert!(
        !edit
            .parent_hashes
            .contains(&authority_entry_hash(&fenced).unwrap())
    );
    replica
        .put_authority_log_entry(&edit, TimeRange { start: 4, end: 4 }, 4)
        .unwrap();
    assert_eq!(
        replica.world_privacy(world).unwrap().read,
        EffectiveRead::OneMachine(here)
    );
    super::world_floor::assert_no_vouch_widens(&replica);
    host.vault
        .put_authority_log_entry(&handoff, TimeRange { start: 4, end: 4 }, 4)
        .unwrap();
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(here));
    super::world_floor::assert_no_vouch_widens(&host.vault);
}

/// A conflict among more machines than one entry may name never locks a
/// contender out: the door names the main-log heads for a world readable
/// nowhere and replaces the picks a share at a time (Sol P2 round 5, F2).
#[test]
fn a_contender_re_picks_a_conflict_among_many_machines() {
    let host = host();
    let world = world_row(&host);
    let here = enrol_here(&host);
    // 31 machines pick themselves on the snapshot before this machine does.
    let picks: Vec<_> = (0..31)
        .map(|seed| {
            let (other, key) = other_machine(
                &host,
                90 + seed,
                MachineRole::Owned(MachineOwnership::Yours),
            );
            edit_by(
                &host,
                other,
                &key,
                world,
                settings(ReadLocation::OneMachine(other)),
            )
        })
        .collect();
    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::OneMachine(here),
    )
    .unwrap();
    land(&host, &picks);
    let EffectiveRead::Conflicted { contenders } = read_of(&host, world) else {
        panic!("32 concurrent picks conflict");
    };
    assert_eq!(contenders.len(), 32);

    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::OneMachine(here),
    )
    .unwrap();
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(here));
}

/// A world whose named machine lost its standing only to a shared install
/// key, a fact outside that machine's own revisions, is re-picked through the
/// door (Sol P2 round 5, F3).
#[test]
fn a_world_orphaned_by_a_shared_key_is_re_picked() {
    let host = host();
    let world = world_row(&host);
    let here = enrol_here(&host);
    let (laptop, laptop_key) =
        other_machine(&host, 66, MachineRole::Owned(MachineOwnership::Yours));
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
    // The owner's root marks a second machine with the laptop's install key.
    let fold = host.vault.authority_fold().unwrap();
    let twin = EntityId::now();
    let request = request_for(host.vault_id, twin, &laptop_key);
    let twin_mark = next_entry(
        &host.issuer,
        &fold,
        AuthorityOp::MachineProfile(MachineProfile {
            machine: twin,
            owner: host.owner.actor(),
            machine_key: request.machine_key,
            encryption_key: request.encryption_key,
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision: 1,
            machine_proof: request.machine_proof,
            seen_world_edits: BTreeSet::new(),
        }),
        3,
    )
    .unwrap();
    land(&host, &[twin_mark]);
    let fold = host.vault.authority_fold().unwrap();
    assert!(
        fold.machine(laptop)
            .is_some_and(|folded| folded.head().conflicted)
    );
    assert!(!fold.world_readable_on(world, Destination::Machine(here)));

    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::OneMachine(here),
    )
    .unwrap();
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(here));
}

/// A conflicted world with more concurrent edits than one entry may name is
/// never moved straight to another machine: a share of the consolidation
/// would grant this machine the world on a replica that missed the last edit.
/// Moved here first, it then moves on (Sol P2 round 5, F5).
#[test]
fn a_flooded_conflict_moves_here_before_it_moves_on() {
    let host = host();
    let world = world_row(&host);
    let here = enrol_here(&host);
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let (other, other_key) = other_machine(&host, 67, yours);
    let (flooder, flooder_key) = other_machine(&host, 68, yours);
    let mut concurrent = vec![edit_by(
        &host,
        other,
        &other_key,
        world,
        settings(ReadLocation::OneMachine(other)),
    )];
    concurrent.extend((0..38).map(|ts| {
        let mut entry = edit_by(
            &host,
            flooder,
            &flooder_key,
            world,
            settings(ReadLocation::Everywhere),
        );
        entry.ts = ts;
        sign_ed(entry, &flooder_key)
    }));
    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::OneMachine(here),
    )
    .unwrap();
    land(&host, &concurrent);
    let conflicted = EffectiveRead::Conflicted {
        contenders: BTreeSet::from([here, other]),
    };
    assert_eq!(read_of(&host, world), conflicted);

    assert!(
        set(
            &host,
            EditOrigin::ThisMachine,
            world,
            ReadLocation::OneMachine(other)
        )
        .is_err()
    );
    let fold = host.vault.authority_fold().unwrap();
    assert_eq!(fold.worlds[&world].live.len(), 40);
    assert_eq!(read_of(&host, world), conflicted);

    for read in [
        ReadLocation::OneMachine(here),
        ReadLocation::OneMachine(other),
    ] {
        set(&host, EditOrigin::ThisMachine, world, read).unwrap();
    }
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(other));
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
        EditOrigin::Peer(PeerMachine::Proven {
            machine: other,
            key: other_key.verifying_key().to_bytes(),
        }),
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
            ActSurface::LinkedDevice { machine: here },
            world,
            settings(ReadLocation::OneMachine(here)),
            None,
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
    land(&host, std::slice::from_ref(&widen));
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
                act: owner_act(host.owner.actor(), world),
                machine: mine,
                settings: widen,
            }),
            2,
        )
        .unwrap();
    // The door holds each edit no install key of the machine it names
    // signed (H72). The work machine's own edit names that machine, so it
    // lands, and only the fold refuses it.
    for entry in [&forged[0], &forged[2], &root_edit] {
        let err = host
            .vault
            .put_authority_log_entries(&[(entry.clone(), TimeRange { start: 2, end: 2 }, 2)])
            .unwrap_err();
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::AuthorityLogSignerPending
        );
    }
    land(&host, std::slice::from_ref(&forged[1]));
    // The fold refuses the held edits too, wherever they are stored.
    crate::authority::with_authority_doors_open_for_test(|| {
        land(
            &host,
            &[forged[0].clone(), forged[2].clone(), root_edit.clone()],
        );
    });

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

/// A holder's edit stands though its hold rests on a row its own head
/// revision does not carry: this machine's mark sits on a demotion that never
/// saw another machine's widening, and only a later "yours" for that machine
/// makes the widening count (Sol P2 round 6, F5).
#[test]
fn a_hold_resting_on_a_later_mark_still_edits() {
    let host = host();
    let world = world_row(&host);
    let here = enrol_here(&host);
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let (laptop, laptop_key) = other_machine(&host, 87, yours);
    let (desk, desk_key) = other_machine(&host, 88, yours);
    let picks = [
        edit_by(
            &host,
            laptop,
            &laptop_key,
            world,
            settings(ReadLocation::OneMachine(laptop)),
        ),
        edit_by(
            &host,
            desk,
            &desk_key,
            world,
            settings(ReadLocation::OneMachine(desk)),
        ),
    ];
    land(&host, &picks);
    land(
        &host,
        &[edit_by(
            &host,
            laptop,
            &laptop_key,
            world,
            settings(ReadLocation::Everywhere),
        )],
    );
    assert_eq!(read_of(&host, world), EffectiveRead::Everywhere);

    // A branch that never saw the widening demotes the laptop, and this
    // machine is marked again on top of it.
    let fold = host.vault.authority_fold().unwrap();
    let mut seq = fold.append_sequences[&host.issuer.public_key()];
    let mut parents: Vec<_> = fold.append_heads.iter().copied().collect();
    let laptop_profile = fold.machine(laptop).unwrap().head().profile.clone();
    let here_profile = fold.machine(here).unwrap().head().profile.clone();
    let demotion = MachineProfile {
        role: MachineRole::Owned(MachineOwnership::WorkSchool),
        revision: laptop_profile.revision + 1,
        seen_world_edits: BTreeSet::new(),
        ..laptop_profile
    };
    let mark = MachineProfile {
        revision: here_profile.revision + 1,
        ..here_profile
    };
    let mut branch = Vec::new();
    for profile in [demotion, mark] {
        seq += 1;
        let entry = host
            .issuer
            .sign_entry(
                fold.vault_id,
                seq,
                parents,
                AuthorityOp::MachineProfile(profile),
                3,
            )
            .unwrap();
        parents = vec![authority_entry_hash(&entry).unwrap()];
        branch.push(entry);
    }
    land(&host, &branch);
    assert!(matches!(
        read_of(&host, world),
        EffectiveRead::Conflicted { .. }
    ));

    // The owner marks the laptop "yours" again: the widening counts, and
    // this machine holds the world on a head its own mark does not carry.
    host.vault
        .set_machine_role(&host.issuer, &host.owner, laptop, yours)
        .unwrap();
    assert_eq!(read_of(&host, world), EffectiveRead::Everywhere);
    let fold = host.vault.authority_fold().unwrap();
    assert_eq!(fold.machine(here).unwrap().head().entry, parents[0]);
    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::MyMachines,
    )
    .unwrap();
    assert_eq!(read_of(&host, world), EffectiveRead::MyMachines);
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
    // The world's side entries: its settings edits, and the key records the
    // settings door's ensure step signs once this install has a keystore.
    let (edits, main): (Vec<_>, Vec<_>) = entries.iter().cloned().partition(|entry| {
        matches!(
            entry.op,
            AuthorityOp::WorldPrivacy(_) | AuthorityOp::WorldKeyWraps(_)
        )
    });
    assert_eq!(
        edits
            .iter()
            .filter(|entry| matches!(entry.op, AuthorityOp::WorldPrivacy(_)))
            .count(),
        2
    );
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
    // A write stamped with a frontier must not depend on a world's entries.
    assert_eq!(full.actor_write_frontiers, without.actor_write_frontiers);
    assert_eq!(
        full.valid_entries
            .difference(&edit_hashes)
            .copied()
            .collect::<ValidEntries>(),
        without.valid_entries
    );
    assert!(without.machine(later).is_some_and(RosterHead::mine));
    assert!(without.worlds.is_empty());
    // The second edit took the first as its parent: one live edit, never a
    // main-log head.
    assert_eq!(full.worlds[&world].live.len(), 1);
    let edit = *full.worlds[&world].live.keys().next().unwrap();
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
    land(&host, std::slice::from_ref(&crossing));
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

    // Nor may a restrictive one: a revoke hanging off a side head revokes
    // nothing, so the main state never depends on a world's entries.
    let fold = host.vault.authority_fold().unwrap();
    let root = host.issuer.public_key();
    let epoch = fold.actor_bindings[&root].epoch;
    let mut parents: Vec<_> = fold.append_heads.iter().copied().collect();
    parents.push(edit);
    let revoke = host
        .issuer
        .sign_entry(
            fold.vault_id,
            fold.append_sequences[&root] + 1,
            parents,
            AuthorityOp::RevokeActor {
                authority_key: root.clone(),
                epoch,
            },
            2,
        )
        .unwrap();
    land(&host, std::slice::from_ref(&revoke));
    let fold = host.vault.authority_fold().unwrap();
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&revoke).unwrap())
    );
    assert_eq!(
        fold.actor_bindings[&root].status,
        ActorBindingStatus::Active
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
    let backups = crate::test_support::restore_tempdir();
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
    let (restored, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("restored"),
        VaultConfig::default(),
        &host.vault,
        200,
    )
    .unwrap();
    assert_eq!(
        restored.world_privacy(world).unwrap().read,
        EffectiveRead::OneMachine(here)
    );
    drop(restored);

    // A direct restore folds the image's own era, never looser than it, and
    // the live log's entries narrow it back on the first sync.
    let live = stored_entries(&host.vault);
    let Host { _dir, vault, .. } = host;
    drop(vault);
    let (direct, _) = Vault::restore_checkpoint(
        &image,
        &backups.path().join("direct"),
        VaultConfig::default(),
        crate::recovery::checkpoint::RestoreReason::Restore,
        300,
    )
    .unwrap();
    assert_eq!(
        direct.world_privacy(world).unwrap().read,
        EffectiveRead::MyMachines
    );
    let at = TimeRange { start: 2, end: 2 };
    let rows: Vec<_> = live.into_iter().map(|entry| (entry, at, 2)).collect();
    direct.put_authority_log_entries(&rows).unwrap();
    assert_eq!(
        direct.world_privacy(world).unwrap().read,
        EffectiveRead::OneMachine(here)
    );
}

/// A second signed genesis leaves the vault's root conflicted, and its fold
/// names no world. A world kept to one machine must not read as portable for
/// that (Sol P2 round 2, F4).
#[test]
fn a_conflicted_root_never_lets_a_private_world_go() {
    let host = host();
    let here = enrol_here(&host);
    let world = world_row(&host);
    set(
        &host,
        EditOrigin::ThisMachine,
        world,
        ReadLocation::OneMachine(here),
    )
    .unwrap();
    let withheld = |vault: &Vault| {
        let txn = vault.store.env.read_txn().unwrap();
        crate::settings::device_local_worlds_at(
            vault,
            &txn,
            crate::claim::CallerLocality::OffDevice,
        )
    };
    assert!(withheld(&host.vault).unwrap().contains(&world));

    // No door stores a rival genesis (H72); build the conflicted log here.
    let rival = genesis_entry(78, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    crate::authority::with_authority_doors_open_for_test(|| {
        host.vault
            .put_authority_log_entry(&rival, TimeRange { start: 3, end: 3 }, 3)
    })
    .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    assert!(fold.vault_root_is_conflicted());
    for destination in [Destination::Unknown, Destination::Machine(here)] {
        assert!(!fold.world_readable_on(world, destination));
    }
    assert!(fold.worlds_withheld_from(Destination::Unknown).is_err());
    assert!(withheld(&host.vault).is_err());
    let txn = host.vault.store.env.read_txn().unwrap();
    assert!(world_readable_on_machine_in(&host.vault, &txn, world, Destination::Unknown).is_err());
}
