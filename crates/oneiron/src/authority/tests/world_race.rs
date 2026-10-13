//! World privacy races: an edit by a machine that lost the owner's standing,
//! or one this install does not count, only ever narrows a world, however
//! many such edits chain and in whatever order they arrive.
use super::history_transfer::re_root_entry;
use super::machine_identity::{host, request_for};
use super::support::{authority_key_from_ed, ed_key, genesis_entry, sign_ed, unsigned_entry};
use super::world_privacy::{
    edit_by, land, other_machine, read_of, settings, stored_entries, world_row,
};
use super::*;

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
fn a_chain_of_raced_widens_never_widens() {
    // The stolen laptop widens twice offline, the second edit on the first,
    // and the owner removes it having seen neither; either may arrive first.
    for second_first in [false, true] {
        let host = host();
        let world = world_row(&host);
        let (laptop, laptop_key) =
            other_machine(&host, 80, MachineRole::Owned(MachineOwnership::Yours));
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
        let first = edit_by(
            &host,
            laptop,
            &laptop_key,
            world,
            settings(ReadLocation::Everywhere),
        );
        let fold = host.vault.authority_fold().unwrap();
        let mut parents: Vec<_> = fold.append_heads.iter().copied().collect();
        parents.push(authority_entry_hash(&first).unwrap());
        let second = sign_ed(
            unsigned_entry(
                fold.vault_id,
                first.seq + 1,
                parents,
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    owner: host.owner.actor(),
                    machine: laptop,
                    settings: settings(ReadLocation::Everywhere),
                }),
                authority_key_from_ed(&laptop_key),
                2,
            ),
            &laptop_key,
        );
        host.vault
            .set_machine_role(&host.issuer, &host.owner, laptop, MachineRole::Removed)
            .unwrap();
        if second_first {
            land(&host, &[second.clone()]);
            land(&host, &[first.clone()]);
        } else {
            land(&host, &[first.clone(), second.clone()]);
        }
        let fold = host.vault.authority_fold().unwrap();
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&second).unwrap())
        );
        assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(laptop));
        assert!(!fold.world_readable_on(world, Destination::Unknown));
    }
}

#[test]
fn one_worlds_later_edit_never_rolls_back_anothers() {
    // One machine edits two worlds; the vault receives the second world's
    // edit first, or last.
    for second_first in [false, true] {
        let host = host();
        let (mine, mine_key) =
            other_machine(&host, 81, MachineRole::Owned(MachineOwnership::Yours));
        let (first_world, second_world) = (world_row(&host), world_row(&host));
        let first = edit_by(
            &host,
            mine,
            &mine_key,
            first_world,
            settings(ReadLocation::MyMachines),
        );
        let mut second = edit_by(
            &host,
            mine,
            &mine_key,
            second_world,
            settings(ReadLocation::MyMachines),
        );
        second.seq = first.seq + 1;
        let second = sign_ed(second, &mine_key);
        if second_first {
            land(&host, &[second]);
            land(&host, &[first]);
        } else {
            land(&host, &[first]);
            land(&host, &[second]);
        }
        let fold = host.vault.authority_fold().unwrap();
        for world in [first_world, second_world] {
            assert_eq!(read_of(&host, world), EffectiveRead::MyMachines);
            assert!(
                fold.worlds_withheld_from(Destination::Unknown)
                    .contains(&world)
            );
        }
    }
}

/// A machine marked by the root before its handoff, and never marked again by
/// the new root, is stale on this install once the stale-roster window passes,
/// and a widening it signed while it stood then only narrows here (Wonder P1
/// round 1, W1).
#[test]
fn a_stale_machine_never_widens_a_world() {
    let old = ed_key(110);
    let next = ed_key(111);
    let genesis = genesis_entry(110, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let (kept, kept_key) = (EntityId::now(), ed_key(112));
    let (stale, stale_key) = (EntityId::now(), ed_key(113));
    let mark = |parent: &AuthorityLogEntry, signer: &SigningKey, seq, machine, key| {
        let request = request_for(id, machine, key);
        sign_ed(
            unsigned_entry(
                Some(id),
                seq,
                vec![hash(parent)],
                AuthorityOp::MachineProfile(MachineProfile {
                    machine,
                    owner: EntityId::now(),
                    machine_key: request.machine_key,
                    encryption_key: request.encryption_key,
                    role: MachineRole::Owned(MachineOwnership::Yours),
                    revision: 1,
                    machine_proof: request.machine_proof,
                    seen_world_edits: BTreeSet::new(),
                }),
                authority_key_from_ed(signer),
                2,
            ),
            signer,
        )
    };
    let stale_mark = mark(&genesis, &old, 1, stale, &stale_key);
    let handoff = re_root_entry(id, &stale_mark, &old, 2, &next);
    let kept_mark = mark(&handoff, &next, 1, kept, &kept_key);
    let world = EntityId::now();
    let edit = |mut parents: Vec<AuthorityEntryHash>, machine, key: &SigningKey, read| {
        parents.sort();
        sign_ed(
            unsigned_entry(
                Some(id),
                1,
                parents,
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    owner: EntityId::now(),
                    machine,
                    settings: settings(read),
                }),
                authority_key_from_ed(key),
                2,
            ),
            key,
        )
    };
    let narrow = edit(
        vec![hash(&kept_mark)],
        kept,
        &kept_key,
        ReadLocation::MyMachines,
    );
    let widen = edit(
        vec![hash(&kept_mark), hash(&narrow)],
        stale,
        &stale_key,
        ReadLocation::Everywhere,
    );
    let entries = [genesis, stale_mark, handoff, kept_mark, narrow, widen];
    let first_seen: BTreeMap<_, _> = entries.iter().map(|entry| (hash(entry), 100)).collect();
    let within = fold_authority_log_with_seen_times(&entries, &first_seen, 100);
    assert_eq!(within.world_privacy(world).read, EffectiveRead::Everywhere);
    let after = fold_authority_log_with_seen_times(
        &entries,
        &first_seen,
        100 + DEFAULT_STALE_ROSTER_WINDOW_SECS + 1,
    );
    assert!(after.machine(stale).is_some_and(|folded| folded.stale));
    assert_eq!(after.world_privacy(world).read, EffectiveRead::MyMachines);
}
