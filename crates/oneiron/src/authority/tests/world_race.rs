//! World privacy races: an edit by a machine that lost the owner's standing,
//! or one this install does not count, only ever narrows a world, however
//! many such edits chain and in whatever order they arrive.
use super::machine_identity::host;
use super::support::{authority_key_from_ed, sign_ed, unsigned_entry};
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
