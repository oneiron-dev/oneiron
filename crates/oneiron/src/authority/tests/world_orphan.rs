//! World privacy orphan re-pick: a world whose read names no machine still
//! the owner's is re-picked from another of the owner's machines, and never
//! while a machine it names is still the owner's.
use super::machine_identity::host;
use super::world_privacy::{
    edit_by, enrol_here, land, other_machine, read_of, set, settings, stored_entries, world_row,
};
use super::*;

#[test]
fn a_stolen_machines_world_is_re_picked_from_another_of_the_owners_machines() {
    // The thief's edit reaches the owner before the removal or after it, or
    // the owner demotes the machine instead of removing it.
    for (seen, role) in [
        (true, MachineRole::Removed),
        (false, MachineRole::Removed),
        (true, MachineRole::Owned(MachineOwnership::Rented)),
    ] {
        let host = host();
        let here = enrol_here(&host);
        let world = world_row(&host);
        let (stolen, stolen_key) =
            other_machine(&host, 73, MachineRole::Owned(MachineOwnership::Yours));
        let theft = edit_by(
            &host,
            stolen,
            &stolen_key,
            world,
            settings(ReadLocation::OneMachine(stolen)),
        );
        if seen {
            land(&host, &[theft.clone()]);
            // While the stolen machine is still the owner's, nobody else
            // re-picks its world.
            assert!(
                set(
                    &host,
                    EditOrigin::ThisMachine,
                    world,
                    ReadLocation::OneMachine(here)
                )
                .is_err()
            );
        }
        host.vault
            .set_machine_role(&host.issuer, &host.owner, stolen, role)
            .unwrap();
        if !seen {
            land(&host, &[theft.clone()]);
        }
        let fold = host.vault.authority_fold().unwrap();
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&theft).unwrap())
        );
        assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(stolen));
        assert_eq!(
            fold.world_edit_standing(here, world),
            Some(WorldEditStanding::RepicksOrphan)
        );

        let receipt = host
            .vault
            .set_world_privacy_as(
                &host.owner,
                EditOrigin::ThisMachine,
                world,
                settings(ReadLocation::OneMachine(here)),
            )
            .unwrap();
        assert_eq!(receipt.orphaned_from, vec![stolen.to_hex()]);
        assert_eq!(receipt.next.read, EffectiveRead::OneMachine(here));
        let entries = stored_entries(&host.vault);
        for entries in [entries.clone(), entries.into_iter().rev().collect()] {
            let fold = fold_authority_log(&entries);
            assert_eq!(
                fold.world_privacy(world).read,
                EffectiveRead::OneMachine(here)
            );
            assert!(fold.world_readable_on(world, Destination::Machine(here)));
        }
    }
}

#[test]
fn a_conflict_with_one_live_contender_is_not_orphaned() {
    let host = host();
    let here = enrol_here(&host);
    let world = world_row(&host);
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let (b, b_key) = other_machine(&host, 74, yours);
    let (c, c_key) = other_machine(&host, 75, yours);
    let (d, d_key) = other_machine(&host, 76, yours);
    let pick_b = edit_by(
        &host,
        b,
        &b_key,
        world,
        settings(ReadLocation::OneMachine(b)),
    );
    let pick_c = edit_by(
        &host,
        c,
        &c_key,
        world,
        settings(ReadLocation::OneMachine(c)),
    );
    land(&host, &[pick_b, pick_c]);
    host.vault
        .set_machine_role(&host.issuer, &host.owner, c, MachineRole::Removed)
        .unwrap();
    let conflicted = EffectiveRead::Conflicted {
        contenders: BTreeSet::from([b, c]),
    };
    assert_eq!(read_of(&host, world), conflicted);

    // One contender is still the owner's: it re-picks, nobody else does.
    assert!(
        set(
            &host,
            EditOrigin::ThisMachine,
            world,
            ReadLocation::OneMachine(here)
        )
        .is_err()
    );
    let early = edit_by(
        &host,
        d,
        &d_key,
        world,
        settings(ReadLocation::OneMachine(d)),
    );
    land(&host, &[early.clone()]);
    let fold = host.vault.authority_fold().unwrap();
    let early = authority_entry_hash(&early).unwrap();
    assert!(fold.refused_world_edits.contains(&early));
    assert_eq!(fold.world_edit_standing(here, world), None);
    assert_eq!(
        fold.world_edit_standing(b, world),
        Some(WorldEditStanding::Contends)
    );
    assert_eq!(read_of(&host, world), conflicted);

    // Once no contender is the owner's, the world is orphaned and another of
    // the owner's machines re-picks it. The early edit stays refused: it was
    // judged where it was made.
    host.vault
        .set_machine_role(&host.issuer, &host.owner, b, MachineRole::Removed)
        .unwrap();
    assert_eq!(read_of(&host, world), conflicted);
    let repick = edit_by(&host, d, &d_key, world, settings(ReadLocation::MyMachines));
    land(&host, &[repick]);
    let fold = host.vault.authority_fold().unwrap();
    assert!(fold.refused_world_edits.contains(&early));
    assert_eq!(read_of(&host, world), EffectiveRead::MyMachines);
    assert!(fold.world_readable_on(world, Destination::Machine(here)));
}
