//! World privacy orphan re-pick: a world whose read names no machine still
//! the owner's is re-picked from another of the owner's machines, and never
//! while a machine it names is still the owner's.
use super::machine_identity::{host, own_encryption_key, request_for};
use super::support::RosterHead;
use super::support::ed_key;
use super::world_floor::assert_no_vouch_widens;
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
            land(&host, std::slice::from_ref(&theft));
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
            land(&host, std::slice::from_ref(&theft));
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
                ActSurface::ThisInstall,
                world,
                settings(ReadLocation::OneMachine(here)),
                None,
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
    land(&host, std::slice::from_ref(&early));
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

/// A world one machine kept to itself, when a handoff from elsewhere never
/// marked that machine again: the handoff hangs off the main log alone and
/// keeps the world's restriction (Sol P2 round 2, F3). Once the old machine
/// goes stale here it no longer reads the world, but it is still the owner's
/// by the roster, so the world is not orphaned on any install until the
/// owner removes it; then a machine the new root marked re-picks the world
/// through the owner's door (Sol P2 rounds 2 and 3, F1).
#[test]
fn a_stale_holders_world_is_re_picked_after_a_handoff() {
    let host = host();
    let world = world_row(&host);
    let (old, old_key) = other_machine(&host, 77, MachineRole::Owned(MachineOwnership::Yours));
    let kept = edit_by(
        &host,
        old,
        &old_key,
        world,
        settings(ReadLocation::OneMachine(old)),
    );
    land(&host, std::slice::from_ref(&kept));

    let next = HostSlipIssuer::from_secret(b"stale holder successor root").unwrap();
    let handoff = host
        .vault
        .re_root_authority(
            next.root_device(crate::HostingPrivacyPosture::SelfHostLocal),
            host.issuer.public_key(),
            |bytes| Ok(host.issuer.sign_slip(bytes)),
        )
        .unwrap();
    assert!(
        !handoff
            .parent_hashes
            .contains(&authority_entry_hash(&kept).unwrap())
    );
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(old));

    let person = host.owner.actor();
    host.vault.bind_host_owner_for_test(&next, person).unwrap();
    let owner = host
        .vault
        .authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let request = host
        .vault
        .machine_enrolment_request(
            host.vault_id,
            own_encryption_key(&host.vault, host.vault_id),
        )
        .unwrap();
    host.vault
        .enroll_machine(
            &next,
            &owner,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    let here = request.machine;
    let repick = || {
        host.vault.set_world_privacy_as(
            &owner,
            ActSurface::ThisInstall,
            world,
            settings(ReadLocation::OneMachine(here)),
            None,
        )
    };
    // Inside the window the old machine still stands, and keeps its world.
    assert!(repick().is_err());

    super::observation_safety::advance_observation_floor(
        &host.vault,
        crate::unix_seconds_now() + DEFAULT_STALE_ROSTER_WINDOW_SECS + 60,
    );
    let fold = host.vault.authority_fold().unwrap();
    assert!(fold.machine(old).is_some_and(|folded| folded.head().stale));
    assert!(fold.machine(here).is_some_and(RosterHead::mine));
    assert!(!fold.world_readable_on(world, Destination::Machine(old)));
    assert_eq!(fold.world_edit_standing(here, world), None);
    assert!(repick().is_err());

    host.vault
        .set_machine_role(&next, &owner, old, MachineRole::Removed)
        .unwrap();
    assert_eq!(
        host.vault
            .authority_fold()
            .unwrap()
            .world_edit_standing(here, world),
        Some(WorldEditStanding::RepicksOrphan)
    );
    let receipt = repick().unwrap();
    assert_eq!(receipt.orphaned_from, vec![old.to_hex()]);
    assert_eq!(receipt.next.read, EffectiveRead::OneMachine(here));
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(here));
    assert_no_vouch_widens(&host.vault);
}

/// A removal that reached this replica after a later row of its signer still
/// stands in the log, so the world it orphans is re-picked here through the
/// owner's door, the edit finding the removal among its parents (Sol P2
/// round 3, F3).
#[test]
fn a_world_orphaned_by_a_removal_that_arrived_late_is_re_picked() {
    let host = host();
    let here = enrol_here(&host);
    let world = world_row(&host);
    let (holder, holder_key) =
        other_machine(&host, 79, MachineRole::Owned(MachineOwnership::Yours));
    land(
        &host,
        &[edit_by(
            &host,
            holder,
            &holder_key,
            world,
            settings(ReadLocation::OneMachine(holder)),
        )],
    );
    let before = host.vault.authority_fold().unwrap();
    let seq = before.append_sequences[&host.issuer.public_key()];
    let root_entry = |seq, op| {
        host.issuer
            .sign_entry(
                Some(host.vault_id),
                seq,
                before.append_heads.iter().copied().collect(),
                op,
                2,
            )
            .unwrap()
    };
    let removal = root_entry(
        seq + 1,
        AuthorityOp::MachineProfile(MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            ..before.machine(holder).unwrap().head().profile.clone()
        }),
    );
    let node = EntityId::now();
    let request = request_for(host.vault_id, node, &ed_key(80));
    let sibling = root_entry(
        seq + 2,
        AuthorityOp::MachineProfile(MachineProfile {
            machine: node,
            owner: host.owner.actor(),
            machine_key: request.machine_key,
            encryption_key: request.encryption_key,
            role: MachineRole::HostedNode,
            revision: 1,
            machine_proof: request.machine_proof,
            seen_world_edits: BTreeSet::new(),
        }),
    );
    // The higher row first, in a write of its own.
    land(&host, &[sibling]);
    land(&host, std::slice::from_ref(&removal));

    let fold = host.vault.authority_fold().unwrap();
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&removal).unwrap())
    );
    assert!(
        fold.machine(holder)
            .is_some_and(|folded| folded.head().removed)
    );
    assert_eq!(
        fold.world_edit_standing(here, world),
        Some(WorldEditStanding::RepicksOrphan)
    );
    let receipt = host
        .vault
        .set_world_privacy_as(
            &host.owner,
            ActSurface::ThisInstall,
            world,
            settings(ReadLocation::OneMachine(here)),
            None,
        )
        .unwrap();
    assert_eq!(receipt.orphaned_from, vec![holder.to_hex()]);
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(here));
}
