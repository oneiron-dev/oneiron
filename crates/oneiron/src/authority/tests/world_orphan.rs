//! World privacy orphan re-pick: a world whose read names no machine still
//! the owner's is re-picked from another of the owner's machines. Standing
//! still reports whether a world is orphaned; the door itself re-picks any
//! world from any live machine (mesh PR1a: the door needs no holder).
use super::machine_identity::{host, own_encryption_key, request_for};
use super::support::RosterHead;
use super::support::ed_key;
use super::world_floor::assert_no_vouch_widens;
use super::world_privacy::{
    answer_by, edit_by, enrol_here, land, next_seq, other_machine, read_of, settings,
    stored_entries, world_row,
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
            // While the stolen machine is still the owner's the world is not
            // orphaned: standing says so, though the door would re-pick it
            // anyway (mesh PR1a, FIX-LIST 10-19 02:16: any live carrier
            // counts at full strength; the door needs no holder,
            // world_privacy_door.rs:1-11).
            assert_eq!(
                host.vault
                    .authority_fold()
                    .unwrap()
                    .world_edit_standing(here, world),
                None
            );
        }
        host.vault
            .set_machine_role(&host.owner, ActSurface::ThisInstall, stolen, role, None)
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
        .set_machine_role(
            &host.owner,
            ActSurface::ThisInstall,
            c,
            MachineRole::Removed,
            None,
        )
        .unwrap();
    let conflicted = EffectiveRead::Conflicted {
        contenders: BTreeSet::from([b, c]),
    };
    assert_eq!(read_of(&host, world), conflicted);

    // One contender is still the owner's: the world is not orphaned, though
    // the door would re-pick it anyway (mesh PR1a, FIX-LIST 10-19 02:16: any
    // live carrier counts; the door needs no holder).
    assert_eq!(
        host.vault
            .authority_fold()
            .unwrap()
            .world_edit_standing(here, world),
        None
    );
    // A live bystander's edit would count at full strength now (owner_act.rs
    // :27-47), so the refused edit below comes from the removed contender: it
    // is judged where it was made.
    let early = edit_by(
        &host,
        c,
        &c_key,
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
        .set_machine_role(
            &host.owner,
            ActSurface::ThisInstall,
            b,
            MachineRole::Removed,
            None,
        )
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
/// marked that machine again: the handoff covers every main-log head, the
/// kept edit among them (FIX 11993 R1), and keeps the world's restriction
/// (Sol P2 round 2, F3). Once the old machine
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
        handoff
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
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            request.machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
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
    // Inside the window the old machine still stands: the world is not
    // orphaned, though the door would re-pick it anyway (mesh PR1a: the door
    // needs no holder).
    assert_eq!(
        host.vault
            .authority_fold()
            .unwrap()
            .world_edit_standing(here, world),
        None
    );

    super::observation_safety::advance_observation_floor(
        &host.vault,
        crate::unix_seconds_now() + DEFAULT_STALE_ROSTER_WINDOW_SECS + 60,
    );
    let fold = host.vault.authority_fold().unwrap();
    assert!(fold.machine(old).is_some_and(|folded| folded.head().stale));
    assert!(fold.machine(here).is_some_and(RosterHead::mine));
    assert!(!fold.world_readable_on(world, Destination::Machine(old)));
    assert_eq!(fold.world_edit_standing(here, world), None);
    // Stale here but still the owner's by the roster, so still not orphaned;
    // the door would re-pick anyway (mesh PR1a).
    assert_eq!(
        host.vault
            .authority_fold()
            .unwrap()
            .world_edit_standing(here, world),
        None
    );

    host.vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            old,
            MachineRole::Removed,
            None,
        )
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
    let parents: Vec<_> = before.append_heads.iter().copied().collect();
    let holder_profile = before.machine(holder).unwrap().head().profile.clone();
    let base_seq = next_seq(&host, &holder_key);
    let removal = answer_by(
        &host,
        holder,
        &holder_key,
        &holder_profile,
        MachineRole::Removed,
        2,
        BTreeSet::new(),
        parents.clone(),
        base_seq,
    );
    let node = EntityId::now();
    let request = request_for(host.vault_id, node, &ed_key(80));
    let node_base = MachineProfile {
        machine: node,
        owner: host.owner.actor(),
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key,
        role: MachineRole::HostedNode,
        revision: 1,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
        restored_from: None,
    };
    let sibling = answer_by(
        &host,
        holder,
        &holder_key,
        &node_base,
        MachineRole::HostedNode,
        1,
        BTreeSet::new(),
        parents,
        base_seq + 1,
    );
    // The higher row of the same signer first, in a write of its own (mesh
    // PR1b: both answers are signed by the holder's install key).
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
