//! World privacy races: an edit by a machine that lost the owner's standing,
//! or one this install does not count, only ever narrows a world, however
//! many such edits chain and in whatever order they arrive.
use super::super::install_fold::fold_authority_log_with_machine_standing;
use super::super::slip_vault::next_entry;
use super::history_transfer::{re_root_entry, store};
use super::machine_identity::{host, request_for};
use super::support::RosterHead;
use super::support::{
    authority_key_from_ed, cosign_ed, device, ed_key, genesis_entry, owner_act, sign_ed,
    unsigned_entry,
};
use super::world_privacy::{
    edit_by, land, other_machine, read_of, settings, stored_entries, world_row,
};
use super::*;
use crate::{Vault, VaultConfig};

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
    land(&host, std::slice::from_ref(&widen));

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
    land(&host, std::slice::from_ref(&late));
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
    let fold = fold_authority_log_with_machine_standing(&entries, &|machine, _| {
        ![laptop, c].contains(&machine)
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
                    act: owner_act(host.owner.actor(), world),
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
            land(&host, std::slice::from_ref(&second));
            land(&host, std::slice::from_ref(&first));
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

/// The stolen laptop's widening raced its demotion, so it only narrows. A
/// later revision of the laptop, the owner's removal or a demotion signed
/// again, took nothing away and acknowledges nothing, whether the owner's door
/// signed it or a peer listed the widening in it (Wonder P2 round 1, W2).
#[test]
fn a_later_revision_never_acknowledges_a_raced_widening() {
    for later in [
        MachineRole::Removed,
        MachineRole::Owned(MachineOwnership::Rented),
    ] {
        for listed in [false, true] {
            let host = host();
            let world = world_row(&host);
            let (laptop, laptop_key) =
                other_machine(&host, 81, MachineRole::Owned(MachineOwnership::Yours));
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
            let widen = edit_by(
                &host,
                laptop,
                &laptop_key,
                world,
                settings(ReadLocation::Everywhere),
            );
            host.vault
                .set_machine_role(
                    &host.issuer,
                    &host.owner,
                    laptop,
                    MachineRole::Owned(MachineOwnership::WorkSchool),
                )
                .unwrap();
            land(&host, std::slice::from_ref(&widen));
            assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(laptop));

            if listed {
                let fold = host.vault.authority_fold().unwrap();
                let current = fold.machine(laptop).unwrap().head().profile.clone();
                let mut seen_world_edits = current.seen_world_edits.clone();
                seen_world_edits.insert(authority_entry_hash(&widen).unwrap());
                let profile = MachineProfile {
                    role: later,
                    revision: current.revision + 1,
                    seen_world_edits,
                    ..current
                };
                land(
                    &host,
                    &[
                        next_entry(&host.issuer, &fold, AuthorityOp::MachineProfile(profile), 3)
                            .unwrap(),
                    ],
                );
            } else {
                host.vault
                    .set_machine_role(&host.issuer, &host.owner, laptop, later)
                    .unwrap();
            }
            let fold = host.vault.authority_fold().unwrap();
            assert_eq!(fold.machine(laptop).unwrap().head().profile.role, later);
            assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(laptop));
            assert!(!fold.world_readable_on(world, Destination::Unknown));
        }
    }
}

/// A removal keeps the widening it saw, though the machine was not the
/// owner's once before, for one revision or a run of them: what an earlier
/// "yours" taken away had seen never narrows what a later one saw (Sol P2
/// round 5, F1; round 7, F1).
#[test]
fn a_removal_keeps_what_it_saw_after_an_earlier_not_mine_period() {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let work = MachineRole::Owned(MachineOwnership::WorkSchool);
    for earlier in [
        vec![work, yours],
        vec![yours, work, yours],
        vec![work, work, yours],
    ] {
        let host = host();
        let world = world_row(&host);
        let (laptop, laptop_key) = other_machine(&host, 84, earlier[0]);
        for role in &earlier[1..] {
            host.vault
                .set_machine_role(&host.issuer, &host.owner, laptop, *role)
                .unwrap();
        }
        for read in [ReadLocation::MyMachines, ReadLocation::Everywhere] {
            land(
                &host,
                &[edit_by(&host, laptop, &laptop_key, world, settings(read))],
            );
        }
        host.vault
            .set_machine_role(&host.issuer, &host.owner, laptop, MachineRole::Removed)
            .unwrap();
        assert_eq!(read_of(&host, world), EffectiveRead::Everywhere);
    }
}

/// A main-log row a machine's install key signed at a high sequence bounds
/// that machine's later edits even when the fold refuses the row and a world
/// edit above it is folded with the row crossed (Sol P2 round 5, F4).
#[test]
fn a_crossed_row_still_bounds_its_signers_sequence() {
    let host = host();
    let world = world_row(&host);
    let (laptop, laptop_key) =
        other_machine(&host, 85, MachineRole::Owned(MachineOwnership::Yours));
    let narrow = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::MyMachines),
    );
    land(&host, std::slice::from_ref(&narrow));
    let fold = host.vault.authority_fold().unwrap();
    let mark = fold.machine(laptop).unwrap().head().clone();
    let unauthorised = sign_ed(
        unsigned_entry(
            fold.vault_id,
            100,
            vec![mark.entry],
            AuthorityOp::MachineProfile(MachineProfile {
                revision: mark.profile.revision + 1,
                ..mark.profile
            }),
            authority_key_from_ed(&laptop_key),
            3,
        ),
        &laptop_key,
    );
    let mut parents = vec![
        authority_entry_hash(&narrow).unwrap(),
        authority_entry_hash(&unauthorised).unwrap(),
    ];
    parents.sort();
    let widen = sign_ed(
        unsigned_entry(
            fold.vault_id,
            2,
            parents,
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                act: owner_act(host.owner.actor(), world),
                machine: laptop,
                settings: settings(ReadLocation::Everywhere),
            }),
            authority_key_from_ed(&laptop_key),
            3,
        ),
        &laptop_key,
    );
    let mut entries = stored_entries(&host.vault);
    entries.extend([unauthorised.clone(), widen.clone()]);
    let fold = fold_authority_log(&entries);
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&unauthorised).unwrap())
    );
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&widen).unwrap())
    );
    assert_eq!(fold.world_privacy(world).read, EffectiveRead::MyMachines);
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
                    .unwrap()
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
                    act: owner_act(EntityId::now(), world),
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
    assert!(
        after
            .machine(stale)
            .is_some_and(|folded| folded.head().stale)
    );
    assert_eq!(after.world_privacy(world).read, EffectiveRead::MyMachines);
}

/// An edit refused because another machine held the world stays refused when
/// that holder later goes stale here: the holder is still the owner's by the
/// roster, so losing its standing on one install never accepts what every
/// install refused (Sol P2 round 3, F1).
#[test]
fn a_holder_going_stale_never_accepts_a_refused_edit() {
    let old = ed_key(114);
    let next = ed_key(115);
    let genesis = genesis_entry(114, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let (holder, holder_key) = (EntityId::now(), ed_key(116));
    let (other, other_key) = (EntityId::now(), ed_key(117));
    let mark = |parent: &AuthorityLogEntry, signer: &SigningKey, seq, machine, key, revision| {
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
                    revision,
                    machine_proof: request.machine_proof,
                    seen_world_edits: BTreeSet::new(),
                }),
                authority_key_from_ed(signer),
                2,
            ),
            signer,
        )
    };
    let holder_mark = mark(&genesis, &old, 1, holder, &holder_key, 1);
    let other_mark = mark(&holder_mark, &old, 2, other, &other_key, 1);
    let world = EntityId::now();
    let edit = |parents: &[&AuthorityLogEntry], machine, key: &SigningKey, read| {
        let mut parents: Vec<_> = parents.iter().map(|&parent| hash(parent)).collect();
        parents.sort();
        sign_ed(
            unsigned_entry(
                Some(id),
                1,
                parents,
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    act: owner_act(EntityId::now(), world),
                    machine,
                    settings: settings(read),
                }),
                authority_key_from_ed(key),
                2,
            ),
            key,
        )
    };
    let kept = edit(
        &[&other_mark],
        holder,
        &holder_key,
        ReadLocation::OneMachine(holder),
    );
    let refused = edit(
        &[&other_mark, &kept],
        other,
        &other_key,
        ReadLocation::Everywhere,
    );
    // The new root marks the other machine again, never the holder.
    let handoff = re_root_entry(id, &other_mark, &old, 3, &next);
    let renewed = mark(&handoff, &next, 1, other, &other_key, 2);
    let entries = [
        genesis,
        holder_mark,
        other_mark,
        kept,
        refused.clone(),
        handoff,
        renewed,
    ];
    let first_seen: BTreeMap<_, _> = entries.iter().map(|entry| (hash(entry), 100)).collect();
    for now in [100, 100 + DEFAULT_STALE_ROSTER_WINDOW_SECS + 1] {
        let fold = fold_authority_log_with_seen_times(&entries, &first_seen, now);
        assert!(fold.refused_world_edits.contains(&hash(&refused)));
        assert_eq!(
            fold.world_privacy(world).read,
            EffectiveRead::OneMachine(holder)
        );
        assert!(!fold.world_readable_on(world, Destination::Machine(other)));
    }
    let after = fold_authority_log_with_seen_times(
        &entries,
        &first_seen,
        100 + DEFAULT_STALE_ROSTER_WINDOW_SECS + 1,
    );
    assert!(
        after
            .machine(holder)
            .is_some_and(|folded| folded.head().stale)
    );
    assert!(after.machine(other).is_some_and(RosterHead::mine));
}

/// A refused edit stays refused when a machine whose edit it would have
/// contended with goes stale here. B's pick of A replaced the conflict between
/// B and C, so C's later widening is refused; weakening B's edits on one
/// install brings the conflict back into the settings it reads, but who may
/// edit is judged on the roster rule's read, so C never becomes a contender
/// there (Sol P2 round 4, F1).
#[test]
fn a_conflict_weakened_back_never_accepts_a_refused_edit() {
    let old = ed_key(130);
    let next = ed_key(131);
    let genesis = genesis_entry(130, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let (a, a_key) = (EntityId::now(), ed_key(132));
    let (b, b_key) = (EntityId::now(), ed_key(133));
    let (c, c_key) = (EntityId::now(), ed_key(134));
    let mark = |parent: &AuthorityLogEntry, signer: &SigningKey, seq, machine, key, revision| {
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
                    revision,
                    machine_proof: request.machine_proof,
                    seen_world_edits: BTreeSet::new(),
                }),
                authority_key_from_ed(signer),
                2,
            ),
            signer,
        )
    };
    let a_mark = mark(&genesis, &old, 1, a, &a_key, 1);
    let b_mark = mark(&a_mark, &old, 2, b, &b_key, 1);
    let c_mark = mark(&b_mark, &old, 3, c, &c_key, 1);
    let world = EntityId::now();
    let edit = |parents: &[&AuthorityLogEntry], seq, machine, key: &SigningKey, read| {
        let mut parents: Vec<_> = parents.iter().map(|&parent| hash(parent)).collect();
        parents.sort();
        sign_ed(
            unsigned_entry(
                Some(id),
                seq,
                parents,
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    act: owner_act(EntityId::now(), world),
                    machine,
                    settings: settings(read),
                }),
                authority_key_from_ed(key),
                2,
            ),
            key,
        )
    };
    let b_pick = edit(&[&c_mark], 1, b, &b_key, ReadLocation::OneMachine(b));
    let c_pick = edit(&[&c_mark], 1, c, &c_key, ReadLocation::OneMachine(c));
    let repick = edit(
        &[&c_mark, &b_pick, &c_pick],
        2,
        b,
        &b_key,
        ReadLocation::OneMachine(a),
    );
    let refused = edit(&[&c_mark, &repick], 2, c, &c_key, ReadLocation::Everywhere);
    // The new root marks A and C again, never B.
    let handoff = re_root_entry(id, &c_mark, &old, 4, &next);
    let renewed_a = mark(&handoff, &next, 1, a, &a_key, 2);
    let renewed_c = mark(&renewed_a, &next, 2, c, &c_key, 2);
    let entries = [
        genesis,
        a_mark,
        b_mark,
        c_mark,
        b_pick,
        c_pick,
        repick,
        refused.clone(),
        handoff,
        renewed_a,
        renewed_c,
    ];
    let first_seen: BTreeMap<_, _> = entries.iter().map(|entry| (hash(entry), 100)).collect();
    for now in [100, 100 + DEFAULT_STALE_ROSTER_WINDOW_SECS + 1] {
        let fold = fold_authority_log_with_seen_times(&entries, &first_seen, now);
        assert!(fold.refused_world_edits.contains(&hash(&refused)));
        assert_eq!(fold.world_roster_read(world), EffectiveRead::OneMachine(a));
        assert_eq!(fold.world_edit_standing(c, world), None);
        assert_eq!(
            fold.world_edit_standing(a, world),
            Some(WorldEditStanding::Holds)
        );
        assert!(!fold.world_readable_on(world, Destination::Machine(c)));
    }
    let after = fold_authority_log_with_seen_times(
        &entries,
        &first_seen,
        100 + DEFAULT_STALE_ROSTER_WINDOW_SECS + 1,
    );
    assert!(after.machine(b).is_some_and(|folded| folded.head().stale));
    // Here B's edits only narrow, so the world reads as the conflict again:
    // stricter than A alone, and readable nowhere.
    assert_eq!(
        after.world_privacy(world).read,
        EffectiveRead::Conflicted {
            contenders: BTreeSet::from([a, b, c]),
        }
    );
}

/// A narrowing made above a main-log row the fold later refuses stays. The
/// laptop signed it on a head the old root signed outside its own handoff, so
/// the handoff's fence refuses that row and settlement drops everything above
/// it; the edit is judged again with the row crossed, and the owner can still
/// change the world after it (Wonder P2 round 1, W1).
#[test]
fn a_narrowing_above_a_fenced_row_stays() {
    let old = ed_key(135);
    let next = ed_key(136);
    let genesis = genesis_entry(135, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let (laptop, laptop_key) = (EntityId::now(), ed_key(137));
    let (other, other_key) = (EntityId::now(), ed_key(138));
    let mark = |parent: &AuthorityLogEntry, seq, machine, key| {
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
                authority_key_from_ed(&old),
                2,
            ),
            &old,
        )
    };
    let laptop_mark = mark(&genesis, 1, laptop, &laptop_key);
    let handoff = re_root_entry(id, &laptop_mark, &old, 2, &next);
    let fenced = mark(&laptop_mark, 3, other, &other_key);
    let world = EntityId::now();
    let edit = |parents: &[&AuthorityLogEntry], seq, read| {
        let mut parents: Vec<_> = parents.iter().map(|&parent| hash(parent)).collect();
        parents.sort();
        sign_ed(
            unsigned_entry(
                Some(id),
                seq,
                parents,
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    act: owner_act(EntityId::now(), world),
                    machine: laptop,
                    settings: settings(read),
                }),
                authority_key_from_ed(&laptop_key),
                2,
            ),
            &laptop_key,
        )
    };
    let narrow = edit(&[&fenced], 1, ReadLocation::OneMachine(laptop));
    let mut entries = vec![
        genesis,
        laptop_mark,
        handoff.clone(),
        fenced.clone(),
        narrow.clone(),
    ];
    let fold = fold_authority_log(&entries);
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::RetiredSigner(hash(&fenced)))
    );
    assert!(fold.valid_entries.contains(&hash(&narrow)));
    assert_eq!(
        fold.world_privacy(world).read,
        EffectiveRead::OneMachine(laptop)
    );
    assert!(!fold.world_readable_on(world, Destination::Unknown));
    assert_eq!(
        fold.worlds[&world]
            .live
            .keys()
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([hash(&narrow)])
    );

    // Past the handoff the laptop names the narrowing as its side head and
    // widens the world again.
    let reopen = edit(&[&handoff, &narrow], 2, ReadLocation::Everywhere);
    entries.push(reopen.clone());
    let fold = fold_authority_log(&entries);
    assert!(fold.valid_entries.contains(&hash(&reopen)));
    assert_eq!(fold.world_privacy(world).read, EffectiveRead::Everywhere);

    // A replica that held the fenced row before it settled the handoff still
    // stores the narrowing, and keeps it (Wonder P2 round 1, W4).
    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    for entry in [&entries[0], &entries[1], &fenced, &handoff, &narrow] {
        store(&replica, entry);
    }
    assert_eq!(
        replica.world_privacy(world).unwrap().read,
        EffectiveRead::OneMachine(laptop)
    );
}

/// A world edit above a row whose parents belong to two vaults folds
/// without a panic: such a row is never crossed, and the fold reads the
/// conflicting roots (Sol P2 round 5, F6).
#[test]
fn a_world_edit_above_a_two_vault_row_folds_closed() {
    let root = ed_key(155);
    let first = genesis_entry(155, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let second = genesis_entry(156, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&first).unwrap();
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let mut parents = vec![hash(&first), hash(&second)];
    parents.sort();
    let joined = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            parents,
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Software,
            },
            authority_key_from_ed(&root),
            2,
        ),
        &root,
    );
    let key = ed_key(157);
    let world = EntityId::now();
    let edit = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![hash(&joined)],
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                act: owner_act(EntityId::now(), world),
                machine: EntityId::now(),
                settings: settings(ReadLocation::Everywhere),
            }),
            authority_key_from_ed(&key),
            2,
        ),
        &key,
    );
    let fold = fold_authority_log(&[first, second, joined.clone(), edit.clone()]);
    assert!(fold.vault_root_is_conflicted());
    assert!(!fold.valid_entries.contains(&hash(&joined)));
    assert!(!fold.valid_entries.contains(&hash(&edit)));
}

/// A mark that still says "yours" acknowledges no edit when its signer turns
/// out to be in a host's custody: on a hosted fold the edit it lists raced
/// that loss of standing, and only narrows (Sol P2 round 3, F2). The DAG is
/// the custody one of `custody_marked_on_another_branch_reaches_the_successor`.
#[test]
fn a_custodial_mark_acknowledges_no_widening() {
    let root = ed_key(120);
    let genesis = genesis_entry(120, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let (custodied, admitted, successor) = (ed_key(121), ed_key(122), ed_key(123));
    let ordinary = |key: &SigningKey| {
        device(
            authority_key_from_ed(key),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
        )
    };
    let entry = |seq,
                 parents: &[&AuthorityLogEntry],
                 op,
                 signer: &SigningKey,
                 cosigner: Option<&SigningKey>| {
        let mut parents: Vec<_> = parents.iter().map(|&parent| hash(parent)).collect();
        parents.sort();
        let unsigned = unsigned_entry(Some(id), seq, parents, op, authority_key_from_ed(signer), 2);
        match cosigner {
            Some(cosigner) => cosign_ed(unsigned, signer, cosigner),
            None => sign_ed(unsigned, signer),
        }
    };
    let plain = entry(
        1,
        &[&genesis],
        AuthorityOp::EnrollDevice {
            device: ordinary(&custodied),
        },
        &root,
        None,
    );
    let marked = entry(
        2,
        &[&genesis],
        AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&custodied),
                ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                AuthorityTier::CloudCustodial,
            ),
        },
        &root,
        None,
    );
    let enrolled = entry(
        1,
        &[&plain],
        AuthorityOp::EnrollDevice {
            device: ordinary(&admitted),
        },
        &custodied,
        Some(&root),
    );
    let (machine, machine_key) = (EntityId::now(), ed_key(124));
    let request = request_for(id, machine, &machine_key);
    let profile = |revision, seen_world_edits| {
        AuthorityOp::MachineProfile(MachineProfile {
            machine,
            owner: EntityId::now(),
            machine_key: request.machine_key,
            encryption_key: request.encryption_key.clone(),
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision,
            machine_proof: request.machine_proof,
            seen_world_edits,
        })
    };
    let mark = entry(
        1,
        &[&enrolled],
        profile(1, BTreeSet::new()),
        &admitted,
        None,
    );
    let world = EntityId::now();
    let edit = |seq, parents: &[&AuthorityLogEntry], read| {
        let mut parents: Vec<_> = parents.iter().map(|&parent| hash(parent)).collect();
        parents.sort();
        sign_ed(
            unsigned_entry(
                Some(id),
                seq,
                parents,
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    act: owner_act(EntityId::now(), world),
                    machine,
                    settings: settings(read),
                }),
                authority_key_from_ed(&machine_key),
                2,
            ),
            &machine_key,
        )
    };
    let narrow = edit(1, &[&mark], ReadLocation::MyMachines);
    let widen = edit(2, &[&mark, &narrow], ReadLocation::Everywhere);
    // The same key marks the machine again, listing the widening, before the
    // branches meet.
    let acknowledged = entry(
        2,
        &[&mark],
        profile(2, BTreeSet::from([hash(&widen)])),
        &admitted,
        None,
    );
    let joining = entry(
        3,
        &[&marked, &acknowledged],
        AuthorityOp::ReRoot {
            new_device: ordinary(&successor),
        },
        &admitted,
        Some(&root),
    );
    let entries = [
        genesis,
        plain,
        marked,
        enrolled,
        mark,
        narrow,
        widen.clone(),
        acknowledged,
        joining.clone(),
    ];
    let fold = fold_authority_log_for_posture(
        &entries,
        &BTreeMap::new(),
        10,
        &BTreeMap::new(),
        crate::HostingPrivacyPosture::Hosted,
    );
    for accepted in [&joining, &widen] {
        assert!(fold.valid_entries.contains(&hash(accepted)));
    }
    let folded = fold.machine(machine).unwrap().head();
    assert_eq!(folded.signer_class, SignerClass::Custodial);
    assert!(folded.profile.seen_world_edits.contains(&hash(&widen)));
    assert_eq!(fold.world_privacy(world).read, EffectiveRead::MyMachines);

    // A removal on the marking branch, before that branch meets the custody,
    // took away a mark that did not stand: once the custody is found it
    // acknowledges nothing (Wonder P2 round 2, W2). The handoff that joins
    // the branches takes the removal into its line (Sol P2 round 6, F1).
    let removal = entry(
        3,
        &[&entries[7]],
        AuthorityOp::MachineProfile(MachineProfile {
            role: MachineRole::Removed,
            revision: 3,
            ..match profile(3, BTreeSet::from([hash(&widen)])) {
                AuthorityOp::MachineProfile(profile) => profile,
                _ => unreachable!(),
            }
        }),
        &admitted,
        None,
    );
    let joined = entry(
        4,
        &[&entries[2], &removal],
        AuthorityOp::ReRoot {
            new_device: ordinary(&successor),
        },
        &admitted,
        Some(&root),
    );
    let mut removed = entries[..8].to_vec();
    removed.extend([removal.clone(), joined.clone()]);
    let fold = fold_authority_log_for_posture(
        &removed,
        &BTreeMap::new(),
        10,
        &BTreeMap::new(),
        crate::HostingPrivacyPosture::Hosted,
    );
    for accepted in [&removal, &joined, &widen] {
        assert!(fold.valid_entries.contains(&hash(accepted)));
    }
    assert_eq!(
        fold.machine(machine).unwrap().head().profile.role,
        MachineRole::Removed
    );
    assert_eq!(fold.world_privacy(world).read, EffectiveRead::MyMachines);
    assert!(!fold.world_readable_on(world, Destination::Unknown));
}

/// A removal never acknowledges a widening through a "yours" revision that
/// turns out to have a divergent sibling: neither one the widening was signed
/// under nor one the removal took away (the widening signed before the
/// siblings). It narrows whoever removes the machine and whatever the removal
/// lists: the owner's door once both siblings are in, crafted on both, or
/// signed on one sibling before the other arrives (Wonder P2 round 2, W2;
/// round 3, W2; Sol P2 round 7, F2; round 8, F2).
#[test]
fn a_removal_of_a_conflicted_mark_never_acknowledges_a_widening() {
    for (removal, widen_first) in ["door", "crafted", "on one sibling"]
        .into_iter()
        .flat_map(|removal| [(removal, false), (removal, true)])
    {
        let host = host();
        let world = world_row(&host);
        let (laptop, laptop_key) =
            other_machine(&host, 86, MachineRole::Owned(MachineOwnership::Yours));
        let narrow = edit_by(
            &host,
            laptop,
            &laptop_key,
            world,
            settings(ReadLocation::OneMachine(laptop)),
        );
        land(&host, std::slice::from_ref(&narrow));
        let first = edit_by(
            &host,
            laptop,
            &laptop_key,
            world,
            settings(ReadLocation::Everywhere),
        );
        let fold = host.vault.authority_fold().unwrap();
        let current = fold.machine(laptop).unwrap().head().profile.clone();
        let sibling = |seen_world_edits| {
            let profile = MachineProfile {
                revision: current.revision + 1,
                seen_world_edits,
                ..current.clone()
            };
            next_entry(&host.issuer, &fold, AuthorityOp::MachineProfile(profile), 3).unwrap()
        };
        let siblings = [
            sibling(BTreeSet::new()),
            sibling(BTreeSet::from([authority_entry_hash(&narrow).unwrap()])),
        ];
        land(&host, &siblings);
        // The laptop widens before the siblings, or on one of them, where it
        // is still the owner's.
        let mut parents: Vec<_> = [&siblings[0], &narrow]
            .map(|entry| authority_entry_hash(entry).unwrap())
            .into();
        parents.sort();
        let on_sibling = sign_ed(
            unsigned_entry(
                fold.vault_id,
                2,
                parents,
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    act: owner_act(host.owner.actor(), world),
                    machine: laptop,
                    settings: settings(ReadLocation::Everywhere),
                }),
                authority_key_from_ed(&laptop_key),
                3,
            ),
            &laptop_key,
        );
        let widen = if widen_first { first } else { on_sibling };
        let seen = BTreeSet::from([authority_entry_hash(&widen).unwrap()]);
        land(&host, std::slice::from_ref(&widen));
        assert!(
            host.vault
                .authority_fold()
                .unwrap()
                .valid_entries
                .contains(&authority_entry_hash(&widen).unwrap())
        );
        assert!(
            host.vault
                .authority_fold()
                .unwrap()
                .machine(laptop)
                .unwrap()
                .head()
                .conflicted
        );
        assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(laptop));

        let fold = host.vault.authority_fold().unwrap();
        let current = fold.machine(laptop).unwrap().head().profile.clone();
        let profile = AuthorityOp::MachineProfile(MachineProfile {
            role: MachineRole::Removed,
            revision: current.revision + 1,
            seen_world_edits: seen,
            ..current
        });
        match removal {
            "door" => {
                host.vault
                    .set_machine_role(&host.issuer, &host.owner, laptop, MachineRole::Removed)
                    .unwrap();
            }
            "crafted" => land(
                &host,
                &[next_entry(&host.issuer, &fold, profile, 4).unwrap()],
            ),
            _ => land(
                &host,
                &[host
                    .issuer
                    .sign_entry(
                        fold.vault_id,
                        fold.append_sequences[&host.issuer.public_key()] + 1,
                        vec![authority_entry_hash(&siblings[0]).unwrap()],
                        profile,
                        4,
                    )
                    .unwrap()],
            ),
        }
        let fold = host.vault.authority_fold().unwrap();
        assert_eq!(
            fold.machine(laptop).unwrap().head().profile.role,
            MachineRole::Removed
        );
        assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(laptop));
        assert!(!fold.world_readable_on(world, Destination::Unknown));
    }
}

/// A removal keeps a widening it never saw narrow, though a branch that never
/// saw the removal marked the machine "yours" again and removed it having
/// seen the widening (Sol P2 round 6, F3), after a demotion of its own (round
/// 7, F4), or though a "yours" text follows the removal (round 7, F3).
#[test]
fn a_removal_keeps_its_race_over_a_later_mark_it_never_saw() {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let work = MachineRole::Owned(MachineOwnership::WorkSchool);
    let removed = MachineRole::Removed;
    for (roles, marked_again) in [
        ([yours, yours, removed], false),
        ([work, yours, removed], false),
        ([yours, yours, removed], true),
    ] {
        let host = host();
        let world = world_row(&host);
        let (laptop, laptop_key) = other_machine(&host, 89, yours);
        land(
            &host,
            &[edit_by(
                &host,
                laptop,
                &laptop_key,
                world,
                settings(ReadLocation::MyMachines),
            )],
        );
        let before = host.vault.authority_fold().unwrap();
        let widen = edit_by(
            &host,
            laptop,
            &laptop_key,
            world,
            settings(ReadLocation::Everywhere),
        );
        host.vault
            .set_machine_role(&host.issuer, &host.owner, laptop, removed)
            .unwrap();
        land(&host, std::slice::from_ref(&widen));
        if marked_again {
            let fold = host.vault.authority_fold().unwrap();
            let current = fold.machine(laptop).unwrap().head().profile.clone();
            let profile = MachineProfile {
                role: yours,
                revision: current.revision + 1,
                ..current
            };
            land(
                &host,
                &[
                    next_entry(&host.issuer, &fold, AuthorityOp::MachineProfile(profile), 3)
                        .unwrap(),
                ],
            );
        }
        assert_eq!(read_of(&host, world), EffectiveRead::MyMachines);

        // The other branch, from before the removal.
        let mut seq =
            host.vault.authority_fold().unwrap().append_sequences[&host.issuer.public_key()];
        let mut parents: Vec<_> = before.append_heads.iter().copied().collect();
        let current = before.machine(laptop).unwrap().head().profile.clone();
        let seen = BTreeSet::from([authority_entry_hash(&widen).unwrap()]);
        let mut branch = Vec::new();
        for (revision, role) in (2..).zip(roles) {
            seq += 1;
            let profile = MachineProfile {
                role,
                revision,
                seen_world_edits: seen.clone(),
                ..current.clone()
            };
            let entry = host
                .issuer
                .sign_entry(
                    before.vault_id,
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
        let fold = host.vault.authority_fold().unwrap();
        for entry in &branch {
            assert!(
                fold.valid_entries
                    .contains(&authority_entry_hash(entry).unwrap())
            );
        }
        assert_eq!(fold.machine(laptop).unwrap().head().profile.revision, 4);
        assert_eq!(read_of(&host, world), EffectiveRead::MyMachines);
        assert!(!fold.world_readable_on(world, Destination::Unknown));
    }
}

/// A demotion the widening's mark never followed keeps it narrow, though the
/// stolen laptop names that demotion among the widening's parents: one branch
/// marks the laptop "yours" again, another demotes it, the thief widens on
/// both, and the owner's removal lists the widening (Wonder P2 round 5, W1).
#[test]
fn a_widening_never_exempts_a_demotion_its_mark_never_followed() {
    let host = host();
    let world = world_row(&host);
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let (laptop, laptop_key) = other_machine(&host, 91, yours);
    let narrow = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::OneMachine(laptop)),
    );
    land(&host, std::slice::from_ref(&narrow));
    let fold = host.vault.authority_fold().unwrap();
    let mut seq = fold.append_sequences[&host.issuer.public_key()];
    let current = fold.machine(laptop).unwrap().head().profile.clone();
    let mut sign = |parents: Vec<AuthorityEntryHash>, revision, role| {
        seq += 1;
        let profile = MachineProfile {
            role,
            revision,
            seen_world_edits: BTreeSet::new(),
            ..current.clone()
        };
        host.issuer
            .sign_entry(
                fold.vault_id,
                seq,
                parents,
                AuthorityOp::MachineProfile(profile),
                3,
            )
            .unwrap()
    };
    let heads: Vec<_> = fold.append_heads.iter().copied().collect();
    let marked = sign(heads.clone(), 2, yours);
    let marked_again = sign(vec![authority_entry_hash(&marked).unwrap()], 3, yours);
    let demoted = sign(heads, 2, MachineRole::Owned(MachineOwnership::WorkSchool));
    land(&host, &[marked, marked_again.clone(), demoted.clone()]);

    let mut parents: Vec<_> = [&marked_again, &demoted, &narrow]
        .map(|entry| authority_entry_hash(entry).unwrap())
        .into();
    parents.sort();
    let widen = sign_ed(
        unsigned_entry(
            fold.vault_id,
            2,
            parents,
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                act: owner_act(host.owner.actor(), world),
                machine: laptop,
                settings: settings(ReadLocation::Everywhere),
            }),
            authority_key_from_ed(&laptop_key),
            3,
        ),
        &laptop_key,
    );
    land(&host, std::slice::from_ref(&widen));
    assert!(
        host.vault
            .authority_fold()
            .unwrap()
            .valid_entries
            .contains(&authority_entry_hash(&widen).unwrap())
    );
    host.vault
        .set_machine_role(&host.issuer, &host.owner, laptop, MachineRole::Removed)
        .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    let removal = fold.machine(laptop).unwrap().head();
    assert_eq!(removal.profile.role, MachineRole::Removed);
    assert!(
        removal
            .profile
            .seen_world_edits
            .contains(&authority_entry_hash(&widen).unwrap())
    );
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(laptop));
    assert!(!fold.world_readable_on(world, Destination::Unknown));
}
