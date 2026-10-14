//! A restriction still lands past a sequence floor (Astra #1430). A replica
//! that stored a later row of a signer first keeps that signer's earlier
//! world edit and its "yours"-ending revision as restriction only, so every
//! arrival order reads the same narrow world.
use std::collections::BTreeSet;

use super::machine_identity::{Host, host, request_for};
use super::support::{authority_key_from_ed, ed_key, sign_ed, unsigned_entry};
use super::world_privacy::{edit_by, land, other_machine, read_of, settings, world_row};
use super::*;
use crate::{Vault, VaultConfig};

/// A replica of the host's history so far that then stores `rows` in this
/// order, each in a write of its own, as sync delivers them.
fn replica_storing(host: &Host, rows: &[&AuthorityLogEntry]) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    replica
        .import_signed_authority_history(&host.vault.export_signed_authority_history().unwrap())
        .unwrap();
    for row in rows {
        replica
            .put_authority_log_entry(row, TimeRange { start: 3, end: 3 }, 3)
            .unwrap();
    }
    (dir, replica)
}

/// The world's read on `replica`, and whether an unknown destination may
/// hold it.
fn judged(replica: &Vault, world: EntityId) -> (EffectiveRead, bool) {
    let read = replica.world_privacy(world).unwrap().read;
    let txn = replica.store.env.read_txn().unwrap();
    let readable =
        world_readable_on_machine_in(replica, &txn, world, Destination::Unknown).unwrap();
    (read, readable)
}

/// The owner's revision of a machine at `seq`, on the main-log heads of `fold`.
fn revision(
    host: &Host,
    fold: &AuthorityFold,
    seq: u64,
    profile: MachineProfile,
) -> AuthorityLogEntry {
    host.issuer
        .sign_entry(
            Some(host.vault_id),
            seq,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::MachineProfile(profile),
            2,
        )
        .unwrap()
}

/// A world edit `key` signs as `machine` at `seq` on `parents`.
fn edit_on(
    host: &Host,
    (machine, key): (EntityId, &SigningKey),
    world: EntityId,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    read: ReadLocation,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(host.vault_id),
            seq,
            parents,
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                owner: host.owner.actor(),
                machine,
                settings: settings(read),
            }),
            authority_key_from_ed(key),
            2,
        ),
        key,
    )
}

/// Astra #1430, shape A: a removed machine's key signs a widening at a high
/// sequence. The fold refuses it, but storing it raised that key's floor for
/// the world, and the owner's earlier narrowing arrives after it. The
/// narrowing still lands: both orders read the world on the removed machine
/// alone, withheld from an unknown destination.
#[test]
fn a_narrowing_that_arrives_after_a_refused_row_still_narrows() {
    let host = host();
    let world = world_row(&host);
    let (laptop, laptop_key) =
        other_machine(&host, 91, MachineRole::Owned(MachineOwnership::Yours));
    let narrowing = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::OneMachine(laptop)),
    );
    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()];
    let removal = revision(
        &host,
        &fold,
        seq + 1,
        MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            ..fold.machine(laptop).unwrap().profile.clone()
        },
    );
    let refused = edit_on(
        &host,
        (laptop, &laptop_key),
        world,
        100,
        vec![authority_entry_hash(&removal).unwrap()],
        ReadLocation::Everywhere,
    );
    for (order, rows) in [
        ("narrowing first", [&narrowing, &removal, &refused]),
        ("refused row first", [&removal, &refused, &narrowing]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        assert!(
            !replica
                .authority_fold()
                .unwrap()
                .valid_entries
                .contains(&authority_entry_hash(&refused).unwrap()),
            "{order}"
        );
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false),
            "{order}"
        );
    }
}

/// Astra #1430, shape B: two concurrent owner revisions of a machine that
/// narrowed and then widened a world. A demotion saw only the narrowing; a
/// removal at a higher sequence saw the widening. A replica that stores the
/// removal first still races the widening against the demotion, so in both
/// orders the widening keeps no full strength.
#[test]
fn a_demotion_that_arrives_after_a_removal_still_races_a_widening() {
    let host = host();
    let world = world_row(&host);
    let (laptop, laptop_key) =
        other_machine(&host, 92, MachineRole::Owned(MachineOwnership::Yours));
    let narrowing = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::OneMachine(laptop)),
    );
    land(&host, std::slice::from_ref(&narrowing));
    let widening = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::Everywhere),
    );
    land(&host, std::slice::from_ref(&widening));
    assert_eq!(read_of(&host, world), EffectiveRead::Everywhere);

    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()];
    let profile = fold.machine(laptop).unwrap().profile.clone();
    let demotion = revision(
        &host,
        &fold,
        seq + 1,
        MachineProfile {
            role: MachineRole::Owned(MachineOwnership::WorkSchool),
            revision: 2,
            seen_world_edits: BTreeSet::from([authority_entry_hash(&narrowing).unwrap()]),
            ..profile.clone()
        },
    );
    let removal = revision(
        &host,
        &fold,
        seq + 2,
        MachineProfile {
            role: MachineRole::Removed,
            revision: 3,
            seen_world_edits: BTreeSet::from([authority_entry_hash(&widening).unwrap()]),
            ..profile
        },
    );
    for (order, rows) in [
        ("demotion first", [&demotion, &removal]),
        ("removal first", [&removal, &demotion]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false),
            "{order}"
        );
    }
}

/// Sol P2 round 10, F1: a floor never grants standing. One machine holds a
/// world and hands it on (to the other machine, or everywhere), then signs a
/// refused row at a high sequence. Whether the handover lands in full or past
/// the floor, standing reads it as the roster rule alone does: the first
/// machine's later widening stays a refused no-op, and the other machine's
/// later pick lands, in both orders.
#[test]
fn a_floor_never_grants_a_later_edit_standing() {
    for handed_everywhere in [false, true] {
        let host = host();
        let world = world_row(&host);
        let (first, first_key) =
            other_machine(&host, 93, MachineRole::Owned(MachineOwnership::Yours));
        let (second, second_key) =
            other_machine(&host, 94, MachineRole::Owned(MachineOwnership::Yours));
        let first = (first, &first_key);
        let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
        let heads = host
            .vault
            .authority_fold()
            .unwrap()
            .append_heads
            .into_iter()
            .collect();
        let held = edit_on(
            &host,
            first,
            world,
            1,
            heads,
            ReadLocation::OneMachine(first.0),
        );
        let handover = edit_on(
            &host,
            first,
            world,
            2,
            vec![hash(&held)],
            if handed_everywhere {
                ReadLocation::Everywhere
            } else {
                ReadLocation::OneMachine(second)
            },
        );
        let refused = edit_on(
            &host,
            first,
            world,
            100,
            vec![hash(&held)],
            ReadLocation::OneMachine(EntityId::now()),
        );
        let later = if handed_everywhere {
            edit_on(
                &host,
                (second, &second_key),
                world,
                1,
                vec![hash(&handover)],
                ReadLocation::OneMachine(second),
            )
        } else {
            edit_on(
                &host,
                first,
                world,
                101,
                vec![hash(&handover)],
                ReadLocation::Everywhere,
            )
        };
        for (order, rows) in [
            ("handover first", [&held, &handover, &refused, &later]),
            ("refused row first", [&held, &refused, &handover, &later]),
        ] {
            let (_dir, replica) = replica_storing(&host, &rows);
            let fold = replica.authority_fold().unwrap();
            let (read, readable) = judged(&replica, world);
            assert!(!readable, "{order}");
            if handed_everywhere {
                assert_eq!(read, EffectiveRead::OneMachine(second), "{order}");
            } else {
                assert!(fold.refused_world_edits.contains(&hash(&later)), "{order}");
            }
        }
    }
}

/// A "yours" revision is evidence too. Two concurrent owner re-marks of a
/// machine at one revision diverge, and a removal on one of them lists the
/// machine's widening. A replica that stores the removal before the other
/// re-mark still finds the divergence, so the removal acknowledges nothing
/// and the widening keeps no full strength, in both orders.
#[test]
fn a_divergent_mark_that_arrives_after_a_removal_still_voids_it() {
    let host = host();
    let world = world_row(&host);
    let (laptop, laptop_key) =
        other_machine(&host, 95, MachineRole::Owned(MachineOwnership::Yours));
    let narrowing = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::OneMachine(laptop)),
    );
    land(&host, std::slice::from_ref(&narrowing));
    let widening = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::Everywhere),
    );
    land(&host, std::slice::from_ref(&widening));

    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()];
    let profile = fold.machine(laptop).unwrap().profile.clone();
    let remark = |seq, seen: BTreeSet<AuthorityEntryHash>| {
        revision(
            &host,
            &fold,
            seq,
            MachineProfile {
                revision: 2,
                seen_world_edits: seen,
                ..profile.clone()
            },
        )
    };
    let marked = remark(seq + 1, BTreeSet::new());
    let sibling = remark(
        seq + 2,
        BTreeSet::from([authority_entry_hash(&narrowing).unwrap()]),
    );
    let removal = host
        .issuer
        .sign_entry(
            Some(host.vault_id),
            seq + 3,
            vec![authority_entry_hash(&marked).unwrap()],
            AuthorityOp::MachineProfile(MachineProfile {
                role: MachineRole::Removed,
                revision: 3,
                seen_world_edits: BTreeSet::from([authority_entry_hash(&widening).unwrap()]),
                ..profile.clone()
            }),
            2,
        )
        .unwrap();
    for (order, rows) in [
        ("sibling first", [&marked, &sibling, &removal]),
        ("removal first", [&marked, &removal, &sibling]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false),
            "{order}"
        );
    }
}

/// A world one machine of the owner's holds through `narrowing`, beside
/// another machine of the owner's.
struct Held {
    host: Host,
    world: EntityId,
    laptop: (EntityId, SigningKey),
    desk: (EntityId, SigningKey),
    narrowing: AuthorityLogEntry,
}

fn held(seed: u8) -> Held {
    let host = host();
    let world = world_row(&host);
    let laptop = other_machine(&host, seed, MachineRole::Owned(MachineOwnership::Yours));
    let desk = other_machine(&host, seed + 1, MachineRole::Owned(MachineOwnership::Yours));
    let narrowing = edit_by(
        &host,
        laptop.0,
        &laptop.1,
        world,
        settings(ReadLocation::OneMachine(laptop.0)),
    );
    land(&host, std::slice::from_ref(&narrowing));
    Held {
        host,
        world,
        laptop,
        desk,
        narrowing,
    }
}

/// The owner's revision of a machine at `seq` on `parents`.
fn owner_on(
    host: &Host,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    profile: MachineProfile,
) -> AuthorityLogEntry {
    host.issuer
        .sign_entry(
            Some(host.vault_id),
            seq,
            parents,
            AuthorityOp::MachineProfile(profile),
            2,
        )
        .unwrap()
}

/// Sol P2 round 13 F1 and Wonder round 7 W1: a "yours" revision past the
/// floor still heads its machine by the roster rule. Two concurrent owner
/// re-marks diverge; a demotion over one of them lists the machine's
/// widening, or the widening is signed under one of them. A replica that
/// stored a later owner row first takes both re-marks past its floor and
/// still finds the demotion replaced, or the widening was signed under, a
/// mark that does not stand: the widening only narrows, in both orders.
#[test]
fn a_demotion_over_a_divergent_mark_past_the_floor_acknowledges_nothing() {
    for signed_under_remark in [false, true] {
        let Held {
            host,
            world,
            laptop: (laptop, laptop_key),
            desk: (desk, _),
            narrowing,
        } = held(97);
        let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
        let landed = (!signed_under_remark).then(|| {
            let widening = edit_by(
                &host,
                laptop,
                &laptop_key,
                world,
                settings(ReadLocation::Everywhere),
            );
            land(&host, std::slice::from_ref(&widening));
            widening
        });
        let fold = host.vault.authority_fold().unwrap();
        let seq = fold.append_sequences[&host.issuer.public_key()];
        let heads: Vec<_> = fold.append_heads.iter().copied().collect();
        let profile = fold.machine(laptop).unwrap().profile.clone();
        let remark = |seq, seen| {
            owner_on(
                &host,
                seq,
                heads.clone(),
                MachineProfile {
                    revision: 2,
                    seen_world_edits: seen,
                    ..profile.clone()
                },
            )
        };
        let marked = remark(seq + 1, BTreeSet::new());
        let sibling = remark(seq + 2, BTreeSet::from([hash(&narrowing)]));
        let other = owner_on(
            &host,
            seq + 3,
            heads.clone(),
            MachineProfile {
                revision: 2,
                ..fold.machine(desk).unwrap().profile.clone()
            },
        );
        let widening = landed.unwrap_or_else(|| {
            edit_on(
                &host,
                (laptop, &laptop_key),
                world,
                fold.append_sequences[&authority_key_from_ed(&laptop_key)] + 1,
                vec![hash(&marked), hash(&narrowing)],
                ReadLocation::Everywhere,
            )
        });
        let demotion = owner_on(
            &host,
            seq + 4,
            if signed_under_remark {
                heads.clone()
            } else {
                vec![hash(&marked)]
            },
            MachineProfile {
                role: MachineRole::Owned(MachineOwnership::WorkSchool),
                revision: 3,
                seen_world_edits: BTreeSet::from([hash(&widening)]),
                ..profile.clone()
            },
        );
        let mut in_order = vec![&marked, &sibling, &other];
        let mut other_first = vec![&other, &marked, &sibling];
        for rows in [&mut in_order, &mut other_first] {
            if signed_under_remark {
                rows.push(&widening);
            }
            rows.push(&demotion);
        }
        for (order, rows) in [("in order", in_order), ("other first", other_first)] {
            let (_dir, replica) = replica_storing(&host, &rows);
            assert_eq!(
                judged(&replica, world),
                (EffectiveRead::OneMachine(laptop), false),
                "{order}, signed under the re-mark: {signed_under_remark}"
            );
        }
    }
}

/// Sol P2 round 13 F2 and Wonder round 7 W2: a revision past the floor still
/// bounds the machine's next revision number. A demotion reusing a re-mark's
/// number over it is invalid without a floor, and invalid past one too, so
/// the world is never orphaned for the other machine's widening re-pick, in
/// both orders.
#[test]
fn a_revision_past_the_floor_still_bounds_the_next_number() {
    let Held {
        host,
        world,
        laptop: (laptop, _),
        desk: (desk, desk_key),
        narrowing,
    } = held(99);
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()];
    let heads: Vec<_> = fold.append_heads.iter().copied().collect();
    let profile = fold.machine(laptop).unwrap().profile.clone();
    let marked = owner_on(
        &host,
        seq + 1,
        heads.clone(),
        MachineProfile {
            revision: 2,
            ..profile.clone()
        },
    );
    let other = owner_on(
        &host,
        seq + 3,
        heads,
        MachineProfile {
            revision: 2,
            ..fold.machine(desk).unwrap().profile.clone()
        },
    );
    let demotion = owner_on(
        &host,
        seq + 4,
        vec![hash(&marked), hash(&other)],
        MachineProfile {
            role: MachineRole::Owned(MachineOwnership::WorkSchool),
            revision: 2,
            ..profile
        },
    );
    let repick = edit_on(
        &host,
        (desk, &desk_key),
        world,
        1,
        vec![hash(&demotion), hash(&narrowing)],
        ReadLocation::Everywhere,
    );
    for (order, rows) in [
        ("in order", [&marked, &other, &demotion, &repick]),
        ("other first", [&other, &marked, &demotion, &repick]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false),
            "{order}"
        );
    }
}

/// Engine ruling on Astra #1430: a re-key past the floor still poisons. The
/// owner re-marks a machine under a second install key, and a later owner
/// row reaches one replica first. A machine whose revisions named two keys
/// is live under neither, so on both replicas a connection proved under
/// either key speaks for no machine.
#[test]
fn a_rekey_past_the_floor_leaves_both_keys_unknown() {
    let Held {
        host,
        laptop: (laptop, first),
        desk: (desk, _),
        ..
    } = held(103);
    let second = ed_key(105);
    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()];
    let request = request_for(host.vault_id, laptop, &second);
    let rekey = revision(
        &host,
        &fold,
        seq + 1,
        MachineProfile {
            machine_key: request.machine_key,
            machine_proof: request.machine_proof,
            revision: 2,
            ..fold.machine(laptop).unwrap().profile.clone()
        },
    );
    let other = revision(
        &host,
        &fold,
        seq + 2,
        MachineProfile {
            revision: 2,
            ..fold.machine(desk).unwrap().profile.clone()
        },
    );
    let transcript = machine_connection_transcript(&host.vault_id, laptop, "token", 7, "nonce");
    for (order, rows) in [
        ("re-key first", [&rekey, &other]),
        ("other first", [&other, &rekey]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        for key in [&first, &second] {
            let proved = replica
                .verify_machine_connection_proof(
                    laptop,
                    &key.sign(&transcript).to_bytes(),
                    "token",
                    7,
                    "nonce",
                )
                .unwrap();
            assert_eq!(proved, PeerMachine::Unknown, "{order}");
        }
    }
}
