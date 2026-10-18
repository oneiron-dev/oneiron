//! A restriction still lands past a sequence floor (Astra #1430). A replica
//! that stored a later row of a signer first keeps that signer's earlier
//! world edit and its "yours"-ending revision as restriction only, so every
//! arrival order reads the same narrow world.
use std::collections::{BTreeMap, BTreeSet};

use super::machine_identity::{Host, host, request_for};
use super::support::RosterHead;
use super::support::{authority_key_from_ed, ed_key, owner_act, sign_ed, unsigned_entry};
use super::world_privacy::{
    edit_by, land, other_machine, read_of, settings, stored_entries, world_row,
};
use super::*;
use crate::world_keys::{
    PolicyRevision, WorldKey, WorldKeyBinding, machine_secret, seal_world_key,
};
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
        let put = || replica.put_authority_log_entry(row, TimeRange { start: 3, end: 3 }, 3);
        match put() {
            // No door stores a row no admitter signed (H72), such as a
            // false handoff; the fold's reading of it is the subject here.
            Err(err) if err.kind() == crate::error::ErrorKind::AuthorityLogSignerPending => {
                crate::authority::with_authority_doors_open_for_test(put).unwrap();
            }
            stored => {
                stored.unwrap();
            }
        }
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
                act: owner_act(host.owner.actor(), world),
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
            ..fold.machine(laptop).unwrap().head().profile.clone()
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
    let profile = fold.machine(laptop).unwrap().head().profile.clone();
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
    let profile = fold.machine(laptop).unwrap().head().profile.clone();
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
        let profile = fold.machine(laptop).unwrap().head().profile.clone();
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
                ..fold.machine(desk).unwrap().head().profile.clone()
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
    let profile = fold.machine(laptop).unwrap().head().profile.clone();
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
            ..fold.machine(desk).unwrap().head().profile.clone()
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
            ..fold.machine(laptop).unwrap().head().profile.clone()
        },
    );
    let other = revision(
        &host,
        &fold,
        seq + 2,
        MachineProfile {
            revision: 2,
            ..fold.machine(desk).unwrap().head().profile.clone()
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

/// Astra #1430b, F1: a removal past the floor stays terminal but
/// acknowledges nothing here. The owner removes a machine that narrowed and
/// then widened a world, listing the widening, and a later owner row for
/// another machine reaches one replica first. There the widening keeps no
/// full strength; where the removal arrived first it acknowledges the
/// widening as usual, a fail-closed difference between the orders.
#[test]
fn a_removal_past_the_floor_acknowledges_nothing_here() {
    let Held {
        host,
        world,
        laptop: (laptop, laptop_key),
        desk: (desk, _),
        ..
    } = held(106);
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
    let removal = revision(
        &host,
        &fold,
        seq + 1,
        MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            seen_world_edits: BTreeSet::from([authority_entry_hash(&widening).unwrap()]),
            ..fold.machine(laptop).unwrap().head().profile.clone()
        },
    );
    let other = revision(
        &host,
        &fold,
        seq + 2,
        MachineProfile {
            revision: 2,
            ..fold.machine(desk).unwrap().head().profile.clone()
        },
    );
    let (_dir, replica) = replica_storing(&host, &[&other, &removal]);
    assert!(
        replica.authority_fold().unwrap().machines[&laptop]
            .head()
            .removed
    );
    assert_eq!(
        judged(&replica, world),
        (EffectiveRead::OneMachine(laptop), false)
    );
    let (_dir, replica) = replica_storing(&host, &[&removal, &other]);
    assert_eq!(judged(&replica, world), (EffectiveRead::Everywhere, true));
}

/// A world the owner's desk narrowed to "my machines", and a work laptop that
/// a later owner row marks "yours" past a replica's floor. The laptop then
/// widens the world under that mark.
struct Start {
    host: Host,
    world: EntityId,
    laptop: (EntityId, SigningKey),
    desk: (EntityId, SigningKey),
    mine: AuthorityLogEntry,
    fold: AuthorityFold,
    seq: u64,
}

impl Start {
    fn new(seed: u8) -> Self {
        let host = host();
        let world = world_row(&host);
        let laptop = other_machine(
            &host,
            seed,
            MachineRole::Owned(MachineOwnership::WorkSchool),
        );
        let (desk, desk_key) =
            other_machine(&host, seed + 1, MachineRole::Owned(MachineOwnership::Yours));
        let mine = edit_by(
            &host,
            desk,
            &desk_key,
            world,
            settings(ReadLocation::MyMachines),
        );
        land(&host, std::slice::from_ref(&mine));
        let fold = host.vault.authority_fold().unwrap();
        let seq = fold.append_sequences[&host.issuer.public_key()];
        Self {
            host,
            world,
            laptop,
            desk: (desk, desk_key),
            mine,
            fold,
            seq,
        }
    }

    /// The same start once the host's history holds `rows`.
    fn landed(mut self, rows: &[AuthorityLogEntry]) -> Self {
        if !rows.is_empty() {
            land(&self.host, rows);
        }
        self.fold = self.host.vault.authority_fold().unwrap();
        self.seq = self.fold.append_sequences[&self.host.issuer.public_key()];
        self
    }

    /// `machine` answered `role` at its next revision, having seen `seen`.
    fn answer(
        &self,
        machine: EntityId,
        role: MachineRole,
        bump: u64,
        seen: BTreeSet<AuthorityEntryHash>,
    ) -> AuthorityOp {
        let profile = &self.fold.machine(machine).unwrap().head().profile;
        AuthorityOp::MachineProfile(MachineProfile {
            role,
            revision: profile.revision + bump,
            seen_world_edits: seen,
            ..profile.clone()
        })
    }

    /// The owner's re-root at `seq` on `parents`, to a root named `name`.
    fn re_root(
        &self,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        name: &[u8],
    ) -> AuthorityLogEntry {
        let next = HostSlipIssuer::from_secret(name).unwrap();
        self.owner_row(
            seq,
            parents,
            AuthorityOp::ReRoot {
                new_device: next.root_device(crate::HostingPrivacyPosture::SelfHostLocal),
            },
        )
    }

    fn heads(&self) -> Vec<AuthorityEntryHash> {
        self.fold.append_heads.iter().copied().collect()
    }

    /// The parents of the owner's head at the current sequence: a row signed
    /// on them at that sequence is refused past a later row's floor.
    fn below_heads(&self) -> Vec<AuthorityEntryHash> {
        let heads = self.heads();
        stored_entries(&self.host.vault)
            .into_iter()
            .find(|entry| heads.contains(&hash(entry)) && entry.seq == self.seq)
            .unwrap()
            .parent_hashes
    }

    fn owner_row(
        &self,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        op: AuthorityOp,
    ) -> AuthorityLogEntry {
        self.host
            .issuer
            .sign_entry(Some(self.host.vault_id), seq, parents, op, 2)
            .unwrap()
    }

    /// An owner row that only revokes an unrelated slip.
    fn revoke(&self, seq: u64, parents: Vec<AuthorityEntryHash>, slip: u8) -> AuthorityLogEntry {
        self.owner_row(
            seq,
            parents,
            AuthorityOp::SlipRevoke {
                slip_id: [slip; 32],
            },
        )
    }

    /// The laptop marked "yours" at `revision`.
    fn yours(&self, revision: u64) -> MachineProfile {
        MachineProfile {
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision,
            ..self
                .fold
                .machine(self.laptop.0)
                .unwrap()
                .head()
                .profile
                .clone()
        }
    }

    /// The owner's "yours" mark of the laptop at `seq`, on the heads.
    fn mark(&self, seq: u64) -> AuthorityLogEntry {
        revision(&self.host, &self.fold, seq, self.yours(2))
    }

    /// The laptop's widening under `mark`, over the desk's narrowing.
    fn widening(&self, mark: &AuthorityLogEntry) -> AuthorityLogEntry {
        edit_on(
            &self.host,
            (self.laptop.0, &self.laptop.1),
            self.world,
            1,
            vec![hash(mark), hash(&self.mine)],
            ReadLocation::Everywhere,
        )
    }

    /// A replica that stores `rows`, each in a write of its own, before the
    /// handoff `re_root` (`None` is the host's own re-root).
    fn replica(
        self,
        name: &'static str,
        rows: &[&AuthorityLogEntry],
        re_root: Option<AuthorityLogEntry>,
    ) -> MarkPastFloor {
        let (dir, replica) = replica_storing(&self.host, rows);
        MarkPastFloor {
            name,
            world: self.world,
            read: EffectiveRead::MyMachines,
            held: Some(self.laptop.0),
            _dir: dir,
            replica,
            vouch: re_root.into_iter().collect(),
            contested: false,
            host: self.host,
        }
    }
}

fn hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).unwrap()
}

/// A replica holding a row past its floor, and the handoff (or the removal)
/// whose vouch arrives after it.
struct MarkPastFloor {
    name: &'static str,
    host: Host,
    world: EntityId,
    /// What the world reads before the vouch and after it.
    read: EffectiveRead,
    /// A machine not live after the vouch.
    held: Option<EntityId>,
    _dir: tempfile::TempDir,
    replica: Vault,
    /// The rows that bring the vouch, stored in one write; none is the
    /// host's own re-root.
    vouch: Vec<AuthorityLogEntry>,
    /// The vouch leaves its handoffs in conflict, so none of them stands.
    contested: bool,
}

impl MarkPastFloor {
    /// The same replica judged on `world`, which reads `read` throughout,
    /// and with `held` not live after the vouch.
    fn expecting(self, world: EntityId, read: EffectiveRead, held: Option<EntityId>) -> Self {
        Self {
            world,
            read,
            held,
            ..self
        }
    }

    /// The same replica, whose vouch also brings `rows` in its write and
    /// leaves its handoffs in conflict.
    fn contested(mut self, rows: Vec<AuthorityLogEntry>) -> Self {
        self.vouch.extend(rows);
        self.contested = true;
        self
    }

    /// Stores the vouch in a write of its own. A hand-signed re-root must
    /// stand, as a handoff that vouches for its line, unless it is contested.
    fn hand_off(&self) {
        let at = TimeRange { start: 3, end: 3 };
        match self.vouch.as_slice() {
            [] => {
                let next = HostSlipIssuer::from_secret(b"world floor successor root").unwrap();
                self.replica.re_root_host(&self.host.issuer, &next).unwrap();
                return;
            }
            [row] => {
                self.replica.put_authority_log_entry(row, at, 3).unwrap();
            }
            rows => {
                let rows: Vec<_> = rows.iter().map(|row| (row.clone(), at, 3)).collect();
                self.replica.put_authority_log_entries(&rows).unwrap();
            }
        }
        let fold = self.replica.authority_fold().unwrap();
        for row in &self.vouch {
            if matches!(row.op, AuthorityOp::ReRoot { .. }) {
                let stands = fold.valid_entries.contains(&hash(row));
                assert_eq!(stands, !self.contested, "{}", self.name);
            }
        }
    }

    /// The world reads the same before the vouch and after it, never on an
    /// unknown destination, and the held machine is not live after it.
    fn assert_held_through_the_handoff(&self) {
        let held = (self.read.clone(), false);
        assert_eq!(judged(&self.replica, self.world), held, "{}", self.name);
        self.hand_off();
        let fold = self.replica.authority_fold().unwrap();
        if let Some(machine) = self.held {
            assert!(!fold.machines[&machine].head().is_live(), "{}", self.name);
        }
        assert_eq!(judged(&self.replica, self.world), held, "{}", self.name);
    }
}

/// Astra #1430b, F2: a handoff vouches for its line but grants nothing this
/// install held back. A machine marked "yours" past the floor widens a world
/// it holds by the roster rule, and this install reads only the narrowing.
/// An ordinary re-root takes the held mark into its line and carries no
/// revision for the held machine.
fn ordinary_re_root() -> MarkPastFloor {
    let start = Start::new(108);
    let marked = start.mark(start.seq + 1);
    let other = revision(
        &start.host,
        &start.fold,
        start.seq + 2,
        MachineProfile {
            revision: 2,
            ..start
                .fold
                .machine(start.desk.0)
                .unwrap()
                .head()
                .profile
                .clone()
        },
    );
    let widening = start.widening(&marked);
    start.replica("ordinary re-root", &[&other, &marked, &widening], None)
}

/// Wonder P2 round 9, W1: a later owner row arrives first; it descends from
/// the mark and from a row its floor refuses. A re-root over it vouches for
/// that refused row, so the later row's ancestry folds.
fn vouch_over_a_refused_row() -> MarkPastFloor {
    let start = Start::new(110);
    let refused = start.revoke(start.seq, start.below_heads(), 7);
    let marked = start.mark(start.seq + 1);
    let later = start.revoke(start.seq + 3, vec![hash(&marked), hash(&refused)], 8);
    let widening = start.widening(&marked);
    let next = HostSlipIssuer::from_secret(b"world floor vouching root").unwrap();
    let re_root = start.owner_row(
        start.seq + 4,
        vec![hash(&later)],
        AuthorityOp::ReRoot {
            new_device: next.root_device(crate::HostingPrivacyPosture::SelfHostLocal),
        },
    );
    start.replica(
        "vouch over a refused row",
        &[&later, &refused, &marked, &widening],
        Some(re_root),
    )
}

/// Wonder P2 round 10, W1: one later owner row's vouched repair clears a
/// refused row's floor, and a second later row standing on the mark and that
/// row would then fold "unaided".
fn two_step_repair() -> MarkPastFloor {
    let start = Start::new(112);
    let first = start.revoke(start.seq, start.below_heads(), 9);
    let second = start.revoke(start.seq + 1, start.heads(), 10);
    let over_both = start.revoke(start.seq + 3, vec![hash(&second), hash(&first)], 11);
    let marked = start.mark(start.seq + 4);
    let over_mark = start.revoke(start.seq + 5, vec![hash(&marked), hash(&second)], 12);
    let widening = start.widening(&marked);
    let next = HostSlipIssuer::from_secret(b"world floor two-step root").unwrap();
    let re_root = start.owner_row(
        start.seq + 6,
        vec![hash(&over_mark), hash(&over_both)],
        AuthorityOp::ReRoot {
            new_device: next.root_device(crate::HostingPrivacyPosture::SelfHostLocal),
        },
    );
    start.replica(
        "two-step repair",
        &[&over_both, &over_mark, &first, &second, &marked, &widening],
        Some(re_root),
    )
}

/// Sol P2 round 17, F1: an owner row past the floor stands under a later
/// "yours" revision of the laptop, and only a re-root over that revision
/// vouches for the row. The revision then heads the laptop, but the vouch
/// admits it, so it grants nothing here.
fn rescued_successor() -> MarkPastFloor {
    let start = Start::new(114);
    let later = start.revoke(start.seq + 4, start.heads(), 13);
    let refused = start.revoke(start.seq, start.below_heads(), 14);
    let marked = start.mark(start.seq + 1);
    let successor = start.owner_row(
        start.seq + 5,
        vec![hash(&marked), hash(&refused)],
        AuthorityOp::MachineProfile(start.yours(3)),
    );
    let widening = start.widening(&successor);
    let next = HostSlipIssuer::from_secret(b"world floor successor revision root").unwrap();
    let re_root = start.owner_row(
        start.seq + 6,
        vec![hash(&successor), hash(&later)],
        AuthorityOp::ReRoot {
            new_device: next.root_device(crate::HostingPrivacyPosture::SelfHostLocal),
        },
    );
    start.replica(
        "rescued successor",
        &[&later, &refused, &marked, &successor, &widening],
        Some(re_root),
    )
}

/// Sol P2 round 17, F2: a retired tier-floor row in a re-root's line folds
/// only as that handoff's verified ancestry, and the handoff stands only by
/// its vouch. A later owner row over the mark and that tier-floor row must
/// not clear the mark's floor through that permission.
fn retired_permission() -> MarkPastFloor {
    let start = Start::new(116);
    let marked = start.mark(start.seq + 1);
    let tier_floor = start.owner_row(
        start.seq + 2,
        vec![hash(&marked)],
        AuthorityOp::SetTierFloor {
            tier_floor: start.fold.tier_floor.unwrap_or(AuthorityTier::Software),
        },
    );
    let later = start.revoke(start.seq + 3, vec![hash(&tier_floor)], 15);
    let refused = start.revoke(start.seq, start.below_heads(), 16);
    let widening = start.widening(&marked);
    let next = HostSlipIssuer::from_secret(b"world floor permission root").unwrap();
    let re_root = start.owner_row(
        start.seq + 4,
        vec![hash(&later), hash(&refused)],
        AuthorityOp::ReRoot {
            new_device: next.root_device(crate::HostingPrivacyPosture::SelfHostLocal),
        },
    );
    start.replica(
        "retired permission",
        &[&later, &refused, &marked, &tier_floor, &widening],
        Some(re_root),
    )
}

/// Sol P2 round 18, F1, and Wonder P2 round 12, W1 (the demotion past its
/// own floor): the desk holds the world on itself alone, and an owner row
/// only a re-root's vouch admits demotes it. Another machine of the owner's
/// re-picks the world as an orphan over that demotion. With no vouch that
/// edit is valid without effect, so it grants nothing here. Over a false
/// handoff (the Engine's pin): the re-pick stands on a re-root the laptop's
/// key signs, which is no candidate, so nothing after it counts as fresh.
fn refused_repick(
    seed: u8,
    demoted_at: u64,
    re_root_at: u64,
    over_a_false_handoff: bool,
) -> MarkPastFloor {
    let start = Start::new(seed);
    let other = other_machine(
        &start.host,
        seed + 2,
        MachineRole::Owned(MachineOwnership::Yours),
    );
    let desk = start.desk.0;
    let holding = edit_by(
        &start.host,
        desk,
        &start.desk.1,
        start.world,
        settings(ReadLocation::OneMachine(desk)),
    );
    let start = start.landed(std::slice::from_ref(&holding));
    let later = start.revoke(start.seq + 4, start.heads(), seed);
    let refused = start.revoke(start.seq, start.below_heads(), seed + 1);
    let mut parents = start.heads();
    parents.push(hash(&refused));
    let demotion = start.owner_row(
        start.seq + demoted_at,
        parents,
        start.answer(
            desk,
            MachineRole::Owned(MachineOwnership::WorkSchool),
            1,
            BTreeSet::new(),
        ),
    );
    let mut over = hash(&demotion);
    let mut rows = vec![later.clone(), refused, demotion];
    if over_a_false_handoff {
        let key = &start.laptop.1;
        let next = HostSlipIssuer::from_secret(&[seed; 9]).unwrap();
        let false_handoff = sign_ed(
            unsigned_entry(
                Some(start.host.vault_id),
                1,
                vec![over],
                AuthorityOp::ReRoot {
                    new_device: next.root_device(crate::HostingPrivacyPosture::SelfHostLocal),
                },
                authority_key_from_ed(key),
                2,
            ),
            key,
        );
        over = hash(&false_handoff);
        rows.push(false_handoff);
    }
    rows.push(edit_on(
        &start.host,
        (other.0, &other.1),
        start.world,
        1,
        vec![over, hash(&holding)],
        ReadLocation::Everywhere,
    ));
    let re_root = start.re_root(
        start.seq + re_root_at,
        vec![hash(&rows[2]), hash(&later)],
        &[seed; 8],
    );
    let world = start.world;
    let name = if over_a_false_handoff {
        "re-pick over a false handoff"
    } else {
        "refused re-pick"
    };
    start
        .replica(name, &rows.iter().collect::<Vec<_>>(), Some(re_root))
        .expecting(world, EffectiveRead::OneMachine(desk), None)
}

/// Sol P2 round 18, F2: two "yours" revisions of one number leave a machine
/// in conflict, so its widening counts only as narrowing. A removal over a
/// row its floor refuses lists the widening; with no handoff, only the
/// removal's own branch vouch admits it, and it acknowledges nothing here.
fn removal_vouch() -> MarkPastFloor {
    let start = Start::new(126);
    let machine = other_machine(
        &start.host,
        128,
        MachineRole::Owned(MachineOwnership::Yours),
    );
    let widening = edit_by(
        &start.host,
        machine.0,
        &machine.1,
        start.world,
        settings(ReadLocation::Everywhere),
    );
    let start = start.landed(std::slice::from_ref(&widening));
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let seen = BTreeSet::from([hash(&widening)]);
    let quiet = start.owner_row(
        start.seq + 1,
        start.heads(),
        start.answer(machine.0, yours, 1, BTreeSet::new()),
    );
    let listing = start.owner_row(
        start.seq + 2,
        start.heads(),
        start.answer(machine.0, yours, 1, seen.clone()),
    );
    let later = start.revoke(start.seq + 4, start.heads(), 26);
    let refused = start.revoke(start.seq, start.below_heads(), 27);
    let mut parents = start.heads();
    parents.push(hash(&refused));
    let removal = start.owner_row(
        start.seq + 5,
        parents,
        start.answer(machine.0, MachineRole::Removed, 2, seen),
    );
    let world = start.world;
    start
        .replica(
            "removal vouch",
            &[&quiet, &listing, &later, &refused],
            Some(removal),
        )
        .expecting(world, EffectiveRead::MyMachines, Some(machine.0))
}

/// Wonder P2 round 12, W2: the laptop's later "yours" revision lands past
/// the floor and holds it, and a re-root whose line holds the earlier mark
/// and a refused row fences that later revision away. The earlier mark then
/// heads the laptop, but the fold with no vouch holds the laptop.
fn fenced_held_head() -> MarkPastFloor {
    let start = Start::new(130);
    let marked = start.mark(start.seq + 1);
    let widening = start.widening(&marked);
    let later = start.revoke(start.seq + 4, start.heads(), 30);
    let successor = start.owner_row(
        start.seq + 2,
        vec![hash(&marked)],
        AuthorityOp::MachineProfile(start.yours(3)),
    );
    let refused = start.revoke(start.seq, start.below_heads(), 31);
    let over = start.revoke(start.seq + 3, vec![hash(&marked), hash(&refused)], 32);
    let re_root = start.re_root(
        start.seq + 5,
        vec![hash(&over), hash(&later)],
        b"world floor fenced head root",
    );
    start.replica(
        "fenced held head",
        &[&marked, &widening, &later, &successor, &refused, &over],
        Some(re_root),
    )
}

/// The desk narrows a fresh world over its own demotion, which only a
/// re-root's vouch admits. With no vouch the demotion waits and the
/// narrowing stands; with the vouch the desk may no longer edit, the
/// narrowing never stands, and the world would read its default everywhere.
fn voided_narrowing() -> MarkPastFloor {
    let start = Start::new(132);
    let fresh = world_row(&start.host);
    let desk = start.desk.0;
    let later = start.revoke(start.seq + 4, start.heads(), 33);
    let refused = start.revoke(start.seq, start.below_heads(), 34);
    let mut parents = start.heads();
    parents.push(hash(&refused));
    let demotion = start.owner_row(
        start.seq + 5,
        parents,
        start.answer(
            desk,
            MachineRole::Owned(MachineOwnership::WorkSchool),
            1,
            BTreeSet::new(),
        ),
    );
    let narrowing = edit_on(
        &start.host,
        (desk, &start.desk.1),
        fresh,
        2,
        vec![hash(&demotion)],
        ReadLocation::MyMachines,
    );
    let re_root = start.re_root(
        start.seq + 6,
        vec![hash(&demotion), hash(&later)],
        b"world floor voided narrowing root",
    );
    start
        .replica(
            "voided narrowing",
            &[&later, &refused, &demotion, &narrowing],
            Some(re_root),
        )
        .expecting(fresh, EffectiveRead::MyMachines, None)
}

/// The Engine's pin on the exemption (#1430): a handoff left in conflict
/// settles no root, so nothing after it is fresh. The desk narrows a fresh
/// world to itself over its own demotion, which only a re-root's vouch
/// admits. Two re-roots of the one root over that demotion arrive together
/// with another machine's widening after the first of them.
fn contested_handoff() -> MarkPastFloor {
    let start = Start::new(138);
    let other = other_machine(
        &start.host,
        140,
        MachineRole::Owned(MachineOwnership::Yours),
    );
    let start = start.landed(&[]);
    let fresh = world_row(&start.host);
    let desk = start.desk.0;
    let later = start.revoke(start.seq + 4, start.heads(), 38);
    let refused = start.revoke(start.seq, start.below_heads(), 39);
    let mut parents = start.heads();
    parents.push(hash(&refused));
    let demotion = start.owner_row(
        start.seq + 5,
        parents,
        start.answer(
            desk,
            MachineRole::Owned(MachineOwnership::WorkSchool),
            1,
            BTreeSet::new(),
        ),
    );
    let narrowing = edit_on(
        &start.host,
        (desk, &start.desk.1),
        fresh,
        2,
        vec![hash(&demotion)],
        ReadLocation::OneMachine(desk),
    );
    let line = vec![hash(&demotion), hash(&later)];
    let first = start.re_root(
        start.seq + 6,
        line.clone(),
        b"world floor first contested root",
    );
    let second = start.re_root(start.seq + 7, line, b"world floor second contested root");
    let widening = edit_on(
        &start.host,
        (other.0, &other.1),
        fresh,
        1,
        vec![hash(&first)],
        ReadLocation::Everywhere,
    );
    start
        .replica(
            "contested handoff",
            &[&later, &refused, &demotion, &narrowing],
            Some(first),
        )
        .contested(vec![second, widening])
        .expecting(fresh, EffectiveRead::OneMachine(desk), None)
}

/// Every graph a review of #1430's vouch found (Wonder P2 rounds 9-12, Sol P2
/// rounds 17-18), the narrowing a vouched demotion voids, and re-picks over a
/// false and a contested handoff: in each, a vouch rescues a row its floor
/// refuses.
fn vouched_graphs() -> Vec<MarkPastFloor> {
    vec![
        vouch_over_a_refused_row(),
        two_step_repair(),
        rescued_successor(),
        retired_permission(),
        refused_repick(118, 5, 6, false),
        refused_repick(122, 1, 5, false),
        refused_repick(134, 5, 6, true),
        contested_handoff(),
        removal_vouch(),
        fenced_held_head(),
        voided_narrowing(),
    ]
}

#[test]
fn a_re_root_keeps_a_floor_held_mark_held() {
    let graph = ordinary_re_root();
    graph.assert_held_through_the_handoff();
    assert_no_vouch_widens(&graph.replica);
}

#[test]
fn a_re_root_never_repairs_a_floor_held_mark_through_its_vouch() {
    vouch_over_a_refused_row().assert_held_through_the_handoff();
}

#[test]
fn a_re_root_never_repairs_a_floor_held_mark_in_two_steps() {
    two_step_repair().assert_held_through_the_handoff();
}

#[test]
fn a_revision_only_the_vouch_admits_grants_nothing() {
    rescued_successor().assert_held_through_the_handoff();
}

#[test]
fn a_permission_only_the_vouch_gives_repairs_no_floor() {
    retired_permission().assert_held_through_the_handoff();
}

#[test]
fn an_edit_valid_without_effect_gains_none_through_the_vouch() {
    refused_repick(118, 5, 6, false).assert_held_through_the_handoff();
    refused_repick(122, 1, 5, false).assert_held_through_the_handoff();
}

#[test]
fn only_a_standing_handoff_makes_what_follows_it_fresh() {
    refused_repick(134, 5, 6, true).assert_held_through_the_handoff();
}

#[test]
fn a_contested_handoff_makes_nothing_after_it_fresh() {
    contested_handoff().assert_held_through_the_handoff();
}

#[test]
fn a_removal_branch_vouch_acknowledges_nothing() {
    removal_vouch().assert_held_through_the_handoff();
}

#[test]
fn a_fenced_held_head_leaves_its_machine_held() {
    fenced_held_head().assert_held_through_the_handoff();
}

#[test]
fn a_narrowing_a_vouched_demotion_voids_still_narrows() {
    voided_narrowing().assert_held_through_the_handoff();
}

/// Where `vault`'s install view reads wider than the fold with no vouch at
/// all, outside a fresh grant after a handoff (the Engine's rulings on Sol P2
/// rounds 17-18), and whether the vouch changed the fold there at all. Both
/// folds read the same rows, receipts and clock; the one with no vouch runs
/// neither a handoff's vouch nor a removal's. Wider means a world readable on
/// a destination (unknown, or any machine) the other withholds it from, a
/// looser seal or another model order, or a machine live or mine here only.
/// A machine a revision after a handoff heads, and a world only edits after
/// a handoff hold, are fresh grants.
pub(super) fn vouch_widenings(vault: &Vault) -> (bool, Vec<String>) {
    let entries = stored_entries(vault);
    let txn = vault.store.env.read_txn().unwrap();
    let observations = authority_local_observations_in_txn(&vault.store, &txn, &entries).unwrap();
    let fold = |observations: &AuthorityLocalObservations| {
        fold_authority_log_with_local_observations_and_posture(
            &entries,
            &BTreeMap::new(),
            0,
            &BTreeMap::new(),
            observations,
            vault.privacy_posture(),
            None,
        )
    };
    let (vouched, unvouched) = (fold(&observations), fold(&observations.without_vouch()));
    let by_hash: BTreeMap<_, _> = entries.iter().map(|entry| (hash(entry), entry)).collect();
    let after_handoff = |row: &AuthorityEntryHash| {
        let mut stack = by_hash[row].parent_hashes.clone();
        let mut seen = BTreeSet::new();
        while let Some(parent) = stack.pop() {
            let Some(entry) = by_hash.get(&parent).filter(|_| seen.insert(parent)) else {
                continue;
            };
            if matches!(entry.op, AuthorityOp::ReRoot { .. })
                && vouched.valid_entries.contains(&parent)
            {
                return true;
            }
            stack.extend(entry.parent_hashes.iter().copied());
        }
        false
    };
    let fresh = |id: &EntityId| {
        vouched
            .machine(*id)
            .is_some_and(|here| after_handoff(&here.head().entry))
    };
    let mut widened = Vec::new();
    let machines: BTreeSet<_> = vouched
        .machines
        .keys()
        .chain(unvouched.machines.keys())
        .copied()
        .collect();
    for id in machines.iter().filter(|id| !fresh(id)) {
        let Some(here) = vouched.machine(*id) else {
            continue;
        };
        let there = unvouched.machine(*id);
        if here.head().is_live() && !there.is_some_and(|there| there.head().is_live()) {
            widened.push(format!("machine {id:?} live"));
        }
        if here.mine() && !there.is_some_and(RosterHead::mine) {
            widened.push(format!("machine {id:?} mine"));
        }
    }
    let destinations: Vec<_> = std::iter::once(Destination::Unknown)
        .chain(
            machines
                .iter()
                .filter(|id| !fresh(id))
                .map(|id| Destination::Machine(*id)),
        )
        .collect();
    let worlds: BTreeSet<_> = vouched
        .worlds
        .keys()
        .chain(unvouched.worlds.keys())
        .copied()
        .collect();
    for world in &worlds {
        if vouched
            .worlds
            .get(world)
            .is_some_and(|folded| !folded.live.is_empty() && folded.live.keys().all(&after_handoff))
        {
            continue;
        }
        for destination in &destinations {
            if vouched.world_readable_on(*world, *destination)
                && !unvouched.world_readable_on(*world, *destination)
            {
                widened.push(format!("world {world:?} readable on {destination:?}"));
            }
        }
        let (here, there) = (
            vouched.world_privacy(*world),
            unvouched.world_privacy(*world),
        );
        if here.sealed > there.sealed {
            widened.push(format!("world {world:?} sealed {:?}", here.sealed));
        }
        if here.models != there.models && here.models != EffectiveModelOrder::Conflicted {
            widened.push(format!("world {world:?} models {:?}", here.models));
        }
    }
    let changed =
        vouched.valid_entries != unvouched.valid_entries || vouched.machines != unvouched.machines;
    (changed, widened)
}

/// A handoff fixture's install view after its handoffs: no vouch widened it.
pub(super) fn assert_no_vouch_widens(vault: &Vault) {
    let (_, widened) = vouch_widenings(vault);
    assert!(widened.is_empty(), "the vouch widened: {widened:?}");
}

/// The Engine's invariant for #1430 (rulings on Wonder P2 rounds 9-10 and
/// Sol P2 rounds 17-18): a vouch decides only which handoffs stand, which
/// wins and settles, and what the roster view shows, never what this install
/// reads. In every graph above, after its vouch, the install view is no
/// wider than the fold with no vouch anywhere.
#[test]
fn a_vouch_never_widens_the_install_view() {
    let mut widened = Vec::new();
    for graph in vouched_graphs() {
        graph.hand_off();
        let (changed, wider) = vouch_widenings(&graph.replica);
        assert!(changed, "{}: the vouch changed nothing", graph.name);
        widened.extend(
            wider
                .into_iter()
                .map(|row| format!("{}: {row}", graph.name)),
        );
    }
    assert!(widened.is_empty(), "the vouch widened: {widened:?}");
}

/// A record of a fresh key of the start's world, signed by the laptop at its
/// first sequence on `parents` and wrapped to a recovery root alone.
fn laptop_key_record(
    start: &Start,
    parents: Vec<AuthorityEntryHash>,
) -> (AuthorityLogEntry, WorldKeyId) {
    let vault_id = start.host.vault_id;
    let key = WorldKey::mint(start.world, FIRST_GENERATION).unwrap();
    let to = WrapRecipient::RecoveryRoot(RecoveryRootId([9; 32]));
    let binding = WorldKeyBinding {
        vault_id,
        key: *key.id(),
        owner: start.host.owner.actor(),
        policy: PolicyRevision::of([hash(&start.mine)]),
        commitment: key.commitment(),
    };
    let secret = machine_secret(
        &oneiron_keystore::MemoryKeystore::new(),
        vault_id,
        *EntityId::now().as_bytes(),
    )
    .unwrap();
    let envelope = seal_world_key(&binding, to, secret.public_key(), &key).unwrap();
    let record = WorldKeyWrapsRecord {
        key: *key.id(),
        commitment: binding.commitment,
        owner: binding.owner,
        policy: binding.policy,
        machine: start.laptop.0,
        wraps: vec![(to, envelope.to_bytes())],
    };
    let entry = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            parents,
            AuthorityOp::WorldKeyWraps(record),
            authority_key_from_ed(&start.laptop.1),
            2,
        ),
        &start.laptop.1,
    );
    (entry, *key.id())
}

/// The Engine on Astra #1422d, the key-domain negative control: a "yours"
/// revision only a vouch admits, a key record under it, then a removal. The
/// owner revokes slip G, and slip L beside it. P marks the laptop "yours"
/// over G alone, and the laptop records a world key J under P. The owner
/// then removes the laptop over P (D) and re-roots over D and L (H). A
/// replica that stores G before L counts J. One that stores L first keeps G
/// below its floor, so only H's vouch admits G and P: both folds end the
/// laptop's chain at D, but P is held where J stands, and J never counts.
#[test]
fn a_key_record_under_a_revision_only_a_vouch_admits_never_counts() {
    let start = Start::new(142);
    let g = start.revoke(start.seq + 1, start.heads(), 37);
    let l = start.revoke(start.seq + 2, start.heads(), 38);
    let p = start.owner_row(
        start.seq + 3,
        vec![hash(&g)],
        AuthorityOp::MachineProfile(start.yours(2)),
    );
    let (j, key) = laptop_key_record(&start, vec![hash(&p), hash(&start.mine)]);
    let d = start.owner_row(
        start.seq + 4,
        vec![hash(&p)],
        start.answer(start.laptop.0, MachineRole::Removed, 2, BTreeSet::new()),
    );
    let h = start.re_root(
        start.seq + 5,
        vec![hash(&d), hash(&l)],
        b"world floor key control root",
    );
    for (first, counts) in [(&g, true), (&l, false)] {
        let second = if counts { &l } else { &g };
        let (_dir, replica) = replica_storing(&start.host, &[first, second, &p, &j, &d, &h]);
        let fold = replica.authority_fold().unwrap();
        for row in [&g, &l, &p, &j, &d, &h] {
            assert!(fold.valid_entries.contains(&hash(row)), "G first: {counts}");
        }
        assert!(fold.machines[&start.laptop.0].head().removed);
        assert_eq!(fold.world_key(&key).is_some(), counts);
        assert_eq!(!fold.refused_world_keys.contains(&hash(&j)), counts);
    }
}
