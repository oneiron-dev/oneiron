//! A restriction still lands past a sequence floor (Astra #1430). A replica
//! that stored a later row of a signer first keeps that signer's earlier
//! world edit and its "yours"-ending revision as restriction only, so every
//! arrival order reads the same narrow world.
use std::collections::{BTreeMap, BTreeSet};

use super::super::install_fold::floor_marks_of;
use super::machine_identity::{Host, host, request_for};
use super::support::{authority_key_from_ed, ed_key, sign_ed, unsigned_entry};
use super::world_privacy::{
    edit_by, land, other_machine, read_of, settings, stored_entries, world_row,
};
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
    let (_dir, replica) = replica_storing(&host, &[&other, &removal]);
    assert!(replica.authority_fold().unwrap().machines[&laptop].removed);
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
    desk: EntityId,
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
            desk,
            mine,
            fold,
            seq,
        }
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

    /// The owner's "yours" mark of the laptop at `seq`, on the heads.
    fn mark(&self, seq: u64) -> AuthorityLogEntry {
        revision(
            &self.host,
            &self.fold,
            seq,
            MachineProfile {
                role: MachineRole::Owned(MachineOwnership::Yours),
                revision: 2,
                ..self.fold.machine(self.laptop.0).unwrap().profile.clone()
            },
        )
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
            laptop: self.laptop.0,
            _dir: dir,
            replica,
            re_root,
            host: self.host,
        }
    }
}

fn hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).unwrap()
}

/// A replica holding the laptop's mark past its floor, and the handoff that
/// arrives after it.
struct MarkPastFloor {
    name: &'static str,
    host: Host,
    world: EntityId,
    laptop: EntityId,
    _dir: tempfile::TempDir,
    replica: Vault,
    re_root: Option<AuthorityLogEntry>,
}

impl MarkPastFloor {
    /// Stores the handoff in a write of its own. A hand-signed re-root must
    /// stand, as a handoff that vouches for its line.
    fn hand_off(&self) {
        let Some(re_root) = &self.re_root else {
            let next = HostSlipIssuer::from_secret(b"world floor successor root").unwrap();
            self.replica.re_root_host(&self.host.issuer, &next).unwrap();
            return;
        };
        self.replica
            .put_authority_log_entry(re_root, TimeRange { start: 3, end: 3 }, 3)
            .unwrap();
        let fold = self.replica.authority_fold().unwrap();
        assert!(fold.valid_entries.contains(&hash(re_root)), "{}", self.name);
    }

    /// The world reads the narrowing before the handoff and after it, and
    /// the laptop is not live after it.
    fn assert_held_through_the_handoff(&self) {
        let held = (EffectiveRead::MyMachines, false);
        assert_eq!(judged(&self.replica, self.world), held);
        self.hand_off();
        let fold = self.replica.authority_fold().unwrap();
        assert!(!fold.machines[&self.laptop].is_live());
        assert_eq!(judged(&self.replica, self.world), held);
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
            ..start.fold.machine(start.desk).unwrap().profile.clone()
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
            new_device: next.root_device(),
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
            new_device: next.root_device(),
        },
    );
    start.replica(
        "two-step repair",
        &[&over_both, &over_mark, &first, &second, &marked, &widening],
        Some(re_root),
    )
}

#[test]
fn a_re_root_keeps_a_floor_held_mark_held() {
    ordinary_re_root().assert_held_through_the_handoff();
}

#[test]
fn a_re_root_never_repairs_a_floor_held_mark_through_its_vouch() {
    vouch_over_a_refused_row().assert_held_through_the_handoff();
}

#[test]
fn a_re_root_never_repairs_a_floor_held_mark_in_two_steps() {
    two_step_repair().assert_held_through_the_handoff();
}

/// The marks `replica`'s install fold keeps on its rows with no handoff's
/// vouch, and those of them its fold with the vouch drops. A row counts only
/// when both folds hold it; a machine's mark, only when both head it with
/// the same revision.
fn marks_a_vouch_drops(replica: &Vault) -> (usize, Vec<String>) {
    let entries = stored_entries(replica);
    let txn = replica.store.env.read_txn().unwrap();
    let observations = authority_local_observations_in_txn(&replica.store, &txn, &entries).unwrap();
    let fold = |vouched| {
        floor_marks_of(vouched, || {
            fold_authority_log_with_local_observations_and_posture(
                &entries,
                &BTreeMap::new(),
                0,
                &BTreeMap::new(),
                &observations,
                replica.privacy_posture(),
            )
        })
    };
    let ((vouched, kept), (unvouched, held)) = (fold(true), fold(false));
    let in_both = |hash: &&AuthorityEntryHash| {
        vouched.valid_entries.contains(*hash) && unvouched.valid_entries.contains(*hash)
    };
    let row = |kind: &str, hash: &AuthorityEntryHash| format!("{kind} on {:02x?}", &hash[..4]);
    let mut dropped: Vec<_> = held
        .past_floor
        .difference(&kept.past_floor)
        .filter(in_both)
        .map(|hash| row("past_floor", hash))
        .collect();
    dropped.extend(
        held.narrow_only
            .difference(&kept.narrow_only)
            .filter(in_both)
            .map(|hash| row("narrow_only", hash)),
    );
    let mut count = held.past_floor.len() + held.narrow_only.len();
    for (id, machine) in unvouched.machines.iter().filter(|(_, m)| m.floor_held) {
        count += 1;
        if vouched
            .machines
            .get(id)
            .is_some_and(|other| other.entry == machine.entry && !other.floor_held)
        {
            dropped.push(row("floor_held head", &machine.entry));
        }
    }
    (count, dropped)
}

/// The Engine's invariant for #1430 (after Wonder P2 rounds 9 and 10): a
/// vouch changes only validity and settlement, never an install floor mark.
/// In every scenario above, after its handoff, each mark the fold with no
/// vouch keeps (a row past its floor, an edit that only narrows, a held
/// machine) the vouched fold keeps on the same row.
#[test]
fn a_vouch_never_drops_a_floor_mark() {
    let mut dropped = Vec::new();
    for scenario in [
        ordinary_re_root(),
        vouch_over_a_refused_row(),
        two_step_repair(),
    ] {
        scenario.hand_off();
        let (held, lost) = marks_a_vouch_drops(&scenario.replica);
        assert!(held > 0, "{}: no floor mark to keep", scenario.name);
        dropped.extend(
            lost.into_iter()
                .map(|mark| format!("{}: {mark}", scenario.name)),
        );
    }
    assert!(
        dropped.is_empty(),
        "a vouch dropped floor marks: {dropped:?}"
    );
}
