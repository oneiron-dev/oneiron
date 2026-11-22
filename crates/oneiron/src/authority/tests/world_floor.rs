//! A restriction still lands past a sequence floor (Astra #1430).
//! SEQ-FLOOR-SHAPE = A and SEQ-FLOOR-SHAPE-S = B: the signed rows set the
//! floor, not delivery order, and a floor alone never refuses a row.
use std::collections::{BTreeMap, BTreeSet};

use super::machine_identity::{Host, host, request_for};
use super::support::RosterHead;
use super::support::{authority_key_from_ed, device, ed_key, owner_act, sign_ed, unsigned_entry};
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
        .import_signed_authority_history(
            &host.vault.export_signed_authority_history().unwrap(),
            &CarriedOverlays::new(),
        )
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

fn next_seq(fold: &AuthorityFold, key: &SigningKey) -> u64 {
    fold.append_sequences
        .get(&authority_key_from_ed(key))
        .map_or(1, |seq| seq + 1)
}

/// A carrier signs the answer; the owner's root cosigns as proof, not as carrier.
fn answer_on(
    host: &Host,
    (carrier, key): (EntityId, &SigningKey),
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    mut profile: MachineProfile,
) -> AuthorityLogEntry {
    let kind = if profile.role == MachineRole::Removed {
        OwnerActKind::MachineRemoval
    } else {
        OwnerActKind::MachineAnswer
    };
    let seen = host
        .vault
        .authority_fold()
        .unwrap()
        .machine(profile.machine)
        .map_or([0; 32], |machine| machine.answer_revision(None));
    profile.carrier = Some(carrier);
    profile.act = Some(OwnerAct::by_owner(
        host.owner.actor(),
        kind,
        profile.machine,
        ActSurface::ThisInstall,
        seen,
    ));
    let mut entry = unsigned_entry(
        Some(host.vault_id),
        seq,
        parents,
        AuthorityOp::MachineProfile(profile),
        authority_key_from_ed(key),
        2,
    );
    entry.cosigns.push(AuthoritySignature {
        suite: AuthoritySignatureSuite::Ed25519,
        public_key: host.issuer.public_key(),
        signature: vec![0; 64],
    });
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry.cosigns[0].signature = host.issuer.sign_mesh(&transcript).to_vec();
    entry
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

/// SEQ-FLOOR-SHAPE = A: a removed machine's later widening is valid
/// without effect. It still sets the floor for that key's earlier narrowing,
/// which counts as restriction only in either delivery order.
#[test]
fn a_narrowing_that_arrives_after_a_refused_row_still_narrows() {
    let host = host();
    let world = world_row(&host);
    let (laptop, laptop_key) =
        other_machine(&host, 91, MachineRole::Owned(MachineOwnership::Yours));
    let (desk, desk_key) = other_machine(&host, 92, MachineRole::Owned(MachineOwnership::Yours));
    let narrowing = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::OneMachine(laptop)),
    );
    let fold = host.vault.authority_fold().unwrap();
    let removal = answer_on(
        &host,
        (desk, &desk_key),
        next_seq(&fold, &desk_key),
        fold.append_heads.iter().copied().collect(),
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
        vec![hash(&removal)],
        ReadLocation::Everywhere,
    );
    for (order, rows) in [
        ("narrowing first", [&narrowing, &removal, &refused]),
        ("refused row first", [&removal, &refused, &narrowing]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        let fold = replica.authority_fold().unwrap();
        assert!(fold.valid_entries.contains(&hash(&refused)), "{order}");
        assert!(
            fold.refused_world_edits.contains(&hash(&refused)),
            "{order}"
        );
        assert!(
            fold.install.held_back.contains(&hash(&narrowing)),
            "{order}"
        );
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false),
            "{order}"
        );
    }
}

/// Mesh PR1a (FIX-LIST 10-19 02:16): a role change is not a taker. Two
/// concurrent removals do race the widening: both must have seen it. The
/// removal that did not see it still counts when it arrives second.
#[test]
fn an_unacknowledging_removal_that_arrives_second_still_races_a_widening() {
    let Held {
        host,
        world,
        laptop: (laptop, laptop_key),
        desk: (desk, desk_key),
        ..
    } = held(92);
    let fold = host.vault.authority_fold().unwrap();
    let seq = next_seq(&fold, &desk_key);
    let heads: Vec<_> = fold.append_heads.iter().copied().collect();
    let profile = fold.machine(laptop).unwrap().head().profile.clone();
    let quiet = answer_on(
        &host,
        (desk, &desk_key),
        seq,
        heads,
        MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            seen_world_edits: BTreeSet::new(),
            ..profile.clone()
        },
    );
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
    let removal = answer_on(
        &host,
        (desk, &desk_key),
        seq + 1,
        fold.append_heads.iter().copied().collect(),
        MachineProfile {
            role: MachineRole::Removed,
            revision: 3,
            seen_world_edits: BTreeSet::from([hash(&widening)]),
            ..profile
        },
    );
    for (order, rows) in [
        ("quiet removal first", [&quiet, &removal]),
        ("acknowledging removal first", [&removal, &quiet]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false),
            "{order}"
        );
    }
}

/// Sol P2 round 10, F1: a floor does not grant a removed carrier standing
/// (mesh PR1a). A handover below a fork's sequence floor still lets the
/// second machine narrow. If the owner removes the first machine over the
/// handover, that machine's later widening is valid without effect.
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
        let fold = host.vault.authority_fold().unwrap();
        let heads = fold.append_heads.iter().copied().collect();
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
            102,
            vec![hash(&held)],
            ReadLocation::OneMachine(EntityId::now()),
        );
        let removal = (!handed_everywhere).then(|| {
            answer_on(
                &host,
                (second, &second_key),
                next_seq(&fold, &second_key),
                vec![hash(&handover)],
                MachineProfile {
                    role: MachineRole::Removed,
                    revision: 2,
                    seen_world_edits: BTreeSet::from([hash(&held), hash(&handover)]),
                    ..fold.machine(first.0).unwrap().head().profile.clone()
                },
            )
        });
        let later = if let Some(removal) = &removal {
            edit_on(
                &host,
                first,
                world,
                101,
                vec![hash(removal)],
                ReadLocation::Everywhere,
            )
        } else {
            edit_on(
                &host,
                (second, &second_key),
                world,
                1,
                vec![hash(&handover)],
                ReadLocation::OneMachine(second),
            )
        };
        for (order, mut rows) in [
            ("handover first", vec![&held, &handover, &refused]),
            ("refused row first", vec![&held, &refused, &handover]),
        ] {
            rows.extend(removal.iter());
            rows.push(&later);
            let (_dir, replica) = replica_storing(&host, &rows);
            let fold = replica.authority_fold().unwrap();
            let (read, readable) = judged(&replica, world);
            assert!(fold.valid_entries.contains(&hash(&handover)), "{order}");
            assert!(fold.install.held_back.contains(&hash(&handover)), "{order}");
            assert!(!readable, "{order}");
            if handed_everywhere {
                assert_eq!(read, EffectiveRead::OneMachine(second), "{order}");
            } else {
                assert!(fold.valid_entries.contains(&hash(&later)), "{order}");
                assert!(fold.refused_world_edits.contains(&hash(&later)), "{order}");
            }
        }
    }
}

/// Mesh PR1b (FIX 4610): two concurrent re-marks at the same revision
/// diverge. A removal on one branch lists the widening but conflicts with
/// the other mark, so the widening counts only as narrowing in both orders.
#[test]
fn a_divergent_mark_that_arrives_after_a_removal_still_voids_it() {
    let Held {
        host,
        world,
        laptop: (laptop, laptop_key),
        desk: (desk, desk_key),
        narrowing,
    } = held(95);
    let widening = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::Everywhere),
    );
    land(&host, std::slice::from_ref(&widening));

    let fold = host.vault.authority_fold().unwrap();
    let seq = next_seq(&fold, &desk_key);
    let heads: Vec<_> = fold.append_heads.iter().copied().collect();
    let profile = fold.machine(laptop).unwrap().head().profile.clone();
    let remark = |seq, seen_world_edits| {
        answer_on(
            &host,
            (desk, &desk_key),
            seq,
            heads.clone(),
            MachineProfile {
                revision: 2,
                seen_world_edits,
                ..profile.clone()
            },
        )
    };
    let marked = remark(seq, BTreeSet::new());
    let sibling = remark(seq + 1, BTreeSet::from([hash(&narrowing)]));
    let removal = answer_on(
        &host,
        (desk, &desk_key),
        seq + 2,
        vec![hash(&marked)],
        MachineProfile {
            role: MachineRole::Removed,
            revision: 3,
            seen_world_edits: BTreeSet::from([hash(&widening)]),
            ..profile
        },
    );
    for (order, rows) in [
        ("sibling first", [&marked, &sibling, &removal]),
        ("removal first", [&marked, &removal, &sibling]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        let fold = replica.authority_fold().unwrap();
        assert!(
            rows.iter()
                .all(|row| fold.valid_entries.contains(&hash(row)))
        );
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

/// Sol P2 round 13 F1 and Wonder round 7 W1: a higher sibling sequence
/// puts both re-marks and the removal past the floor. The removal races the
/// widening even if it lists it. A widening signed under a held mark also
/// lands restriction only. Mesh PR1a: a demotion alone would not take away.
#[test]
fn a_removal_over_a_divergent_mark_past_the_floor_acknowledges_nothing() {
    for signed_under_remark in [false, true] {
        let Held {
            host,
            world,
            laptop: (laptop, laptop_key),
            desk: (desk, desk_key),
            narrowing,
        } = held(97);
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
        let seq = next_seq(&fold, &desk_key);
        let heads: Vec<_> = fold.append_heads.iter().copied().collect();
        let profile = fold.machine(laptop).unwrap().head().profile.clone();
        let remark = |seq, seen_world_edits| {
            answer_on(
                &host,
                (desk, &desk_key),
                seq,
                heads.clone(),
                MachineProfile {
                    revision: 2,
                    seen_world_edits,
                    ..profile.clone()
                },
            )
        };
        let marked = remark(seq, BTreeSet::new());
        let sibling = remark(seq + 1, BTreeSet::from([hash(&narrowing)]));
        let widening = landed.unwrap_or_else(|| {
            edit_on(
                &host,
                (laptop, &laptop_key),
                world,
                next_seq(&fold, &laptop_key),
                vec![hash(&marked)],
                ReadLocation::Everywhere,
            )
        });
        let removal = answer_on(
            &host,
            (desk, &desk_key),
            seq + 2,
            vec![hash(&marked), hash(&widening)],
            MachineProfile {
                role: MachineRole::Removed,
                revision: 3,
                seen_world_edits: BTreeSet::from([hash(&widening)]),
                ..profile
            },
        );
        let other = answer_on(
            &host,
            (desk, &desk_key),
            seq + 3,
            heads,
            MachineProfile {
                revision: 2,
                ..fold.machine(desk).unwrap().head().profile.clone()
            },
        );
        for (order, mut rows) in [
            ("in order", vec![&marked, &sibling, &other]),
            ("other first", vec![&other, &marked, &sibling]),
        ] {
            if signed_under_remark {
                rows.push(&widening);
            }
            rows.push(&removal);
            let (_dir, replica) = replica_storing(&host, &rows);
            let fold = replica.authority_fold().unwrap();
            assert!(fold.valid_entries.contains(&hash(&removal)), "{order}");
            assert!(fold.install.held_back.contains(&hash(&removal)), "{order}");
            assert_eq!(
                judged(&replica, world),
                (EffectiveRead::OneMachine(laptop), false),
                "{order}, signed under the re-mark: {signed_under_remark}"
            );
        }
    }
}

/// Sol P2 round 13 F2 and Wonder round 7 W2: a mark below a sequence floor
/// still bounds the revision number. A duplicate-number removal fails;
/// the widening on the held mark can only narrow (SEQ-FLOOR-SHAPE = A).
#[test]
fn a_revision_past_the_floor_still_bounds_the_next_number() {
    let Held {
        host,
        world,
        laptop: (laptop, laptop_key),
        desk: (desk, desk_key),
        ..
    } = held(99);
    let fold = host.vault.authority_fold().unwrap();
    let seq = next_seq(&fold, &desk_key);
    let heads: Vec<_> = fold.append_heads.iter().copied().collect();
    let profile = fold.machine(laptop).unwrap().head().profile.clone();
    let marked = answer_on(
        &host,
        (desk, &desk_key),
        seq,
        heads.clone(),
        MachineProfile {
            revision: 2,
            ..profile.clone()
        },
    );
    let other = answer_on(
        &host,
        (desk, &desk_key),
        seq + 2,
        heads,
        MachineProfile {
            revision: 2,
            ..fold.machine(desk).unwrap().head().profile.clone()
        },
    );
    let duplicate = answer_on(
        &host,
        (desk, &desk_key),
        seq + 3,
        vec![hash(&marked), hash(&other)],
        MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            ..profile
        },
    );
    let widening = edit_on(
        &host,
        (laptop, &laptop_key),
        world,
        next_seq(&fold, &laptop_key),
        vec![hash(&marked)],
        ReadLocation::Everywhere,
    );
    for (order, rows) in [
        ("in order", [&marked, &other, &duplicate, &widening]),
        ("other first", [&other, &marked, &duplicate, &widening]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        let fold = replica.authority_fold().unwrap();
        assert!(fold.valid_entries.contains(&hash(&marked)), "{order}");
        assert!(!fold.valid_entries.contains(&hash(&duplicate)), "{order}");
        assert!(fold.valid_entries.contains(&hash(&widening)), "{order}");
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false),
            "{order}"
        );
    }
}

/// Engine ruling on Astra #1430: a re-key past the floor still poisons. The
/// owner re-marks a machine under a second install key, and a sibling row
/// of the same carrier sets the floor. A machine whose revisions named two keys
/// is live under neither, so on both replicas a connection proved under
/// either key speaks for no machine.
#[test]
fn a_rekey_past_the_floor_leaves_both_keys_unknown() {
    let Held {
        host,
        laptop: (laptop, first),
        desk: (desk, desk_key),
        ..
    } = held(103);
    let second = ed_key(105);
    let fold = host.vault.authority_fold().unwrap();
    let seq = next_seq(&fold, &desk_key);
    let heads: Vec<_> = fold.append_heads.iter().copied().collect();
    let request = request_for(host.vault_id, laptop, &second);
    let rekey = answer_on(
        &host,
        (desk, &desk_key),
        seq,
        heads.clone(),
        MachineProfile {
            machine_key: request.machine_key,
            machine_proof: request.machine_proof,
            revision: 2,
            ..fold.machine(laptop).unwrap().head().profile.clone()
        },
    );
    let other = answer_on(
        &host,
        (desk, &desk_key),
        seq + 1,
        heads,
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
        let fold = replica.authority_fold().unwrap();
        assert!(fold.valid_entries.contains(&hash(&rekey)), "{order}");
        assert!(fold.machines[&laptop].head().conflicted, "{order}");
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
/// acknowledges nothing here. SEQ-FLOOR-SHAPE = A: the same rows produce
/// the same floor in both orders. Without the sibling, the removal saw
/// the widening and keeps it at full strength (mesh PR1a).
#[test]
fn a_removal_past_the_floor_acknowledges_nothing_here() {
    let Held {
        host,
        world,
        laptop: (laptop, laptop_key),
        desk: (desk, desk_key),
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
    let seq = next_seq(&fold, &desk_key);
    let heads: Vec<_> = fold.append_heads.iter().copied().collect();
    let removal = answer_on(
        &host,
        (desk, &desk_key),
        seq,
        heads.clone(),
        MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            seen_world_edits: BTreeSet::from([hash(&widening)]),
            ..fold.machine(laptop).unwrap().head().profile.clone()
        },
    );
    let other = answer_on(
        &host,
        (desk, &desk_key),
        seq + 1,
        heads,
        MachineProfile {
            revision: 2,
            ..fold.machine(desk).unwrap().head().profile.clone()
        },
    );
    let (_dir, replica) = replica_storing(&host, &[&removal]);
    assert_eq!(judged(&replica, world), (EffectiveRead::Everywhere, true));
    for rows in [[&other, &removal], [&removal, &other]] {
        let (_dir, replica) = replica_storing(&host, &rows);
        assert!(
            replica.authority_fold().unwrap().machines[&laptop]
                .head()
                .removed
        );
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false)
        );
    }
}

/// A world the desk narrowed to "my machines", and a work laptop the desk
/// can mark or remove. The desk's own main-log rows set its answers' floors.
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

    fn desk_seq(&self) -> u64 {
        next_seq(&self.fold, &self.desk.1)
    }

    /// A full-copy mark is a main-log row that records a sequence fork.
    fn copy_mark(&self, seq: u64, parents: Vec<AuthorityEntryHash>) -> AuthorityLogEntry {
        let (machine, key) = (self.desk.0, &self.desk.1);
        sign_ed(
            unsigned_entry(
                Some(self.host.vault_id),
                seq,
                parents,
                AuthorityOp::FullCopyMark(FullCopyMark {
                    machine,
                    held: false,
                }),
                authority_key_from_ed(key),
                2,
            ),
            key,
        )
    }

    /// A retired device enrollment permitted only on a verified handoff's line.
    fn retired(&self, parents: Vec<AuthorityEntryHash>, seed: u8) -> AuthorityLogEntry {
        self.owner_row(
            self.seq + 1,
            parents,
            AuthorityOp::EnrollDevice {
                device: device(
                    authority_key_from_ed(&ed_key(seed)),
                    ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
        )
    }

    fn profile(&self, machine: EntityId) -> MachineProfile {
        self.fold.machine(machine).unwrap().head().profile.clone()
    }

    fn answer(
        &self,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        profile: MachineProfile,
    ) -> AuthorityLogEntry {
        answer_on(
            &self.host,
            (self.desk.0, &self.desk.1),
            seq,
            parents,
            profile,
        )
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

    /// Parents of the issuer's latest stored row, even when the main-log
    /// heads have advanced on the install keys.
    fn below_heads(&self) -> Vec<AuthorityEntryHash> {
        let issuer = self.host.issuer.public_key();
        stored_entries(&self.host.vault)
            .into_iter()
            .find(|entry| entry.signer_key() == &issuer && entry.seq == self.seq)
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

    /// The desk carries the owner's "yours" answer for the laptop.
    fn mark(&self, seq: u64, revision: u64, parents: Vec<AuthorityEntryHash>) -> AuthorityLogEntry {
        self.answer(
            seq,
            parents,
            MachineProfile {
                role: MachineRole::Owned(MachineOwnership::Yours),
                revision,
                ..self.profile(self.laptop.0)
            },
        )
    }

    /// The laptop's widening under `mark`, over the desk's narrowing.
    fn widening(&self, mark: &AuthorityLogEntry) -> AuthorityLogEntry {
        edit_on(
            &self.host,
            (self.laptop.0, &self.laptop.1),
            self.world,
            next_seq(&self.fold, &self.laptop.1),
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

/// Astra #1430b, F2: a different signer's handoff does not clear the desk's
/// floor. The laptop's widening under the held mark still only narrows.
fn ordinary_re_root() -> MarkPastFloor {
    let start = Start::new(108);
    let seq = start.desk_seq();
    let marked = start.mark(seq, 2, start.heads());
    let other = start.copy_mark(seq + 1, start.heads());
    let widening = start.widening(&marked);
    start.replica("ordinary re-root", &[&other, &marked, &widening], None)
}

/// Wonder P2 round 9, W1, under SEQ-FLOOR-SHAPE-S = B: a forked row is
/// valid. A handoff that covers that row and the held mark clears neither
/// the fork nor the other signer's floor.
fn vouch_over_a_fork() -> (MarkPastFloor, AuthorityEntryHash) {
    let start = Start::new(110);
    let seq = start.desk_seq();
    let fork = start.copy_mark(seq, start.heads());
    let marked = start.mark(seq + 1, 2, vec![hash(&fork)]);
    let later = start.copy_mark(seq + 2, start.heads());
    let widening = start.widening(&marked);
    let re_root = start.re_root(
        start.seq + 1,
        vec![hash(&later), hash(&widening)],
        b"world floor vouching root",
    );
    let graph = start.replica(
        "vouch over a fork",
        &[&later, &fork, &marked, &widening],
        Some(re_root),
    );
    (graph, hash(&fork))
}

/// Wonder P2 round 10, W1: two descendants reach neither their own floor
/// nor the floor of the fork. A cross-signer handoff covering both of them
/// does not turn either row into an ancestry repair (SEQ-FLOOR-SHAPE = A).
fn two_step_repair() -> MarkPastFloor {
    let start = Start::new(112);
    let seq = start.desk_seq();
    let first = start.copy_mark(seq, start.heads());
    let second = start.copy_mark(seq + 1, start.heads());
    let over_both = start.copy_mark(seq + 2, vec![hash(&first), hash(&second)]);
    let marked = start.mark(seq + 3, 2, start.heads());
    let over_mark = start.copy_mark(seq + 4, vec![hash(&marked), hash(&second)]);
    let later = start.copy_mark(seq + 5, start.heads());
    let widening = start.widening(&marked);
    let re_root = start.re_root(
        start.seq + 1,
        vec![
            hash(&over_both),
            hash(&over_mark),
            hash(&later),
            hash(&widening),
        ],
        b"world floor two-step root",
    );
    start.replica(
        "two-step repair",
        &[
            &later, &over_both, &over_mark, &first, &second, &marked, &widening,
        ],
        Some(re_root),
    )
}

/// Sol P2 round 17, F1: a carried successor revision depends on a retired
/// enrollment. The handoff admits that ancestor, not a clearance of the
/// successor's own sequence floor (SEQ-FLOOR-SHAPE = A).
fn rescued_successor() -> (MarkPastFloor, AuthorityEntryHash) {
    let start = Start::new(114);
    let seq = start.desk_seq();
    let marked = start.mark(seq, 2, start.heads());
    let retired = start.retired(vec![hash(&marked)], 214);
    let successor = start.mark(seq + 1, 3, vec![hash(&retired)]);
    let later = start.copy_mark(seq + 2, start.heads());
    let widening = start.widening(&successor);
    let re_root = start.re_root(
        start.seq + 2,
        vec![hash(&widening), hash(&later)],
        b"world floor successor revision root",
    );
    let graph = start.replica(
        "rescued successor",
        &[&later, &marked, &retired, &successor, &widening],
        Some(re_root),
    );
    (graph, hash(&successor))
}

/// Sol P2 round 17, F2: a retired enrollment becomes valid as a verified
/// handoff's ancestry. A carried tip over it stays below its own floor,
/// so the new permission clears no floor (SEQ-FLOOR-SHAPE = A).
fn retired_permission() -> (MarkPastFloor, AuthorityEntryHash, AuthorityEntryHash) {
    let start = Start::new(116);
    let seq = start.desk_seq();
    let sibling = start.revoke(start.seq, start.below_heads(), 16);
    let marked = start.mark(seq, 2, start.heads());
    let retired = start.retired(vec![hash(&marked), hash(&sibling)], 216);
    let tip = start.copy_mark(seq + 1, vec![hash(&retired)]);
    let later = start.copy_mark(seq + 2, start.heads());
    let widening = start.widening(&marked);
    let re_root = start.re_root(
        start.seq + 2,
        vec![hash(&later), hash(&tip), hash(&widening)],
        b"world floor permission root",
    );
    let graph = start.replica(
        "retired permission",
        &[&later, &sibling, &marked, &retired, &tip, &widening],
        Some(re_root),
    );
    (graph, hash(&retired), hash(&tip))
}

/// Sol P2 round 18, F1: a desk-signed removal makes the laptop's next
/// edit valid without effect (mesh PR1a). The handoff admits a retired
/// enrollment on another branch, not that edit, with or without a floor
/// on the removal.
fn refused_repick(seed: u8, removal_offset: u64) -> (MarkPastFloor, AuthorityEntryHash) {
    let start = Start::new(seed);
    let desk = start.desk.0;
    let holding = edit_by(
        &start.host,
        desk,
        &start.desk.1,
        start.world,
        settings(ReadLocation::OneMachine(desk)),
    );
    let start = start.landed(std::slice::from_ref(&holding));
    let seq = start.desk_seq();
    let later = start.copy_mark(seq + 1, start.heads());
    let retired = start.retired(start.heads(), seed + 100);
    let removal = start.answer(
        seq + removal_offset,
        start.heads(),
        MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            ..start.profile(start.laptop.0)
        },
    );
    let widening = start.widening(&removal);
    let re_root = start.re_root(
        start.seq + 2,
        vec![hash(&retired), hash(&later), hash(&widening)],
        &[seed; 8],
    );
    let world = start.world;
    let graph = start
        .replica(
            "refused re-pick",
            &[&later, &retired, &removal, &widening],
            Some(re_root),
        )
        .expecting(world, EffectiveRead::OneMachine(desk), None);
    (graph, hash(&widening))
}

/// The Engine's pin on the exemption (#1430): a signature by an install
/// key cannot settle a re-root. Crossing that row to read an edit does not
/// grant freshness or clear the edit's desk-key floor.
fn false_handoff() -> (MarkPastFloor, AuthorityEntryHash, AuthorityEntryHash) {
    let start = Start::new(134);
    let seq = start.desk_seq();
    let key = &start.laptop.1;
    let impostor = HostSlipIssuer::from_secret(b"world floor false successor").unwrap();
    let false_root = sign_ed(
        unsigned_entry(
            Some(start.host.vault_id),
            next_seq(&start.fold, key),
            start.heads(),
            AuthorityOp::ReRoot {
                new_device: impostor.root_device(crate::HostingPrivacyPosture::SelfHostLocal),
            },
            authority_key_from_ed(key),
            2,
        ),
        key,
    );
    let widening = edit_on(
        &start.host,
        (start.desk.0, &start.desk.1),
        start.world,
        seq,
        vec![hash(&false_root)],
        ReadLocation::Everywhere,
    );
    let later = start.copy_mark(seq + 1, start.heads());
    let re_root = start.re_root(
        start.seq + 1,
        vec![hash(&later)],
        b"world floor actual successor",
    );
    let world = start.world;
    let graph = start
        .replica(
            "false handoff",
            &[&later, &false_root, &widening],
            Some(re_root),
        )
        .expecting(world, EffectiveRead::MyMachines, None);
    (graph, hash(&false_root), hash(&widening))
}

/// Sol P2 round 18, F2: the removal's signed branch includes a fork that
/// stands under SEQ-FLOOR-SHAPE-S = B. The removal still lands past its
/// own floor, and neither branch proof nor fork lets it acknowledge the
/// widening here.
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
    let seq = start.desk_seq();
    let fork = start.copy_mark(seq, start.heads());
    let profile = start.profile(machine.0);
    let seen = BTreeSet::from([hash(&widening)]);
    let quiet = start.answer(
        seq + 1,
        start.heads(),
        MachineProfile {
            revision: 2,
            seen_world_edits: BTreeSet::new(),
            ..profile.clone()
        },
    );
    let listing = start.answer(
        seq + 2,
        start.heads(),
        MachineProfile {
            revision: 2,
            seen_world_edits: seen.clone(),
            ..profile.clone()
        },
    );
    let later = start.copy_mark(seq + 4, start.heads());
    let removal = start.answer(
        seq + 3,
        vec![hash(&fork)],
        MachineProfile {
            role: MachineRole::Removed,
            revision: 3,
            seen_world_edits: seen,
            ..profile
        },
    );
    let world = start.world;
    start
        .replica(
            "removal vouch",
            &[&quiet, &listing, &later, &fork],
            Some(removal),
        )
        .expecting(world, EffectiveRead::MyMachines, Some(machine.0))
}

/// Wonder P2 round 12, W2: two revisions are below the desk's floor. The
/// re-root keeps the first and fences the successor by its old-root proof
/// signature. Falling back to the first head does not lift its hold.
fn fenced_held_head() -> (MarkPastFloor, AuthorityEntryHash, AuthorityEntryHash) {
    let start = Start::new(130);
    let seq = start.desk_seq();
    let marked = start.mark(seq, 2, start.heads());
    let widening = start.widening(&marked);
    let successor = start.mark(seq + 1, 3, vec![hash(&marked)]);
    let later = start.copy_mark(seq + 2, start.heads());
    let re_root = start.re_root(
        start.seq + 1,
        vec![hash(&widening), hash(&later)],
        b"world floor fenced head root",
    );
    let graph = start.replica(
        "fenced held head",
        &[&marked, &widening, &later, &successor],
        Some(re_root),
    );
    (graph, hash(&marked), hash(&successor))
}

/// A re-root admits the retired ancestry of a removal, not a widening of
/// the read. The desk's edit crosses the refused ancestry before the
/// re-root; after it, that edit is refused without effect. The earlier
/// restriction still narrows (mesh PR1a, FIX 2222).
fn voided_narrowing() -> (MarkPastFloor, AuthorityEntryHash) {
    let start = Start::new(132);
    let fresh = world_row(&start.host);
    let desk = start.desk.0;
    let earlier = edit_by(
        &start.host,
        desk,
        &start.desk.1,
        fresh,
        settings(ReadLocation::MyMachines),
    );
    let start = start.landed(std::slice::from_ref(&earlier));
    let retired = start.retired(start.heads(), 232);
    // A second retired enrollment on the first: until the handoff's line is
    // verified it has no state of its own (its parent has none), so the
    // removal on it has no ordinary state either and the narrowing crosses
    // it with the desk still live. One retired enrollment alone is crossed
    // with the removal's real state kept, which refuses the narrowing at once.
    let retired_child = start.owner_row(
        start.seq + 2,
        vec![hash(&retired)],
        AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&ed_key(233)),
                ROLE_ADMIN,
                AuthorityTier::Software,
            ),
        },
    );
    let removal = answer_on(
        &start.host,
        (start.laptop.0, &start.laptop.1),
        next_seq(&start.fold, &start.laptop.1),
        vec![hash(&retired_child)],
        MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            ..start.profile(desk)
        },
    );
    let narrowing = edit_on(
        &start.host,
        (desk, &start.desk.1),
        fresh,
        start.desk_seq(),
        vec![hash(&removal)],
        ReadLocation::MyMachines,
    );
    let re_root = start.re_root(
        start.seq + 3,
        vec![hash(&removal)],
        b"world floor narrowing root",
    );
    let graph = start
        .replica(
            "voided narrowing",
            &[&retired, &retired_child, &removal, &narrowing],
            Some(re_root),
        )
        .expecting(fresh, EffectiveRead::MyMachines, Some(desk));
    (graph, hash(&narrowing))
}

/// The Engine's pin on #1430: neither competing handoff settles. Their
/// lines cover a desk-key sequence fork, activating the no-vouch cap,
/// but nothing after either handoff is a fresh grant.
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
    let narrowing = edit_by(
        &start.host,
        desk,
        &start.desk.1,
        fresh,
        settings(ReadLocation::OneMachine(desk)),
    );
    let seq = narrowing.seq + 1;
    let low = start.copy_mark(seq, vec![hash(&narrowing)]);
    let high = start.copy_mark(seq + 1, vec![hash(&narrowing)]);
    let line = vec![hash(&low), hash(&high)];
    let first = start.re_root(
        start.seq + 1,
        line.clone(),
        b"world floor first contested root",
    );
    let second = start.re_root(start.seq + 2, line, b"world floor second contested root");
    let widening = edit_on(
        &start.host,
        (other.0, &other.1),
        fresh,
        next_seq(&start.fold, &other.1),
        vec![hash(&first)],
        ReadLocation::Everywhere,
    );
    start
        .replica("contested handoff", &[&narrowing, &high, &low], Some(first))
        .contested(vec![second, widening])
        .expecting(fresh, EffectiveRead::OneMachine(desk), None)
}

/// Handoffs and a removal branch that exercise the vouch boundary on the
/// same signed rows, with cross-signer floors and retired permissions.
fn vouched_graphs() -> Vec<MarkPastFloor> {
    vec![
        vouch_over_a_fork().0,
        two_step_repair(),
        rescued_successor().0,
        retired_permission().0,
        refused_repick(118, 2).0,
        refused_repick(122, 0).0,
        false_handoff().0,
        contested_handoff(),
        removal_vouch(),
        fenced_held_head().0,
        voided_narrowing().0,
    ]
}

#[test]
fn a_re_root_keeps_a_floor_held_mark_held() {
    let graph = ordinary_re_root();
    graph.assert_held_through_the_handoff();
    let fold = graph.replica.authority_fold().unwrap();
    assert!(fold.machines[&graph.held.unwrap()].head().floor_held);
    assert_no_vouch_widens(&graph.replica);
}

#[test]
fn a_re_root_never_repairs_a_floor_held_mark_through_its_vouch() {
    let (graph, fork) = vouch_over_a_fork();
    let assert_fork = || {
        let fold = graph.replica.authority_fold().unwrap();
        assert!(fold.valid_entries.contains(&fork));
        assert!(
            fold.issues
                .contains(&AuthorityFoldIssue::SequenceFork(fork))
        );
    };
    assert_fork();
    graph.assert_held_through_the_handoff();
    assert_fork();
}

#[test]
fn a_re_root_never_repairs_a_floor_held_mark_in_two_steps() {
    two_step_repair().assert_held_through_the_handoff();
}

#[test]
fn a_revision_only_the_vouch_admits_grants_nothing() {
    let (graph, successor) = rescued_successor();
    let fold = graph.replica.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&successor));
    graph.assert_held_through_the_handoff();
    let fold = graph.replica.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&successor));
    let head = fold.machines[&graph.held.unwrap()].head();
    assert_eq!(head.entry, successor);
    assert!(head.floor_held);
}

#[test]
fn a_permission_only_the_vouch_gives_repairs_no_floor() {
    let (graph, retired, tip) = retired_permission();
    let fold = graph.replica.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&retired));
    assert!(!fold.valid_entries.contains(&tip));
    graph.assert_held_through_the_handoff();
    let fold = graph.replica.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&retired));
    assert!(fold.valid_entries.contains(&tip));
    assert!(fold.issues.contains(&AuthorityFoldIssue::SequenceFork(tip)));
}

#[test]
fn an_edit_valid_without_effect_gains_none_through_the_vouch() {
    for (seed, removal_offset) in [(118, 2), (122, 0)] {
        let (graph, edit) = refused_repick(seed, removal_offset);
        let assert_refused = || {
            let fold = graph.replica.authority_fold().unwrap();
            assert!(fold.valid_entries.contains(&edit));
            assert!(fold.refused_world_edits.contains(&edit));
        };
        assert_refused();
        graph.assert_held_through_the_handoff();
        assert_refused();
    }
}

#[test]
fn only_a_standing_handoff_makes_what_follows_it_fresh() {
    let (graph, false_root, widening) = false_handoff();
    let assert_not_fresh = || {
        let fold = graph.replica.authority_fold().unwrap();
        assert!(!fold.closed_handoffs.contains(&false_root));
        assert!(!fold.valid_entries.contains(&false_root));
        assert!(fold.valid_entries.contains(&widening));
        assert!(fold.install.held_back.contains(&widening));
    };
    assert_not_fresh();
    graph.assert_held_through_the_handoff();
    assert_not_fresh();
}

#[test]
fn a_contested_handoff_makes_nothing_after_it_fresh() {
    contested_handoff().assert_held_through_the_handoff();
}

#[test]
fn a_removal_branch_vouch_acknowledges_nothing() {
    let graph = removal_vouch();
    graph.assert_held_through_the_handoff();
    let fold = graph.replica.authority_fold().unwrap();
    let removal = hash(&graph.vouch[0]);
    assert!(fold.valid_entries.contains(&removal));
    assert!(fold.install.held_back.contains(&removal));
    assert!(fold.machines[&graph.held.unwrap()].head().removed);
}

#[test]
fn a_fenced_held_head_leaves_its_machine_held() {
    let (graph, marked, successor) = fenced_held_head();
    let laptop = graph.held.unwrap();
    let fold = graph.replica.authority_fold().unwrap();
    assert_eq!(fold.machines[&laptop].head().entry, successor);
    graph.assert_held_through_the_handoff();
    let fold = graph.replica.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&successor));
    assert_eq!(fold.machines[&laptop].head().entry, marked);
    assert!(fold.machines[&laptop].head().floor_held);
}

#[test]
fn a_narrowing_a_handoff_refuses_leaves_the_earlier_narrowing() {
    let (graph, narrowing) = voided_narrowing();
    let fold = graph.replica.authority_fold().unwrap();
    assert!(fold.worlds[&graph.world].live.contains_key(&narrowing));
    graph.assert_held_through_the_handoff();
    let fold = graph.replica.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&narrowing));
    assert!(fold.refused_world_edits.contains(&narrowing));
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
    let observations = authority_local_observations_in_txn(&vault.store, &txn).unwrap();
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
/// Sol P2 rounds 17-18): the install view is never wider than the no-vouch
/// fold. The vouch decides no verdict now (Engine RULING
/// SEQ-FLOOR-S-WORLD-KEY-FLOOR = A, fold_engine.rs `floor_vouched`), so only
/// the contested handoff must change the fold: it still exercises an actual
/// cap, holding already-unsettled roster chains.
#[test]
fn a_vouch_never_widens_the_install_view() {
    let mut widened = Vec::new();
    for graph in vouched_graphs() {
        graph.hand_off();
        let (changed, wider) = vouch_widenings(&graph.replica);
        if graph.contested {
            assert!(changed, "{}: the vouch changed nothing", graph.name);
        }
        widened.extend(
            wider
                .into_iter()
                .map(|row| format!("{}: {row}", graph.name)),
        );
    }
    assert!(widened.is_empty(), "the vouch widened: {widened:?}");
}

/// A record of a fresh key of the start's world, signed by the laptop at its
/// first world-key sequence on `parents` and wrapped to the eligible desk.
fn laptop_key_record(
    start: &Start,
    parents: Vec<AuthorityEntryHash>,
) -> (AuthorityLogEntry, WorldKeyId) {
    let vault_id = start.host.vault_id;
    let key = WorldKey::mint(start.world, FIRST_GENERATION).unwrap();
    let to = WrapRecipient::Machine(start.desk.0);
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
    let pad = oneiron_store::world_pad_codec::WorldKeyPad::mint().unwrap();
    let envelope = seal_world_key(&binding, to, secret.public_key(), &key, &pad).unwrap();
    let record = WorldKeyWrapsRecord {
        key: *key.id(),
        commitment: binding.commitment,
        owner: binding.owner,
        policy: binding.policy,
        machine: start.laptop.0,
        wraps: vec![(to, envelope.to_bytes())],
        request: None,
        permitted: vec![to],
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

/// Astra #1422d, the key-domain control: the handoff admits the retired
/// enrollment G, and thus the laptop's "yours" revision P and key record J.
/// The desk's sibling L floors P only when its sequence is higher. D removes
/// the laptop on both replicas, but J counts only under a full-strength P.
/// Delivery order does not choose the floor (SEQ-FLOOR-SHAPE = A).
#[test]
fn a_key_record_under_a_floor_held_revision_never_counts() {
    let start = Start::new(142);
    let remover = other_machine(
        &start.host,
        144,
        MachineRole::Owned(MachineOwnership::Yours),
    );
    let start = start.landed(&[]);
    let seq = start.desk_seq();
    let g = start.retired(start.heads(), 242);
    let p = start.mark(seq + 1, 2, vec![hash(&g)]);
    let (j, key) = laptop_key_record(&start, vec![hash(&p), hash(&start.mine)]);
    let d = answer_on(
        &start.host,
        (remover.0, &remover.1),
        next_seq(&start.fold, &remover.1),
        vec![hash(&p)],
        MachineProfile {
            role: MachineRole::Removed,
            revision: 3,
            ..start.profile(start.laptop.0)
        },
    );
    for (sibling_seq, counts) in [(seq, true), (seq + 2, false)] {
        let l = start.copy_mark(sibling_seq, start.heads());
        let h = start.re_root(
            start.seq + 2,
            vec![hash(&d), hash(&l)],
            b"world floor key control root",
        );
        for (order, rows) in [
            ("G first", [&g, &l, &p, &j, &d, &h]),
            ("L first", [&l, &g, &p, &j, &d, &h]),
        ] {
            let (_dir, replica) = replica_storing(&start.host, &rows);
            let fold = replica.authority_fold().unwrap();
            for row in rows {
                assert!(
                    fold.valid_entries.contains(&hash(row)),
                    "{order}, counts: {counts}"
                );
            }
            assert!(fold.machines[&start.laptop.0].head().removed, "{order}");
            assert_eq!(fold.world_key(&key).is_some(), counts, "{order}");
            assert_eq!(
                !fold.refused_world_keys.contains(&hash(&j)),
                counts,
                "{order}"
            );
        }
    }
}
