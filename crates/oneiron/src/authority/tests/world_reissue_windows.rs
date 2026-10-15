//! World privacy P6b acceptance for the windows a re-issue opens (contract
//! §4, check 7c): whatever the old root's seed holder writes afterwards, and
//! in whatever order it arrives, installs pinned to the new root read no
//! wider than the owner set them; and a holder the old seed strands gets the
//! world back only through the ordinary owner's path.
use super::support::{authority_key_from_ed, sign_ed, unsigned_entry};
use super::world_key_doors::{Fresh, fresh_install, own_request};
use super::world_privacy::{settings, world_row};
use super::world_reissue::{admit, issue, read_on, revision, set_on, sync};
use super::*;
use crate::world_keys::RecoveryRootSeed;
use crate::{Vault, VaultConfig};

const HERE: EditOrigin = EditOrigin::ThisMachine;

fn anchor_key(seed: &RecoveryRootSeed) -> [u8; 32] {
    seed.anchor().verifying_key().to_bytes()
}

/// `machine`'s head in `seed`'s anchor chain on `install`.
fn head(install: &Fresh, seed: &RecoveryRootSeed, machine: EntityId) -> MachineProfile {
    install
        .vault
        .authority_fold()
        .unwrap()
        .machine(machine)
        .unwrap()
        .anchored[&anchor_key(seed)]
        .profile
        .clone()
}

/// `seed`'s anchor removes `machine` from its chain on `install`, listing
/// `seen` as the edits its removal saw.
fn remove_under(
    install: &Fresh,
    seed: &RecoveryRootSeed,
    machine: EntityId,
    seen: &[AuthorityEntryHash],
) {
    let current = head(install, seed, machine);
    let profile = MachineProfile {
        role: MachineRole::Removed,
        revision: current.revision + 1,
        seen_world_edits: seen.iter().copied().collect(),
        ..current
    };
    let fold = install.vault.authority_fold().unwrap();
    let entry = anchor_signed_entry(
        &fold,
        &seed.anchor(),
        AuthorityOp::MachineProfile(profile),
        2,
    )
    .unwrap();
    install
        .vault
        .put_authority_log_entry(&entry, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
}

/// The world's live edits on `install`.
fn live(install: &Fresh, world: EntityId) -> Vec<AuthorityEntryHash> {
    install.vault.authority_fold().unwrap().worlds[&world]
        .live
        .keys()
        .copied()
        .collect()
}

/// `profiles`, each signed by `seed`'s anchor on `install`'s main-log heads at
/// consecutive sequences: concurrent siblings that land in any order.
fn siblings(
    install: &Fresh,
    seed: &RecoveryRootSeed,
    profiles: Vec<MachineProfile>,
) -> Vec<AuthorityLogEntry> {
    let fold = install.vault.authority_fold().unwrap();
    let anchor = seed.anchor();
    let signer = authority_key_from_ed(&anchor);
    let next = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
    let heads: Vec<_> = fold.append_heads.iter().copied().collect();
    profiles
        .into_iter()
        .zip(next..)
        .map(|(profile, seq)| {
            sign_ed(
                unsigned_entry(
                    fold.vault_id,
                    seq,
                    heads.clone(),
                    AuthorityOp::MachineProfile(profile),
                    signer.clone(),
                    2,
                ),
                &anchor,
            )
        })
        .collect()
}

/// A replica of `install`'s history, pinned to `pin`, that then stores
/// `rows` in this order, each in a write of its own.
fn pinned_replica(
    install: &Fresh,
    pin: PinnedRoot,
    rows: &[&AuthorityLogEntry],
) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    replica
        .import_signed_authority_history(&install.vault.export_signed_authority_history().unwrap())
        .unwrap();
    replica
        .with_write_txn_grouped(|wtxn| write_pinned_root_in_txn(&replica.store, wtxn, pin, None))
        .unwrap();
    for row in rows {
        replica
            .put_authority_log_entry(row, TimeRange { start: 3, end: 3 }, 3)
            .unwrap();
    }
    (dir, replica)
}

/// Every order of `rows`.
fn orders<T: Copy>(rows: &[T]) -> Vec<Vec<T>> {
    if rows.len() <= 1 {
        return vec![rows.to_vec()];
    }
    let mut out = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let mut rest = rows.to_vec();
        rest.remove(index);
        for mut tail in orders(&rest) {
            tail.insert(0, *row);
            out.push(tail);
        }
    }
    out
}

/// 7c, old-root writes after a re-issue change nothing (Sol R1e-F1, R1f-F2,
/// R1g-F2, R1g-F3). After the owner re-asserts W from A on R2, the holder of
/// R1's seed removes A under R1, demotes it, conflicts its chain, and
/// publishes a higher removal that lists A's old edits. Installs pinned to
/// R2 keep W's re-asserted read in every arrival order. A widening A signed
/// offline before it saw R2's carry stays restriction-only on R2, beside a
/// concurrent R1 removal and whatever R1 lists later. Fails before: the carry
/// lift read the old root's chain, so its later writes could lift or demote.
#[test]
fn old_root_writes_after_a_re_issue_change_nothing() {
    let host = super::machine_identity::host();
    let world = world_row(&host);
    let offline = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    set_on(&a, world, ReadLocation::OneMachine(a.machine()));
    set_on(&a, world, ReadLocation::MyMachines);
    set_on(&a, offline, ReadLocation::OneMachine(a.machine()));
    let old_edits: Vec<_> = live(&a, world);
    sync(&a.vault, &issuer.vault);
    let second = issue(&issuer, &[a.machine()]);
    // Before it learns of R2's carry, A widens the other world offline.
    set_on(&a, offline, ReadLocation::MyMachines);
    let widening = live(&a, offline);
    sync(&issuer.vault, &a.vault);
    a.vault.pin_owner_root(&a.owner, HERE, second.root).unwrap();
    a.vault
        .reassert_world_privacy(
            &a.owner,
            HERE,
            world,
            settings(ReadLocation::MyMachines),
            revision(&a.vault, world),
        )
        .unwrap();
    assert_eq!(read_on(&a, world), EffectiveRead::MyMachines);
    assert_eq!(read_on(&a, offline), EffectiveRead::OneMachine(a.machine()));

    let held = head(&a, &first.seed, a.machine());
    let rows = siblings(
        &a,
        &first.seed,
        vec![
            MachineProfile {
                role: MachineRole::Removed,
                revision: held.revision + 1,
                ..held.clone()
            },
            MachineProfile {
                role: MachineRole::Owned(MachineOwnership::WorkSchool),
                revision: held.revision + 1,
                ..held.clone()
            },
            MachineProfile {
                owner: EntityId::now(),
                revision: held.revision + 1,
                ..held.clone()
            },
            MachineProfile {
                role: MachineRole::Removed,
                revision: held.revision + 2,
                seen_world_edits: old_edits.iter().chain(&widening).copied().collect(),
                ..held
            },
        ],
    );
    let pin = PinnedRoot {
        id: second.root,
        anchor_key: anchor_key(&second.seed),
    };
    let refs: Vec<&AuthorityLogEntry> = rows.iter().collect();
    for order in orders(&refs) {
        let (_dir, replica) = pinned_replica(&a, pin, &order);
        assert_eq!(
            replica.world_privacy(world).unwrap().read,
            EffectiveRead::MyMachines
        );
        assert_eq!(
            replica.world_privacy(offline).unwrap().read,
            EffectiveRead::OneMachine(a.machine())
        );
    }
}

/// 7c, a compromised old seed in the window (Sol R1f-F1, R1g-F1): R1 admits
/// A and B. A holds W and sets it to `OneMachine(B)`; while another install
/// re-issues R2 carrying B, R1 removes B and A re-picks W to `MyMachines`.
/// Before A moves, the holder of R1's seed removes A under R1, listing only
/// the first edit. A anchors its own request with R2's seed. Its earlier
/// read already equals R2's (`OneMachine(B)`: under R1 the removal leaves the
/// re-pick restriction only), so the narrowed report does not list W (the
/// Engine's ruling, 2026-10-15). A has standing neither in its earlier read
/// nor in R2's, so a re-assertion is refused, and installs pinned to R2 read
/// `OneMachine(B)`, never wider. B holds no rows of W: the owner removes B
/// under R2, and A re-picks W through the ordinary door.
#[test]
fn a_compromised_old_seed_only_narrows_and_the_owner_recovers() {
    let host = super::machine_identity::host();
    let world = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let b = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    admit(&issuer, &first, &b);
    sync(&issuer.vault, &a.vault);
    set_on(&a, world, ReadLocation::OneMachine(b.machine()));
    let moved = live(&a, world);
    let second = issue(&issuer, &[b.machine()]);
    remove_under(&a, &first.seed, b.machine(), &[]);
    set_on(&a, world, ReadLocation::MyMachines);
    remove_under(&a, &first.seed, a.machine(), &moved);
    sync(&issuer.vault, &a.vault);

    let own = own_request(&a.vault);
    let report = a
        .vault
        .anchor_machine(&a.owner, HERE, &second.seed, &own, None, None)
        .unwrap();
    assert!(
        report
            .repin
            .unwrap()
            .narrowed
            .iter()
            .all(|narrowed| narrowed.world != world)
    );
    assert!(
        a.vault
            .reassert_world_privacy(
                &a.owner,
                HERE,
                world,
                settings(ReadLocation::MyMachines),
                revision(&a.vault, world),
            )
            .is_err()
    );
    assert_eq!(read_on(&a, world), EffectiveRead::OneMachine(b.machine()));
    sync(&a.vault, &issuer.vault);
    assert_eq!(
        read_on(&issuer, world),
        EffectiveRead::OneMachine(b.machine())
    );

    remove_under(&a, &second.seed, b.machine(), &[]);
    set_on(&a, world, ReadLocation::OneMachine(a.machine()));
    assert_eq!(read_on(&a, world), EffectiveRead::OneMachine(a.machine()));
}
