//! Strangers' roots at the store gate (Astra #1422e F1; the Engine, r23). A
//! root needs nothing but a fresh key, so an anchor this install does not pin
//! is a stranger: its root records, its marks and the world rows of the
//! machines only it marks share one bound, and no flood of them takes the
//! fold past its budget. The owner's own anchors never meet that bound. A
//! root held behind a flood pins in two steps: the first awaits it, which
//! changes only what the gate stores, and the second, once it has arrived,
//! pins it. So does a re-pin whose marks still wait.
use super::machine_identity::{host, request_for};
use super::support::{authority_key_from_ed, ed_key, owner_act, sign_ed, unsigned_entry};
use super::world_key_doors::{Fresh, fresh_install, own_request};
use super::world_key_store_gate::put_replicated;
use super::world_privacy::{settings, stored_entries, world_row};
use super::world_reissue::{admit, issue, pinned, set_on};
use super::*;
use crate::Vault;
use crate::authority::log_budget::with_rows_per_signer_for_test;
use crate::error::ErrorKind;
use crate::world_keys::RecoveryRootSeed;

const HERE: EditOrigin = EditOrigin::ThisMachine;
/// The scaled bound: each signer, and all strangers together, store 48
/// rows, and one fold reads 192.
const BOUND: usize = 48;

/// `seed`'s root record on `vault`'s heads, signed by its own anchor: what
/// anyone with a fresh key can sign.
fn root_entry(vault: &Vault, owner: EntityId, seed: &RecoveryRootSeed) -> AuthorityLogEntry {
    let fold = vault.authority_fold().unwrap();
    let root = seed.public(&fold.vault_id.unwrap()).unwrap();
    let record = OwnerRootRecord {
        owner,
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    anchor_signed_entry(&fold, &seed.anchor(), AuthorityOp::OwnerRoot(record), 2).unwrap()
}

/// `seed`'s anchor's "yours" mark of a new machine whose install key is
/// `key`, on `vault`'s heads.
fn mark_entry(
    vault: &Vault,
    owner: EntityId,
    seed: &RecoveryRootSeed,
    key: &ed25519_dalek::SigningKey,
) -> (AuthorityLogEntry, EntityId) {
    let fold = vault.authority_fold().unwrap();
    let request = request_for(fold.vault_id.unwrap(), EntityId::now(), key);
    let profile = MachineProfile {
        machine: request.machine,
        owner,
        machine_key: request.machine_key,
        encryption_key: request.encryption_key.clone(),
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
    };
    let op = AuthorityOp::MachineProfile(profile);
    let entry = anchor_signed_entry(&fold, &seed.anchor(), op, 2).unwrap();
    (entry, request.machine)
}

/// `count` fresh anchors' root records replicated to `vault`, one at a time:
/// the seeds of those that land. Each that waits is past the strangers'
/// bound.
fn flood(install: &Fresh, count: usize) -> Vec<RecoveryRootSeed> {
    let mut landed = Vec::new();
    for _ in 0..count {
        let seed = RecoveryRootSeed::generate().unwrap();
        let entry = root_entry(&install.vault, install.owner.actor(), &seed);
        match put_replicated(&install.vault, &entry) {
            Ok(()) => landed.push(seed),
            Err(error) => assert_eq!(error.kind(), ErrorKind::AuthorityLogFull),
        }
    }
    landed
}

/// One sync pass from `from` to `to`: each row `to` lacks, in stage order,
/// through the replicated door. Returns how many wait, past the strangers'
/// bound or with no key to vouch for them yet.
fn drain(from: &Vault, to: &Vault) -> usize {
    let held: BTreeSet<_> = stored_entries(to)
        .iter()
        .map(|entry| authority_entry_hash(entry).unwrap())
        .collect();
    let rows: Vec<_> = stored_entries(from)
        .into_iter()
        .map(|entry| (authority_entry_hash(&entry).unwrap(), entry))
        .filter(|(hash, _)| !held.contains(hash))
        .collect();
    let staged: Vec<_> = rows.iter().map(|(hash, entry)| (*hash, entry)).collect();
    let mut waiting = 0;
    for index in crate::authority::authority_stage_order(&staged) {
        if let Err(error) = put_replicated(to, &rows[index].1) {
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::AuthorityLogFull | ErrorKind::AuthorityLogSignerPending
                ),
                "{error:?}"
            );
            waiting += 1;
        }
    }
    waiting
}

fn awaiting(install: &Fresh) -> Option<AwaitedRoot> {
    install.vault.owner_root_view(None, 0).unwrap().awaiting
}

fn holds_root(vault: &Vault, root: RecoveryRootId) -> bool {
    vault.owner_root_records().unwrap().contains_key(&root)
}

/// What the fold decides for `world` on `install`: its read, its current
/// key, the pin it applies, and this machine's trusted key.
fn decisions(
    install: &Fresh,
    world: EntityId,
) -> (
    EffectiveRead,
    Option<crate::world_keys::WorldKeyId>,
    Option<PinnedRoot>,
    Option<[u8; 32]>,
) {
    let fold = install.vault.authority_fold().unwrap();
    (
        fold.world_privacy(world).read,
        fold.current_world_key(world).map(|key| key.id),
        fold.pinned_root,
        fold.trusted_machine(install.machine())
            .map(|trusted| trusted.profile.machine_key),
    )
}

/// The negative check, at a scaled bound. A stranger's root reaches the
/// owner's issuing install, its anchor marks a machine M, and M signs
/// settings edits until the strangers' bound is full; then four bounds'
/// worth of fresh anchors' root records arrive, one row each. None of them
/// lands, the log raises its typed check, and the fold never passes its
/// budget. Through all of it the owner's anchor marks a machine, its
/// machine keys a world, and a re-issue publishes and pins a new root.
/// Fails before: each fresh anchor stored up to a bound of its own, so the
/// flood passed the fold's budget and the fold refused every owner verb.
#[test]
fn a_flood_of_strangers_rows_never_fails_the_fold() {
    with_rows_per_signer_for_test(BOUND, || {
        let host = host();
        let world = world_row(&host);
        let [issuer, peer] = [(); 2].map(|()| fresh_install(&host));
        let root = issue(&issuer, &[]);
        let owner = issuer.owner.actor();
        let stranger = RecoveryRootSeed::generate().unwrap();
        put_replicated(&issuer.vault, &root_entry(&issuer.vault, owner, &stranger)).unwrap();
        let m_key = ed_key(241);
        let (mark, m) = mark_entry(&issuer.vault, owner, &stranger, &m_key);
        put_replicated(&issuer.vault, &mark).unwrap();
        let (mut strangers, elsewhere) = (2, EntityId::now());
        for seq in 1.. {
            let fold = issuer.vault.authority_fold().unwrap();
            let op = AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world: elsewhere,
                act: owner_act(owner, elsewhere),
                machine: m,
                settings: settings(ReadLocation::OneMachine(m)),
            });
            let parents = fold.append_heads.iter().copied().collect();
            let signer = authority_key_from_ed(&m_key);
            let edit = sign_ed(
                unsigned_entry(fold.vault_id, seq, parents, op, signer, 2),
                &m_key,
            );
            match put_replicated(&issuer.vault, &edit) {
                Ok(()) => strangers += 1,
                Err(error) => {
                    assert_eq!(error.kind(), ErrorKind::AuthorityLogFull);
                    break;
                }
            }
        }
        assert_eq!(strangers, BOUND);
        assert!(flood(&issuer, 4 * BOUND + 1).is_empty());
        let checks = issuer.vault.authority_log_checks().unwrap();
        assert!(checks.iter().any(|check| {
            check.kind == AuthorityLogCheck::UNPINNED_ROOTS && check.count == BOUND as u64
        }));
        assert!(
            !issuer
                .vault
                .authority_fold()
                .unwrap()
                .authority_log_past_bound()
        );

        let request = own_request(&peer.vault);
        issuer
            .vault
            .anchor_machine(
                &issuer.owner,
                HERE,
                &root.seed,
                &request,
                Some(request.code()),
                None,
            )
            .unwrap();
        set_on(&issuer, world, ReadLocation::MyMachines);
        let anchor = root.seed.anchor().verifying_key().to_bytes();
        let fold = issuer.vault.authority_fold().unwrap();
        assert!(!fold.authority_log_past_bound());
        assert!(
            fold.machine(request.machine)
                .is_some_and(|machine| machine.anchored.contains_key(&anchor))
        );
        assert!(fold.current_world_key(world).is_some());
        let again = issue(&issuer, &[]);
        assert_eq!(pinned(&issuer.vault), Some(again.root));
    });
}

/// The Engine's requirement 1, with the awaiting checks. B pins R0 and
/// keys a world; the issuer activates R1 carrying B. Strangers fill B's
/// bound, so R1's record waits there, and its marks with it. The owner pins
/// R1 on B by its fingerprint: the pin stays R0, R1 is awaited, and B's fold
/// is what it was. Another root, and a mark of a stranger's anchor, still
/// wait. The next drain lands R1's record and every mark of its anchor, and
/// B's key and settings decisions are still R0's; the owner item says R1
/// has arrived. Pinning again moves the pin and ends the wait. Fails
/// before: the pin door refused a root the log did not hold, and the flood
/// kept R1 out.
#[test]
fn a_root_held_behind_a_flood_pins_in_two_steps() {
    with_rows_per_signer_for_test(BOUND, || {
        let host = host();
        let world = world_row(&host);
        let [issuer, b] = [(); 2].map(|()| fresh_install(&host));
        let r0 = issue(&issuer, &[]);
        admit(&issuer, &r0, &b);
        set_on(&b, world, ReadLocation::MyMachines);
        let r1 = issue(&issuer, &[b.machine()]);
        let junk = flood(&b, BOUND + 1);
        assert_eq!(junk.len(), BOUND);
        assert!(drain(&issuer.vault, &b.vault) > 0);
        assert!(!holds_root(&b.vault, r1.root));
        let before = decisions(&b, world);
        let fold = b.vault.authority_fold().unwrap();

        let report = b.vault.pin_owner_root(&b.owner, HERE, r1.root).unwrap();
        assert_eq!(report.awaiting, Some(r1.root));
        assert_eq!(pinned(&b.vault), Some(r0.root));
        assert_eq!(b.vault.authority_fold().unwrap(), fold);
        let waiting = AwaitedRoot {
            root: r1.root,
            arrived: false,
        };
        assert_eq!(awaiting(&b), Some(waiting));
        let owner = b.owner.actor();
        let other = root_entry(&b.vault, owner, &RecoveryRootSeed::generate().unwrap());
        let (stranger_mark, _) = mark_entry(&b.vault, owner, &junk[0], &ed_key(242));
        for row in [&other, &stranger_mark] {
            let error = put_replicated(&b.vault, row).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::AuthorityLogFull);
        }

        assert_eq!(drain(&issuer.vault, &b.vault), 0);
        assert!(holds_root(&b.vault, r1.root));
        assert_eq!(decisions(&b, world), before);
        let arrived = AwaitedRoot {
            root: r1.root,
            arrived: true,
        };
        assert_eq!(awaiting(&b), Some(arrived));
        let report = b.vault.pin_owner_root(&b.owner, HERE, r1.root).unwrap();
        assert_eq!(report.awaiting, None);
        assert_eq!(pinned(&b.vault), Some(r1.root));
        assert_eq!(awaiting(&b), None);
    });
}

/// The Engine on (b'), check 7c's carried re-pin. B pins R0 and keys a
/// world with K; the issuer activates R1 carrying B, and B stores R1's
/// record. With room left in B's bound, B stores R1's marks as a
/// stranger's, pins R1 once, and K is current under it. With the bound
/// full, R1's marks wait: the pin moves, but B is not mine under R1, K is
/// not current there, and the owner item names R1. The next drain lands
/// the marks, since R1's anchor is now B's own; the item says they have
/// arrived, and pinning again keys K under R1 and ends the wait. Fails
/// before: the pin door left no item, so the owner could not tell when to
/// pin again.
#[test]
fn a_carried_re_pin_whose_marks_wait_finishes_on_the_second_pin() {
    with_rows_per_signer_for_test(BOUND, || {
        for flooded in [false, true] {
            let host = host();
            let world = world_row(&host);
            let [issuer, b] = [(); 2].map(|()| fresh_install(&host));
            let r0 = issue(&issuer, &[]);
            admit(&issuer, &r0, &b);
            set_on(&b, world, ReadLocation::MyMachines);
            let current = || {
                let fold = b.vault.authority_fold().unwrap();
                fold.current_world_key(world).map(|key| key.id)
            };
            let key = current().unwrap();
            let r1 = issue(&issuer, &[b.machine()]);
            let record = stored_entries(&issuer.vault)
                .into_iter()
                .find(|entry| {
                    matches!(&entry.op, AuthorityOp::OwnerRoot(record) if record.root == r1.root)
                })
                .unwrap();
            put_replicated(&b.vault, &record).unwrap();
            if flooded {
                assert_eq!(flood(&b, BOUND).len(), BOUND - 1);
            }
            assert_eq!(drain(&issuer.vault, &b.vault) > 0, flooded);
            let report = b.vault.pin_owner_root(&b.owner, HERE, r1.root).unwrap();
            assert_eq!(pinned(&b.vault), Some(r1.root));
            if !flooded {
                assert_eq!(report.awaiting, None);
                assert_eq!(awaiting(&b), None);
                assert_eq!(current(), Some(key));
                continue;
            }
            assert_eq!(report.awaiting, Some(r1.root));
            assert_ne!(current(), Some(key));
            let waiting = AwaitedRoot {
                root: r1.root,
                arrived: false,
            };
            assert_eq!(awaiting(&b), Some(waiting));
            assert_eq!(drain(&issuer.vault, &b.vault), 0);
            let arrived = AwaitedRoot {
                root: r1.root,
                arrived: true,
            };
            assert_eq!(awaiting(&b), Some(arrived));
            let report = b.vault.pin_owner_root(&b.owner, HERE, r1.root).unwrap();
            assert_eq!(report.awaiting, None);
            assert_eq!(awaiting(&b), None);
            assert_eq!(current(), Some(key));
        }
    });
}
