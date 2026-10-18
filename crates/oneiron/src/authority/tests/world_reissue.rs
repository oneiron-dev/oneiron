//! World privacy P6b acceptance across a root re-issue (contract §4, checks
//! 7c and 7e): every install is a new install of one vault, and they meet by
//! syncing their authority logs. Losing standing never widens a world, a
//! machine left out of a carry gets its keys back by anchoring itself with
//! the new seed, and only the owner's explicit re-assertion restores a
//! world's earlier settings, keeping its key.
use super::machine_identity::{host, request_for};
use super::support::{authority_key_from_ed, ed_key, owner_act, sign_ed, unsigned_entry};
use super::world_key_doors::{Fresh, fresh_install, kit_seed, opened_by, own_request};
use super::world_privacy::{settings, stored_entries, world_row};
use super::*;
use crate::Vault;
use crate::world_keys::{PolicyRevision, RecoveryRootSeed, Withheld};

const HERE: EditOrigin = EditOrigin::ThisMachine;

/// Every authority entry `from` holds that `to` lacks, landed on `to`.
pub(super) fn sync(from: &Vault, to: &Vault) {
    let held: BTreeSet<_> = stored_entries(to)
        .iter()
        .map(|entry| authority_entry_hash(entry).unwrap())
        .collect();
    let at = TimeRange { start: 2, end: 2 };
    let rows: Vec<_> = stored_entries(from)
        .into_iter()
        .filter(|entry| !held.contains(&authority_entry_hash(entry).unwrap()))
        .map(|entry| (entry, at, 2))
        .collect();
    if !rows.is_empty() {
        to.put_authority_log_entries(&rows).unwrap();
    }
}

pub(super) fn set_on(install: &Fresh, world: EntityId, read: ReadLocation) {
    install
        .vault
        .set_world_privacy_as(
            &install.owner,
            ActSurface::ThisInstall,
            world,
            settings(read),
            None,
        )
        .unwrap();
}

pub(super) fn read_on(install: &Fresh, world: EntityId) -> EffectiveRead {
    install.vault.world_privacy(world).unwrap().read
}

pub(super) fn pinned(vault: &Vault) -> Option<RecoveryRootId> {
    vault.owner_root_view(None, 0).unwrap().pinned
}

/// The world's settings revision on `vault`.
pub(super) fn revision(vault: &Vault, world: EntityId) -> PolicyRevision {
    let fold = vault.authority_fold().unwrap();
    PolicyRevision::of(
        fold.worlds
            .get(&world)
            .into_iter()
            .flat_map(|folded| folded.live.keys().copied()),
    )
}

/// A root issued by `issuer`, with its kit rebuilt from two stored pieces
/// and the root's recovery secret.
pub(super) struct Issued {
    pub(super) root: RecoveryRootId,
    pub(super) seed: RecoveryRootSeed,
    pub(super) recovery: oneiron_crypto::HybridSecretKey,
}

pub(super) fn issue(issuer: &Fresh, carry: &[EntityId]) -> Issued {
    let prepared = issuer.vault.prepare_owner_root(&issuer.owner).unwrap();
    let vault_id = issuer.vault.authority_fold().unwrap().vault_id.unwrap();
    let issued = Issued {
        root: prepared.seed().public(&vault_id).unwrap().id,
        seed: kit_seed(vault_id, prepared.seed()),
        recovery: prepared.seed().recovery_secret().unwrap(),
    };
    issuer
        .vault
        .activate_owner_root(
            &issuer.owner,
            HERE,
            prepared,
            &carry.iter().copied().collect(),
        )
        .unwrap();
    issued
}

/// `install`'s own request, anchored by `by` with `root`'s seed; then
/// `install` learns of it and pins `root` by its fingerprint.
pub(super) fn admit(by: &Fresh, root: &Issued, install: &Fresh) {
    let request = own_request(&install.vault);
    by.vault
        .anchor_machine(
            &by.owner,
            HERE,
            &root.seed,
            &request,
            Some(request.code()),
            None,
        )
        .unwrap();
    sync(&by.vault, &install.vault);
    install
        .vault
        .pin_owner_root(&install.owner, HERE, root.root)
        .unwrap();
}

/// A settings edit `key` signs as `machine` on `vault`'s heads and the
/// world's live edits, as that machine's own door would.
pub(super) fn edit_on(
    vault: &Vault,
    owner: EntityId,
    machine: EntityId,
    key: &SigningKey,
    world: EntityId,
    read: ReadLocation,
) {
    let fold = vault.authority_fold().unwrap();
    let signer = authority_key_from_ed(key);
    let seq = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
    let mut parents = fold.append_heads.clone();
    if let Some(folded) = fold.worlds.get(&world) {
        parents.extend(folded.live.keys().copied());
    }
    let entry = sign_ed(
        unsigned_entry(
            fold.vault_id,
            seq,
            parents.into_iter().collect(),
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                act: owner_act(owner, world),
                machine,
                settings: settings(read),
            }),
            signer,
            2,
        ),
        key,
    );
    vault
        .put_authority_log_entry(&entry, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
}

/// 7c, re-issue without carry: under R1, A sets W to `OneMachine(A)`; the
/// owner re-issues R2 without carrying A. On the issuer, on a fresh install
/// pinned to R2 by fingerprint, on one pinned to a third root and on an
/// unpinned one, W reads no wider than `OneMachine(A)`. Under R2's admitter
/// W is orphaned, and the issuer re-picks it at full strength.
#[test]
fn a_re_issue_without_carry_never_widens() {
    let host = host();
    let world = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let second_pin = fresh_install(&host);
    let third_pin = fresh_install(&host);
    let unpinned = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    set_on(&a, world, ReadLocation::OneMachine(a.machine()));
    sync(&a.vault, &issuer.vault);
    let second = issue(&issuer, &[]);
    let third = publish_root_on(&third_pin);
    for install in [&second_pin, &third_pin, &unpinned] {
        sync(&issuer.vault, &install.vault);
    }
    second_pin
        .vault
        .pin_owner_root(&second_pin.owner, HERE, second.root)
        .unwrap();
    third_pin
        .vault
        .pin_owner_root(&third_pin.owner, HERE, third)
        .unwrap();
    for install in [&issuer, &second_pin, &third_pin, &unpinned] {
        assert_eq!(
            read_on(install, world),
            EffectiveRead::OneMachine(a.machine())
        );
    }
    assert_eq!(
        issuer
            .vault
            .authority_fold()
            .unwrap()
            .world_edit_standing(issuer.machine(), world),
        Some(WorldEditStanding::RepicksOrphan)
    );
    set_on(&issuer, world, ReadLocation::OneMachine(issuer.machine()));
    sync(&issuer.vault, &second_pin.vault);
    for install in [&issuer, &second_pin] {
        assert_eq!(
            read_on(install, world),
            EffectiveRead::OneMachine(issuer.machine())
        );
    }
}

/// A root of an anchor nobody else trusts, published on `install`.
pub(super) fn publish_root_on(install: &Fresh) -> RecoveryRootId {
    let seed = RecoveryRootSeed::generate().unwrap();
    let vault_id = install.vault.authority_fold().unwrap().vault_id.unwrap();
    let root = seed.public(&vault_id).unwrap();
    let record = OwnerRootRecord {
        owner: install.owner.actor(),
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    let fold = install.vault.authority_fold().unwrap();
    let entry =
        anchor_signed_entry(&fold, &seed.anchor(), AuthorityOp::OwnerRoot(record), 2).unwrap();
    install
        .vault
        .put_authority_log_entry(&entry, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
    root.id
}

/// 7c, re-assertion keeps a widening (Sol R1b-F2): under R1, A sets W to
/// `OneMachine(A)` and widens it to `MyMachines`; the re-issue carries A.
/// R2 installs read `OneMachine(A)` until the owner acts. A re-pins and
/// lists W as narrowed, with A as its earlier signer, mine under R2; the
/// owner re-asserts `MyMachines` from A, and R2 installs read it.
#[test]
fn re_assertion_keeps_a_widening() {
    let host = host();
    let world = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    set_on(&a, world, ReadLocation::OneMachine(a.machine()));
    set_on(&a, world, ReadLocation::MyMachines);
    sync(&a.vault, &issuer.vault);
    let second = issue(&issuer, &[a.machine()]);
    assert_eq!(
        read_on(&issuer, world),
        EffectiveRead::OneMachine(a.machine())
    );
    sync(&issuer.vault, &a.vault);
    assert_eq!(read_on(&a, world), EffectiveRead::MyMachines);

    let report = a.vault.pin_owner_root(&a.owner, HERE, second.root).unwrap();
    assert_eq!(report.narrowed.len(), 1);
    let narrowed = &report.narrowed[0];
    assert_eq!(narrowed.world, world);
    assert_eq!(narrowed.earlier.read, EffectiveRead::MyMachines);
    assert_eq!(narrowed.now.read, EffectiveRead::OneMachine(a.machine()));
    assert_eq!(narrowed.earlier_signers, vec![(a.machine(), true)]);
    assert_eq!(read_on(&a, world), EffectiveRead::OneMachine(a.machine()));

    a.vault
        .reassert_world_privacy(
            &a.owner,
            HERE,
            world,
            settings(ReadLocation::MyMachines),
            revision(&a.vault, world),
        )
        .unwrap();
    sync(&a.vault, &issuer.vault);
    for install in [&a, &issuer] {
        assert_eq!(read_on(install, world), EffectiveRead::MyMachines);
    }
}

/// 7c, the narrowed report at scale (Sol R1c-F4; the Engine's scaled
/// oracle, 2026-10-15): under R1, A holds 24 worlds, each set to
/// `OneMachine(A)` and widened to `MyMachines`; the re-issue carries A. A's
/// re-pin lists every one as narrowed, and re-asserting each restores
/// `MyMachines` on R2 installs. Nothing on the report path caps it (the
/// carry list's 4096 cap is gone); 24 stands in for "more than 4096", which
/// a lib-test fold cannot reach in time (48 took 26 minutes in debug).
#[test]
fn the_narrowed_report_lists_every_world_at_scale() {
    const WORLDS: usize = 24;
    let host = host();
    let worlds: BTreeSet<_> = (0..WORLDS).map(|_| world_row(&host)).collect();
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    for world in &worlds {
        set_on(&a, *world, ReadLocation::OneMachine(a.machine()));
        set_on(&a, *world, ReadLocation::MyMachines);
    }
    sync(&a.vault, &issuer.vault);
    let second = issue(&issuer, &[a.machine()]);
    sync(&issuer.vault, &a.vault);

    let report = a.vault.pin_owner_root(&a.owner, HERE, second.root).unwrap();
    let narrowed: BTreeSet<_> = report
        .narrowed
        .iter()
        .map(|narrowed| narrowed.world)
        .collect();
    assert_eq!(narrowed, worlds);
    for world in &worlds {
        a.vault
            .reassert_world_privacy(
                &a.owner,
                HERE,
                *world,
                settings(ReadLocation::MyMachines),
                revision(&a.vault, *world),
            )
            .unwrap();
    }
    sync(&a.vault, &issuer.vault);
    for world in &worlds {
        for install in [&a, &issuer] {
            assert_eq!(read_on(install, *world), EffectiveRead::MyMachines);
        }
    }
}

/// 7c, a compromised old root's late widening is never promoted (Sol
/// R1h-F1): R2 carries A while A still pins R1. A holder of R1's seed then
/// admits its own machine H under R1, and H widens W from `MyMachines` to
/// everywhere. A re-pins to R2: no settings edit is appended, W reads
/// `MyMachines`, and the narrowed report flags H as not mine.
#[test]
fn a_compromised_old_roots_late_widening_is_never_promoted() {
    let host = host();
    let world = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    set_on(&a, world, ReadLocation::MyMachines);
    sync(&a.vault, &issuer.vault);
    let second = issue(&issuer, &[a.machine()]);
    sync(&issuer.vault, &a.vault);

    let vault_id = a.vault.authority_fold().unwrap().vault_id.unwrap();
    let h_key = ed_key(81);
    let h = request_for(vault_id, EntityId::now(), &h_key);
    let mark = AuthorityOp::MachineProfile(MachineProfile {
        machine: h.machine,
        owner: a.owner.actor(),
        machine_key: h.machine_key,
        encryption_key: h.encryption_key.clone(),
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof: h.machine_proof,
        seen_world_edits: BTreeSet::new(),
    });
    let fold = a.vault.authority_fold().unwrap();
    let entry = anchor_signed_entry(&fold, &first.seed.anchor(), mark, 2).unwrap();
    a.vault
        .put_authority_log_entry(&entry, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
    edit_on(
        &a.vault,
        a.owner.actor(),
        h.machine,
        &h_key,
        world,
        ReadLocation::Everywhere,
    );
    assert_eq!(read_on(&a, world), EffectiveRead::Everywhere);

    let edits = |vault: &Vault| {
        stored_entries(vault)
            .iter()
            .filter(|entry| matches!(entry.op, AuthorityOp::WorldPrivacy(_)))
            .count()
    };
    let before = edits(&a.vault);
    let report = a.vault.pin_owner_root(&a.owner, HERE, second.root).unwrap();
    assert_eq!(edits(&a.vault), before);
    assert_eq!(read_on(&a, world), EffectiveRead::MyMachines);
    let narrowed = report
        .narrowed
        .iter()
        .find(|narrowed| narrowed.world == world)
        .unwrap();
    assert_eq!(narrowed.earlier.read, EffectiveRead::Everywhere);
    assert!(narrowed.earlier_signers.contains(&(h.machine, false)));
}

/// 7e, own-request anchoring of a left-out machine (Sol R1c-F2): A pins R1
/// and alone reads W = `OneMachine(A)` with key K. Another install issues
/// R2 without carrying A, so it cannot open K. A anchors its own request
/// with R2's seed, directly or after first re-pinning to R2 by fingerprint
/// (K withheld `NotMine`): K is rewrapped, and after a reopen A opens it,
/// and so does R2's seed.
#[test]
fn a_left_out_machine_anchors_itself_back_and_keeps_its_key() {
    for repin_first in [false, true] {
        let host = host();
        let world = world_row(&host);
        let issuer = fresh_install(&host);
        let mut a = fresh_install(&host);
        let first = issue(&issuer, &[]);
        admit(&issuer, &first, &a);
        set_on(&a, world, ReadLocation::OneMachine(a.machine()));
        let key = *a.vault.world_key(world).unwrap().id();
        sync(&a.vault, &issuer.vault);
        let second = issue(&issuer, &[]);
        sync(&issuer.vault, &a.vault);
        if repin_first {
            let report = a.vault.pin_owner_root(&a.owner, HERE, second.root).unwrap();
            assert_eq!(report.withheld, vec![(key, Withheld::NotMine)]);
            assert!(a.vault.world_key(world).is_err());
            a = a.reopen();
        }
        let own = own_request(&a.vault);
        let anchored = a
            .vault
            .anchor_machine(&a.owner, HERE, &second.seed, &own, None, None)
            .unwrap();
        assert_eq!(anchored.repin.unwrap().rewrapped, vec![key]);
        assert_eq!(pinned(&a.vault), Some(second.root));
        let a = a.reopen();
        let opened = a.vault.world_key(world).unwrap();
        assert_eq!(opened.id(), &key);
        let vault_id = a.vault.authority_fold().unwrap().vault_id.unwrap();
        assert_eq!(
            opened_by(
                &a.vault,
                vault_id,
                key,
                WrapRecipient::RecoveryRoot(second.root),
                &second.recovery
            ),
            BTreeSet::from([opened.commitment()])
        );
    }
}

/// 7e, a left-out recipient whose key records another machine signed (Sol
/// R1e-F2): R1 admits A and B; W reads on the owner's machines and A mints
/// K, wrapped to A, B and R1. R2 is issued from an install that holds no
/// K, carrying neither. B re-pins to R2 (K withheld `NotMine`), reopens and
/// anchors its own request with R2's seed: K is rewrapped, B opens it after
/// a reopen, and R2's seed opens it.
#[test]
fn a_left_out_recipient_anchors_itself_back_from_records_another_signed() {
    let host = host();
    let world = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let b = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    admit(&issuer, &first, &b);
    sync(&issuer.vault, &a.vault);
    set_on(&a, world, ReadLocation::MyMachines);
    let key = *a.vault.world_key(world).unwrap().id();
    sync(&a.vault, &b.vault);
    assert_eq!(b.vault.world_key(world).unwrap().id(), &key);

    let other = fresh_install(&host);
    let second = issue(&other, &[]);
    sync(&other.vault, &b.vault);
    let report = b.vault.pin_owner_root(&b.owner, HERE, second.root).unwrap();
    assert_eq!(report.withheld, vec![(key, Withheld::NotMine)]);
    let b = b.reopen();
    let own = own_request(&b.vault);
    let anchored = b
        .vault
        .anchor_machine(&b.owner, HERE, &second.seed, &own, None, None)
        .unwrap();
    assert_eq!(anchored.repin.unwrap().rewrapped, vec![key]);
    let b = b.reopen();
    let opened = b.vault.world_key(world).unwrap();
    assert_eq!(opened.id(), &key);
    let vault_id = b.vault.authority_fold().unwrap().vault_id.unwrap();
    assert_eq!(
        opened_by(
            &b.vault,
            vault_id,
            key,
            WrapRecipient::RecoveryRoot(second.root),
            &second.recovery
        ),
        BTreeSet::from([opened.commitment()])
    );
}

/// 7c, a recipient's key survives an explicit re-assertion (Sol R1i-F1):
/// R1 admits A and B. B sets W to `OneMachine(B)`, mints K, then widens W to
/// `MyMachines`, so K is wrapped to A, B and R1, every record B's. R2
/// carries A and B. A re-pins: K is withheld `NotReadable`, and A pre-wraps
/// it. After a reopen the owner re-asserts `MyMachines` from A: the same
/// transaction wraps K again under R2, A opens K, and R2's seed opens it.
#[test]
fn a_recipients_key_survives_an_explicit_re_assertion() {
    let host = host();
    let world = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let b = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    admit(&issuer, &first, &b);
    sync(&issuer.vault, &b.vault);
    set_on(&b, world, ReadLocation::OneMachine(b.machine()));
    let key = *b.vault.world_key(world).unwrap().id();
    set_on(&b, world, ReadLocation::MyMachines);
    sync(&b.vault, &a.vault);
    sync(&b.vault, &issuer.vault);
    assert_eq!(a.vault.world_key(world).unwrap().id(), &key);

    let second = issue(&issuer, &[a.machine(), b.machine()]);
    sync(&issuer.vault, &a.vault);
    let report = a.vault.pin_owner_root(&a.owner, HERE, second.root).unwrap();
    assert_eq!(report.withheld, vec![(key, Withheld::NotReadable)]);
    let a = a.reopen();
    a.vault
        .reassert_world_privacy(
            &a.owner,
            HERE,
            world,
            settings(ReadLocation::MyMachines),
            revision(&a.vault, world),
        )
        .unwrap();
    let opened = a.vault.world_key(world).unwrap();
    assert_eq!(opened.id(), &key);
    let vault_id = a.vault.authority_fold().unwrap().vault_id.unwrap();
    assert_eq!(
        opened_by(
            &a.vault,
            vault_id,
            key,
            WrapRecipient::RecoveryRoot(second.root),
            &second.recovery
        ),
        BTreeSet::from([opened.commitment()])
    );
}

/// 7c, no earlier admitter (Sol R1i-F2): a fresh, unpinned B holds W, which
/// A set to `OneMachine(A)` and widened to `MyMachines` under R1. B restores
/// R1's seed: the narrowed report's earlier settings are B's own local
/// settings before the door, `OneMachine(A)`, and the pin keeps no earlier
/// admitter, so a re-assertion has no extra standing source.
#[test]
fn a_restore_with_no_earlier_admitter_reports_the_local_settings() {
    let host = host();
    let world = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let b = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    set_on(&a, world, ReadLocation::OneMachine(a.machine()));
    set_on(&a, world, ReadLocation::MyMachines);
    sync(&a.vault, &b.vault);
    assert_eq!(read_on(&b, world), EffectiveRead::OneMachine(a.machine()));

    let restore = b
        .vault
        .restore_world_keys(&b.owner, HERE, &first.seed, None)
        .unwrap();
    let narrowed = restore
        .narrowed
        .iter()
        .find(|narrowed| narrowed.world == world)
        .unwrap();
    assert_eq!(
        narrowed.earlier.read,
        EffectiveRead::OneMachine(a.machine())
    );
    assert_eq!(read_on(&b, world), EffectiveRead::MyMachines);
    let txn = b.vault.store.env.read_txn().unwrap();
    let (pin, earlier) = read_pin_and_earlier_in_txn(&b.vault.store, &txn).unwrap();
    assert_eq!(pin.map(|pin| pin.id), Some(first.root));
    assert_eq!(earlier, None);
}
