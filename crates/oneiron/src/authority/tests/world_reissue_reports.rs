//! World privacy P6b acceptance for the pin doors' reports across a re-issue
//! (contract §4, checks 7c and 7e): a carried machine re-pins with its keys,
//! an activation always heads its own anchor chain, a model-order conflict
//! stays the owner's to resolve, and an edit a clone made under the old root
//! is never offered for re-assertion.
use super::machine_identity::request_for;
use super::support::ed_key;
use super::world_key_doors::{Fresh, enrol_own, fresh_install, keyed_machine};
use super::world_privacy::{settings, stored_entries, world_row};
use super::world_reissue::{admit, edit_on, issue, pinned, read_on, revision, set_on, sync};
use super::*;
use crate::world_keys::RecoveryRootSeed;

const HERE: EditOrigin = EditOrigin::ThisMachine;

/// 7e: R1 admits A and B, and A mints W's key K, wrapped to every machine
/// of the owner's. The issuer re-issues R2 carrying B but not A. B re-pins
/// and K is rewrapped for it: the pin commits, B opens K after a reopen,
/// and a fresh install pinned to R2 counts B as the owner's and not A.
#[test]
fn a_carried_machine_re_pins_with_its_keys() {
    let (host, world) = host_with_world();
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let b = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    admit(&issuer, &first, &b);
    sync(&issuer.vault, &a.vault);
    set_on(&a, world, ReadLocation::MyMachines);
    let key = *a.vault.world_key(world).unwrap().id();
    sync(&a.vault, &issuer.vault);
    let second = issue(&issuer, &[b.machine()]);
    sync(&issuer.vault, &b.vault);
    let report = b.vault.pin_owner_root(&b.owner, HERE, second.root).unwrap();
    assert_eq!(report.rewrapped, vec![key]);
    assert!(report.withheld.is_empty());
    assert_eq!(pinned(&b.vault), Some(second.root));
    let b = b.reopen();
    assert_eq!(b.vault.world_key(world).unwrap().id(), &key);

    sync(&issuer.vault, &host.vault);
    let fresh = fresh_install(&host);
    fresh
        .vault
        .pin_owner_root(&fresh.owner, HERE, second.root)
        .unwrap();
    let fold = fresh.vault.authority_fold().unwrap();
    assert!(fold.trusted_machine(b.machine()).is_some());
    assert!(fold.trusted_machine(a.machine()).is_none());
}

fn host_with_world() -> (super::machine_identity::Host, EntityId) {
    let host = super::machine_identity::host();
    let world = world_row(&host);
    (host, world)
}

/// 7e: an activation on an install the roster already makes the owner's
/// still heads the new anchor's chain, and that chain is the trusted one
/// under the new pin. A re-issue carrying another roster machine marks it
/// under the newer anchor too, and it is the owner's there.
#[test]
fn an_activation_on_a_roster_mine_install_still_heads_its_anchor_chain() {
    let host = super::machine_identity::host();
    let own = enrol_own(&host);
    let other = keyed_machine(&host, 236);
    let anchor_of = |prepared: &crate::world_keys::PreparedRoot| {
        prepared.seed().anchor().verifying_key().to_bytes()
    };
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let first = anchor_of(&prepared);
    host.vault
        .activate_owner_root(&host.owner, HERE, prepared, &BTreeSet::new())
        .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    assert!(fold.machine(own).unwrap().anchored[&first].says_yours());
    assert_eq!(
        fold.trusted_machine(own).unwrap().chain,
        MachineAdmitter::Anchor(first)
    );
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let second = anchor_of(&prepared);
    host.vault
        .activate_owner_root(
            &host.owner,
            HERE,
            prepared,
            &BTreeSet::from([other.machine]),
        )
        .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    for machine in [own, other.machine] {
        assert!(fold.machine(machine).unwrap().anchored[&second].says_yours());
        assert_eq!(
            fold.trusted_machine(machine).unwrap().chain,
            MachineAdmitter::Anchor(second)
        );
    }
}

/// `install`'s full settings edit of `world`.
fn set_full(install: &Fresh, world: EntityId, privacy: WorldPrivacy) {
    install
        .vault
        .set_world_privacy_as(
            &install.owner,
            ActSurface::ThisInstall,
            world,
            privacy,
            None,
        )
        .unwrap();
}

/// 7c, a model-order conflict is the owner's to resolve (Sol R1h-F2): under
/// R1, A widens W to `MyMachines`, then A and B concurrently set two
/// different model orders, so W's model order is conflicted. R2 carries A,
/// and A re-pins: the narrowed report shows the earlier conflicted order,
/// and nothing is edited. Only the owner's re-assertion of a complete
/// setting changes W.
#[test]
fn a_model_order_conflict_is_reported_and_never_resolved_by_the_engine() {
    let (host, world) = host_with_world();
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let b = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    admit(&issuer, &first, &b);
    sync(&issuer.vault, &a.vault);
    set_on(&a, world, ReadLocation::OneMachine(a.machine()));
    set_on(&a, world, ReadLocation::MyMachines);
    sync(&a.vault, &b.vault);
    let ordered = |route: &str| WorldPrivacy {
        models: ModelOrder::Ordered(vec![route.to_owned()]),
        ..settings(ReadLocation::MyMachines)
    };
    set_full(&a, world, ordered("route-a"));
    set_full(&b, world, ordered("route-b"));
    sync(&b.vault, &a.vault);
    sync(&a.vault, &issuer.vault);
    assert_eq!(
        a.vault.world_privacy(world).unwrap().models,
        EffectiveModelOrder::Conflicted
    );
    let second = issue(&issuer, &[a.machine()]);
    sync(&issuer.vault, &a.vault);
    let edits = |install: &Fresh| {
        stored_entries(&install.vault)
            .iter()
            .filter(|entry| matches!(entry.op, AuthorityOp::WorldPrivacy(_)))
            .count()
    };
    let before = edits(&a);
    let report = a.vault.pin_owner_root(&a.owner, HERE, second.root).unwrap();
    assert_eq!(edits(&a), before);
    let narrowed = report
        .narrowed
        .iter()
        .find(|narrowed| narrowed.world == world)
        .unwrap();
    assert_eq!(narrowed.earlier.models, EffectiveModelOrder::Conflicted);
    assert_eq!(narrowed.earlier.read, EffectiveRead::MyMachines);

    a.vault
        .reassert_world_privacy(
            &a.owner,
            HERE,
            world,
            ordered("route-a"),
            revision(&a.vault, world),
        )
        .unwrap();
    let now = a.vault.world_privacy(world).unwrap();
    assert_eq!(now.read, EffectiveRead::MyMachines);
    assert_eq!(
        now.models,
        EffectiveModelOrder::Ordered(vec!["route-a".to_owned()])
    );
}

/// `seed`'s root, published on `install` by its own anchor.
fn root_on(install: &Fresh, seed: &RecoveryRootSeed) {
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
}

/// 7c, a clone's edit is never offered (Wonder R1c-F1, Sol R1i-F3): under
/// R1, A holds W at `OneMachine(A)`, and a host clone of A's id, with the
/// host's keys under the host's own root, widens W to everywhere. On A the
/// clone's edit was restriction-only all along, so W reads `OneMachine(A)`
/// under R1 and, once A re-pins to R2, under R2; the narrowed report never
/// offers everywhere for W.
#[test]
fn a_clones_widening_is_never_offered_for_re_assertion() {
    let (host, world) = host_with_world();
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    set_on(&a, world, ReadLocation::OneMachine(a.machine()));

    let host_seed = RecoveryRootSeed::generate().unwrap();
    root_on(&a, &host_seed);
    let vault_id = a.vault.authority_fold().unwrap().vault_id.unwrap();
    let clone_key = ed_key(237);
    let clone = request_for(vault_id, a.machine(), &clone_key);
    let mark = AuthorityOp::MachineProfile(MachineProfile {
        machine: clone.machine,
        owner: a.owner.actor(),
        machine_key: clone.machine_key,
        encryption_key: clone.encryption_key.clone(),
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof: clone.machine_proof,
        seen_world_edits: BTreeSet::new(),
    });
    let fold = a.vault.authority_fold().unwrap();
    let entry = anchor_signed_entry(&fold, &host_seed.anchor(), mark, 2).unwrap();
    a.vault
        .put_authority_log_entry(&entry, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
    edit_on(
        &a.vault,
        a.owner.actor(),
        a.machine(),
        &clone_key,
        world,
        ReadLocation::Everywhere,
    );
    assert_eq!(read_on(&a, world), EffectiveRead::OneMachine(a.machine()));

    sync(&a.vault, &issuer.vault);
    let second = issue(&issuer, &[a.machine()]);
    sync(&issuer.vault, &a.vault);
    let report = a.vault.pin_owner_root(&a.owner, HERE, second.root).unwrap();
    assert_eq!(read_on(&a, world), EffectiveRead::OneMachine(a.machine()));
    assert!(
        report
            .narrowed
            .iter()
            .all(|narrowed| narrowed.world != world)
    );
}
