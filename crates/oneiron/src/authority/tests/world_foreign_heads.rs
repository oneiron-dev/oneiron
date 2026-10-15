//! Owner doors never name another anchor's rows (Astra S2-R2 A2-F4; Engine
//! ruling, 2026-10-15). A host's own roots never crowd an owner door's
//! parents past the format bound. Owner entries that no longer name those
//! rows fold the same in every arrival order.
use super::machine_identity::{host, request_for};
use super::owner_anchor::{YOURS, agent, enrol_anchor, pin, profile, publish, root_record, signed};
use super::support::{cosign_ed, ed_key, genesis_entry};
use super::world_chain_reads::{edit, fold_under, hash, seeing};
use super::world_key_doors::{Fresh, enrol_own, fresh_install, kit_seed, set};
use super::world_privacy::world_row;
use super::*;
use crate::HostingPrivacyPosture::SelfHostLocal;
use crate::world_keys::{RecoveryRoot, RecoveryRootSeed};

const HERE: EditOrigin = EditOrigin::ThisMachine;

/// What two installs must agree on: the machine, the roster, the roots, the
/// world's read and the valid entries.
fn agreed(
    fold: &AuthorityFold,
    machine: EntityId,
    world: EntityId,
) -> impl PartialEq + std::fmt::Debug {
    (
        fold.machine(machine).cloned(),
        fold.roster.clone(),
        fold.root_anchors().clone(),
        fold.world_privacy(world),
        fold.valid_entries.clone(),
    )
}

/// Astra S2-R2 A2-F4: forty roots a host publishes from its own anchors, all
/// concurrent on the same heads, leave every owner door its parents. An
/// unpinned fresh install restores from the kit, and the owner re-issues.
/// Before, each door named every main-log head: forty-odd parents, past the
/// format bound.
#[test]
fn forty_foreign_roots_never_crowd_a_root_door() {
    let host = host();
    enrol_own(&host);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let seed = kit_seed(host.vault_id, prepared.seed());
    host.vault
        .activate_owner_root(&host.owner, HERE, prepared, &BTreeSet::new())
        .unwrap();
    let world = world_row(&host);
    set(&host, world, ReadLocation::MyMachines);
    let fold = host.vault.authority_fold().unwrap();
    let key = fold.current_world_key(world).unwrap().id;
    let at = TimeRange { start: 2, end: 2 };
    let roots: Vec<_> = (0..40)
        .map(|_| {
            let foreign = RecoveryRootSeed::generate().unwrap();
            let root = foreign.public(&host.vault_id).unwrap();
            let record = OwnerRootRecord {
                owner: host.owner.actor(),
                ..root_record(&root)
            };
            let entry =
                anchor_signed_entry(&fold, &foreign.anchor(), AuthorityOp::OwnerRoot(record), 2)
                    .unwrap();
            (entry, at, 2)
        })
        .collect();
    host.vault.put_authority_log_entries(&roots).unwrap();
    assert_eq!(
        host.vault.owner_root_view(None, 64).unwrap().inert_foreign,
        40
    );

    let Fresh {
        _backups,
        vault: fresh,
        owner,
        ..
    } = fresh_install(&host);
    let restore = fresh.restore_world_keys(&owner, HERE, &seed, None).unwrap();
    assert_eq!(restore.usable, vec![key]);
    assert!(fresh.local_machine().unwrap().unwrap().mine);

    let next = host.vault.prepare_owner_root(&host.owner).unwrap();
    let next_root = next.seed().public(&host.vault_id).unwrap().id;
    host.vault
        .activate_owner_root(&host.owner, HERE, next, &BTreeSet::new())
        .unwrap();
    assert_eq!(
        host.vault.owner_root_view(None, 0).unwrap().pinned,
        Some(next_root)
    );
}

/// Ruling 2's check (a), on the race shape of 7c (Sol R1d-F3). M keeps W
/// on itself, then widens it to `MyMachines`; concurrently the owner removes
/// M through its anchor and through the roster, each removal listing only
/// the first edit. Beside that, a foreign anchor publishes a root and marks
/// M "yours" without naming the removals. In both arrival orders, on an
/// install pinned to the owner's root and on an unpinned one, both removals
/// stand, M is not mine, the widening only narrows, and the two orders fold
/// the same.
#[test]
fn an_owner_removal_beside_a_foreign_root_folds_the_same_in_both_orders() {
    let owner_key = ed_key(150);
    let genesis = genesis_entry(150, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let (owner_root, owner_anchor, owner_published) = publish(id, &genesis);
    let machine_key = ed_key(151);
    let request = request_for(id, EntityId::now(), &machine_key);
    let m = (request.machine, &machine_key);
    let roster_mark = signed(
        id,
        &[&owner_published],
        &owner_key,
        1,
        profile(&request, YOURS, 1),
    );
    let anchor_mark = signed(
        id,
        &[&roster_mark],
        &owner_anchor,
        2,
        profile(&request, YOURS, 1),
    );
    let world = EntityId::now();
    let kept = edit(
        id,
        &[&anchor_mark],
        m,
        1,
        world,
        ReadLocation::OneMachine(request.machine),
    );
    let widened = edit(
        id,
        &[&anchor_mark, &kept],
        m,
        2,
        world,
        ReadLocation::MyMachines,
    );
    let removal = |signer, seq| {
        signed(
            id,
            &[&anchor_mark],
            signer,
            seq,
            seeing(&request, MachineRole::Removed, 2, &[&kept]),
        )
    };
    let removals = [removal(&owner_anchor, 3), removal(&owner_key, 2)];
    let owner_side = [
        owner_published,
        roster_mark,
        anchor_mark.clone(),
        kept,
        widened,
        removals[0].clone(),
        removals[1].clone(),
    ];
    let (_, foreign_anchor, foreign_published) = publish(id, &genesis);
    let foreign_mark = signed(
        id,
        &[&foreign_published, &anchor_mark],
        &foreign_anchor,
        2,
        profile(&request, YOURS, u64::MAX),
    );
    let foreign_side = [foreign_published, foreign_mark.clone()];
    let owner_first: Vec<_> = std::iter::once(&genesis)
        .chain(&owner_side)
        .chain(&foreign_side)
        .cloned()
        .collect();
    let foreign_first: Vec<_> = std::iter::once(&genesis)
        .chain(&foreign_side)
        .chain(&owner_side)
        .cloned()
        .collect();
    for root in [Some(&owner_root), None::<&RecoveryRoot>] {
        let [first, second] =
            [&owner_first, &foreign_first].map(|entries| fold_under(entries, SelfHostLocal, root));
        assert_eq!(
            agreed(&first, request.machine, world),
            agreed(&second, request.machine, world)
        );
        for entry in removals.iter().chain([&foreign_mark]) {
            assert!(first.valid_entries.contains(&hash(entry)));
        }
        let folded = first.machine(request.machine).unwrap();
        assert!(!folded.is_mine(root.map(pin).as_ref()));
        assert_eq!(
            first.world_privacy(world).read,
            EffectiveRead::OneMachine(request.machine)
        );
    }
}

/// Ruling 2's check (b). The owner enrols agent device D, whose key is also
/// the anchor of a root of D's own, then revokes D with a second agent's
/// cosign; D's root does not name the revoke. In both arrival orders, pinned
/// to the owner's root and unpinned, the enrolments and the revoke stand, D
/// is revoked, its root stays foreign, and the two orders fold the same.
#[test]
fn an_owner_revoke_beside_a_root_its_key_signed_folds_the_same_in_both_orders() {
    let owner_key = ed_key(160);
    let genesis = genesis_entry(160, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let (owner_root, _, owner_published) = publish(id, &genesis);
    let second = agent(id, &owner_published, &owner_key, 161);
    let seed = RecoveryRootSeed::generate().unwrap();
    let theirs = seed.public(&id).unwrap();
    let device_key = AuthorityKey::Ed25519(theirs.anchor_key);
    let enrolled = enrol_anchor(id, &second, (&owner_key, &ed_key(161)), 2, &theirs);
    let revoked = cosign_ed(
        signed(
            id,
            &[&enrolled],
            &owner_key,
            3,
            AuthorityOp::RevokeDevice {
                revoked_key: device_key.clone(),
            },
        ),
        &owner_key,
        &ed_key(161),
    );
    let their_root = signed(
        id,
        &[&enrolled],
        &seed.anchor(),
        1,
        AuthorityOp::OwnerRoot(root_record(&theirs)),
    );
    let owner_first = vec![
        genesis.clone(),
        owner_published.clone(),
        second.clone(),
        enrolled.clone(),
        revoked.clone(),
        their_root.clone(),
    ];
    let root_first = vec![
        genesis,
        owner_published,
        second.clone(),
        enrolled.clone(),
        their_root.clone(),
        revoked.clone(),
    ];
    let (nobody, world) = (EntityId::now(), EntityId::now());
    for root in [Some(&owner_root), None::<&RecoveryRoot>] {
        let [first, other] =
            [&owner_first, &root_first].map(|entries| fold_under(entries, SelfHostLocal, root));
        assert_eq!(agreed(&first, nobody, world), agreed(&other, nobody, world));
        for entry in [&second, &enrolled, &revoked, &their_root] {
            assert!(first.valid_entries.contains(&hash(entry)));
        }
        assert!(first.roster[&device_key].revoked);
        assert!(first.root_anchors()[&theirs.anchor_key].contains(&theirs.id));
        assert_ne!(first.pinned_root.map(|pin| pin.id), Some(theirs.id));
    }
}
