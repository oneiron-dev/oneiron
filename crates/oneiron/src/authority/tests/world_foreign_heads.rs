//! Owner doors never name another anchor's rows (Astra S2-R2 A2-F4; Engine
//! ruling, 2026-10-15). A host's own roots never crowd an owner door's
//! parents past the format bound. Owner entries that no longer name those
//! rows fold the same in every arrival order.
use super::machine_identity::{host, request_for};
use super::owner_anchor::{YOURS, pin, profile, publish, root_record, signed};
use super::support::{authority_key_from_ed, device, ed_key, genesis_entry};
use super::world_chain_reads::{edit, fold_under, hash};
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

/// Ruling 2's check (a). The owner removes M through its pinned anchor and
/// through the roster after M widened a world. Beside that, a foreign anchor
/// publishes a root and marks M "yours" without naming the removals. In both
/// arrival orders, on an install pinned to the owner's root and on an
/// unpinned one, M is not mine, and the two orders fold the same.
#[test]
fn an_owner_removal_beside_a_foreign_root_folds_the_same_in_both_orders() {
    let owner_key = ed_key(150);
    let genesis = genesis_entry(150, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let (owner_root, owner_anchor, owner_published) = publish(id, &genesis);
    let machine_key = ed_key(151);
    let request = request_for(id, EntityId::now(), &machine_key);
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
    let widened = edit(
        id,
        &[&anchor_mark],
        (request.machine, &machine_key),
        1,
        world,
        ReadLocation::MyMachines,
    );
    let removed = MachineRole::Removed;
    let owner_side = [
        owner_published.clone(),
        roster_mark.clone(),
        anchor_mark.clone(),
        widened.clone(),
        signed(
            id,
            &[&widened],
            &owner_anchor,
            3,
            profile(&request, removed, 2),
        ),
        signed(
            id,
            &[&widened],
            &owner_key,
            2,
            profile(&request, removed, 2),
        ),
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
        assert!(first.valid_entries.contains(&hash(&foreign_mark)));
        let folded = first.machine(request.machine).unwrap();
        assert!(!folded.is_mine(root.map(pin).as_ref()));
        assert_ne!(first.world_privacy(world).read, EffectiveRead::Everywhere);
    }
}

/// Ruling 2's check (b). The owner revokes roster device D while D's key,
/// as an anchor, publishes a root of its own that does not name the revoke.
/// In both arrival orders, pinned to the owner's root and unpinned, D is
/// revoked, its root stays foreign, and the two orders fold the same.
#[test]
fn an_owner_revoke_beside_a_root_its_key_signed_folds_the_same_in_both_orders() {
    let owner_key = ed_key(160);
    let genesis = genesis_entry(160, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let (owner_root, _, owner_published) = publish(id, &genesis);
    let seed = RecoveryRootSeed::generate().unwrap();
    let anchor = seed.anchor();
    let device_key = authority_key_from_ed(&anchor);
    let theirs = seed.public(&id).unwrap();
    let enrolled = signed(
        id,
        &[&owner_published],
        &owner_key,
        1,
        AuthorityOp::EnrollDevice {
            device: device(device_key.clone(), ROLE_ADMIN, AuthorityTier::Software),
        },
    );
    let revoked = signed(
        id,
        &[&enrolled],
        &owner_key,
        2,
        AuthorityOp::RevokeDevice {
            revoked_key: device_key.clone(),
        },
    );
    let their_root = signed(
        id,
        &[&enrolled],
        &anchor,
        1,
        AuthorityOp::OwnerRoot(root_record(&theirs)),
    );
    let owner_first = vec![
        genesis.clone(),
        owner_published.clone(),
        enrolled.clone(),
        revoked.clone(),
        their_root.clone(),
    ];
    let root_first = vec![
        genesis,
        owner_published,
        enrolled,
        their_root.clone(),
        revoked,
    ];
    let (nobody, world) = (EntityId::now(), EntityId::now());
    for root in [Some(&owner_root), None::<&RecoveryRoot>] {
        let [first, second] =
            [&owner_first, &root_first].map(|entries| fold_under(entries, SelfHostLocal, root));
        assert_eq!(
            agreed(&first, nobody, world),
            agreed(&second, nobody, world)
        );
        assert!(first.roster[&device_key].revoked);
        assert!(first.valid_entries.contains(&hash(&their_root)));
        assert!(first.root_anchors()[&theirs.anchor_key].contains(&theirs.id));
        assert_ne!(first.pinned_root.map(|pin| pin.id), Some(theirs.id));
    }
}
