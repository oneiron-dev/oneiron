//! World privacy P6b acceptance for the pin doors (contract §5, check 7e):
//! only this machine's own call moves its pin or appends a mark; another
//! machine's request is anchored only with the code that machine shows, and
//! only with the pinned root's seed; and a world that reads everywhere is
//! reported by every pin door and never wrapped.
use super::machine_identity::{host, request_for};
use super::support::ed_key;
use super::world_key_doors::{enrol_own, key_records, kit_seed, own_request, set};
use super::world_kit_gate::publish_root;
use super::world_privacy::{stored_entries, world_row};
use super::*;
use crate::Vault;
use crate::world_keys::{RecoveryRootSeed, RepinReport, Withheld};

fn pinned(vault: &Vault) -> Option<RecoveryRootId> {
    vault.owner_root_view(None, 0).unwrap().pinned
}

/// A remote call to any pin door, a fully valid request other than the one
/// the new machine shows, and a request with no code change neither the pin
/// nor any chain, and append nothing. The new machine's own request with
/// the code it shows is anchored under the pinned root, and the pin stays.
#[test]
fn only_this_machines_own_call_moves_its_pin_or_anchors() {
    let host = host();
    enrol_own(&host);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let seed = kit_seed(host.vault_id, prepared.seed());
    let root = prepared.seed().public(&host.vault_id).unwrap().id;
    let here = EditOrigin::ThisMachine;
    host.vault
        .activate_owner_root(&host.owner, here, prepared, &BTreeSet::new())
        .unwrap();
    let new = request_for(host.vault_id, EntityId::now(), &ed_key(71));
    let substitute = request_for(host.vault_id, EntityId::now(), &ed_key(72));
    let stored = stored_entries(&host.vault).len();

    let remote = EditOrigin::Peer(PeerMachine::Unknown);
    let next = host.vault.prepare_owner_root(&host.owner).unwrap();
    assert!(
        host.vault
            .activate_owner_root(&host.owner, remote, next, &BTreeSet::new())
            .is_err()
    );
    assert!(
        host.vault
            .anchor_machine(&host.owner, remote, &seed, &new, Some(new.code()), None)
            .is_err()
    );
    assert!(
        host.vault
            .restore_world_keys(&host.owner, remote, &seed, None)
            .is_err()
    );
    assert!(
        host.vault
            .pin_owner_root(&host.owner, remote, root)
            .is_err()
    );
    assert!(
        host.vault
            .anchor_machine(
                &host.owner,
                here,
                &seed,
                &substitute,
                Some(new.code()),
                None
            )
            .is_err()
    );
    assert!(
        host.vault
            .anchor_machine(&host.owner, here, &seed, &new, None, None)
            .is_err()
    );
    assert_eq!(stored_entries(&host.vault).len(), stored);
    assert_eq!(pinned(&host.vault), Some(root));
    let fold = host.vault.authority_fold().unwrap();
    assert!(fold.machine(new.machine).is_none());
    assert!(fold.machine(substitute.machine).is_none());

    let anchored = host
        .vault
        .anchor_machine(&host.owner, here, &seed, &new, Some(new.code()), None)
        .unwrap();
    assert!(anchored.repin.is_none());
    assert_eq!(pinned(&host.vault), Some(root));
    let fold = host.vault.authority_fold().unwrap();
    assert!(fold.trusted_machine(new.machine).is_some());
}

/// An install pinned to root R never anchors a new machine with another
/// root S's seed, and its pin stays R (Wonder R1n-F3). Once it moves itself
/// to S by anchoring its own request with S's seed, it anchors the new
/// machine under S and shows S's fingerprint.
#[test]
fn an_install_anchors_another_machine_only_with_its_pinned_roots_seed() {
    let host = host();
    enrol_own(&host);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let first = prepared.seed().public(&host.vault_id).unwrap().id;
    let here = EditOrigin::ThisMachine;
    host.vault
        .activate_owner_root(&host.owner, here, prepared, &BTreeSet::new())
        .unwrap();
    let drawn = RecoveryRootSeed::generate().unwrap();
    let second = publish_root(&host, &drawn);
    let seed = kit_seed(host.vault_id, &drawn);
    let new = request_for(host.vault_id, EntityId::now(), &ed_key(73));
    let stored = stored_entries(&host.vault).len();

    assert!(
        host.vault
            .anchor_machine(&host.owner, here, &seed, &new, Some(new.code()), None)
            .is_err()
    );
    assert_eq!(stored_entries(&host.vault).len(), stored);
    assert_eq!(pinned(&host.vault), Some(first));

    let own = own_request(&host.vault);
    let moved = host
        .vault
        .anchor_machine(&host.owner, here, &seed, &own, None, None)
        .unwrap();
    assert!(moved.repin.is_some());
    assert_eq!(pinned(&host.vault), Some(second));
    host.vault
        .anchor_machine(&host.owner, here, &seed, &new, Some(new.code()), None)
        .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    let trusted = fold.trusted_machine(new.machine).unwrap();
    let anchor = drawn.public(&host.vault_id).unwrap().anchor_key;
    assert_eq!(trusted.chain, MachineAdmitter::Anchor(anchor));
}

/// A key this machine holds for a world it then widened to everywhere is
/// reported withheld as not private by every pin door, and none of them
/// wraps it again (Sol R1d-F2).
#[test]
fn a_world_that_reads_everywhere_is_reported_and_never_wrapped_by_a_pin_door() {
    let host = host();
    enrol_own(&host);
    let world = world_row(&host);
    set(&host, world, ReadLocation::MyMachines);
    let key = *host.vault.world_key(world).unwrap().id();
    set(&host, world, ReadLocation::Everywhere);
    let records = key_records(&host.vault, world).len();
    let not_private = |report: &RepinReport| {
        report.rewrapped.is_empty() && report.withheld == vec![(key, Withheld::NotPrivate)]
    };
    let here = EditOrigin::ThisMachine;

    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let seed = kit_seed(host.vault_id, prepared.seed());
    let activated = host
        .vault
        .activate_owner_root(&host.owner, here, prepared, &BTreeSet::new())
        .unwrap();
    assert!(not_private(&activated.keys));
    let other = publish_root(&host, &RecoveryRootSeed::generate().unwrap());
    let repinned = host.vault.pin_owner_root(&host.owner, here, other).unwrap();
    assert!(not_private(&repinned));
    let own = own_request(&host.vault);
    let anchored = host
        .vault
        .anchor_machine(&host.owner, here, &seed, &own, None, None)
        .unwrap();
    assert!(not_private(anchored.repin.as_ref().unwrap()));
    let restored = host
        .vault
        .restore_world_keys(&host.owner, here, &seed, None)
        .unwrap();
    assert!(restored.usable.is_empty());
    assert_eq!(restored.withheld, vec![(key, Withheld::NotPrivate)]);
    assert_eq!(key_records(&host.vault, world).len(), records);
}
