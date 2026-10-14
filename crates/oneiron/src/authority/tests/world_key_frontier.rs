//! A world whose live settings edits outgrow one key record (Engine ruling on
//! the owner's rate law, 2026-10-15). A key record names every live edit of
//! its world, and one record names at most `MAX_PARENTS` parents: a format
//! bound, never a lockout. The key door refuses with the way out and raises
//! OF-520's question; a pin door withholds that one key as `FrontierWide` and
//! goes on; one machine's settings merge makes the key recordable again.
use std::collections::BTreeSet;

use super::machine_identity::host;
use super::support::sign_ed;
use super::world_key_doors::{Fresh, enrol_own, fresh_install, keyed_machine, kit_seed, set};
use super::world_privacy::{edit_by, land, settings, world_row};
use super::*;
use crate::error::{Error, SecretError};
use crate::world_keys::{Withheld, WorldKeyFrontierCheck};

const WAY_OUT: &str = "merge this world's settings from one machine that sees every edit";

/// Check (Engine, 2026-10-15): a kit restore over a vault with one world
/// past the bound pins, wraps every other world's key, withholds that
/// world's key as `FrontierWide` and raises its question; after a settings
/// merge from the restored machine, a re-run wraps it. Before, the restore
/// was refused whole, and the install it left unpinned could not merge.
#[test]
fn a_restore_past_one_wide_world_pins_and_withholds_only_that_key() {
    let host = host();
    enrol_own(&host);
    let flooder = keyed_machine(&host, 46);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let seed = kit_seed(host.vault_id, prepared.seed());
    host.vault
        .activate_owner_root(
            &host.owner,
            EditOrigin::ThisMachine,
            prepared,
            &BTreeSet::new(),
        )
        .unwrap();
    let calm = world_row(&host);
    set(&host, calm, ReadLocation::MyMachines);
    let wide = world_row(&host);
    set(&host, wide, ReadLocation::MyMachines);
    let unkeyed = world_row(&host);
    let fold = host.vault.authority_fold().unwrap();
    let [calm_key, wide_key] = [calm, wide].map(|world| fold.current_world_key(world).unwrap().id);
    // One machine of the owner's floods two worlds with concurrent edits
    // that keep them private.
    let flood: Vec<_> = [wide, unkeyed]
        .into_iter()
        .flat_map(|world| (0..40).map(move |ts| (world, ts)))
        .map(|(world, ts)| {
            let mut entry = edit_by(
                &host,
                flooder.machine,
                &flooder.signing,
                world,
                settings(ReadLocation::MyMachines),
            );
            entry.ts = ts;
            sign_ed(entry, &flooder.signing)
        })
        .collect();
    land(&host, &flood);
    let fold = host.vault.authority_fold().unwrap();
    assert_eq!(fold.worlds[&wide].live.len(), 40);
    assert_eq!(fold.worlds[&unkeyed].live.len(), 40);

    // The key door refuses the unkeyed world with the way out, and raises
    // its question.
    let refused = host
        .vault
        .ensure_world_key(&host.owner, unkeyed)
        .unwrap_err();
    assert!(
        matches!(&refused, Error::Secret(SecretError::WorldKeyRefused(reason)) if reason.contains(WAY_OUT)),
        "{refused:?}"
    );
    assert!(
        host.vault
            .authority_fold()
            .unwrap()
            .current_world_key(unkeyed)
            .is_none()
    );
    let [check] = host.vault.world_key_frontier_checks().try_into().unwrap();
    assert_eq!((check.world, check.bound), (unkeyed, MAX_PARENTS));
    assert!(check.rows > MAX_PARENTS);
    assert_eq!(WorldKeyFrontierCheck::KIND, "world_key_frontier_wide");

    let Fresh {
        _backups,
        vault: fresh,
        owner,
        ..
    } = fresh_install(&host);
    let restore = fresh
        .restore_world_keys(&owner, EditOrigin::ThisMachine, &seed, None)
        .unwrap();
    assert_eq!(restore.usable, vec![calm_key]);
    assert_eq!(restore.withheld, vec![(wide_key, Withheld::FrontierWide)]);
    assert!(restore.needs_rehome.is_empty());
    let here = fresh.local_machine().unwrap().unwrap();
    assert!(here.mine);
    assert_eq!(fresh.world_key(calm).unwrap().id(), &calm_key);
    assert!(fresh.world_key(wide).is_err());
    assert_eq!(
        fresh
            .world_key_frontier_checks()
            .iter()
            .map(|check| check.world)
            .collect::<Vec<_>>(),
        vec![wide]
    );

    // The way out: the restored machine, now mine, merges the world's
    // settings, and the restore run again wraps the key.
    fresh
        .set_world_privacy_as(
            &owner,
            EditOrigin::ThisMachine,
            wide,
            settings(ReadLocation::MyMachines),
        )
        .unwrap();
    assert_eq!(fresh.authority_fold().unwrap().worlds[&wide].live.len(), 1);
    let again = fresh
        .restore_world_keys(&owner, EditOrigin::ThisMachine, &seed, None)
        .unwrap();
    assert!(again.usable.contains(&wide_key), "{again:?}");
    assert!(again.withheld.is_empty(), "{again:?}");
    assert_eq!(fresh.world_key(wide).unwrap().id(), &wide_key);
}
