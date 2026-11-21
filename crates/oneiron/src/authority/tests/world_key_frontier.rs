//! A world whose live settings edits outgrow one key record (Engine rulings
//! on the owner's rate law, 2026-10-15). A key record names every live edit
//! of its world, and one record names at most `MAX_PARENTS` parents: a
//! format bound, never a lockout. Since FIX 8497 the key door and a pin
//! door's wrap step join a frontier wider than one record names first and
//! wrap on it, so neither refuses for a count. A pin door's pre-wrap on the
//! old pin's own rows keeps the key in a bridge record, to the root and to
//! itself alone, raises OF-520's question and goes on. One machine's
//! settings merge makes the key recordable for every reader again.
use std::collections::BTreeSet;

use super::machine_identity::{Host, host};
use super::support::{authority_key_from_ed, owner_act, sign_ed, unsigned_entry};
use super::world_key_doors::{
    Fresh, Keyed, enrol_own, fresh_install, key_records, keyed_machine, kit_seed, own_request, set,
};
use super::world_privacy::{settings, world_row};
use super::world_reissue::{admit, issue, profiled, set_on, sync, with_predecessor};
use super::*;
use crate::Vault;
use crate::world_keys::{Withheld, WorldKeyStatus};

/// `by` signs 40 concurrent edits of `world` on the world's live edits and
/// `vault`'s heads, each keeping it `MyMachines`: more live edits than one
/// record names. Settings edits are main-log rows, so an earlier flood's
/// edits are heads here too; the edits name every live edit and then heads
/// up to `MAX_PARENTS`, as many parents as one entry may name.
fn flood_on(vault: &Vault, host: &Host, by: &Keyed, world: EntityId) {
    let fold = vault.authority_fold().unwrap();
    let signer = authority_key_from_ed(&by.signing);
    let seq = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
    let mut parents: BTreeSet<_> = fold
        .worlds
        .get(&world)
        .map(|folded| folded.live.keys().copied().collect())
        .unwrap_or_default();
    let room = MAX_PARENTS.saturating_sub(parents.len());
    parents.extend(fold.append_heads.iter().copied().take(room));
    let rows: Vec<_> = (0..40)
        .map(|ts| {
            let entry = unsigned_entry(
                fold.vault_id,
                seq,
                parents.iter().copied().collect(),
                AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                    world,
                    act: owner_act(host.owner.actor(), world),
                    machine: by.machine,
                    settings: settings(ReadLocation::MyMachines),
                }),
                signer.clone(),
                ts,
            );
            (
                sign_ed(entry, &by.signing),
                TimeRange { start: 2, end: 2 },
                2,
            )
        })
        .collect();
    vault.put_authority_log_entries(&rows).unwrap();
}

fn flood(host: &Host, by: &Keyed, world: EntityId) {
    flood_on(&host.vault, host, by, world);
}

/// Check (Engine, 2026-10-15), as FIX 7908 and FIX 8497 left it: a world
/// whose live edits outgrow one record stops no door. One machine of the
/// owner's floods two worlds, one keyed and one not, and a machine joins
/// after the flood. The key door joins the wide frontier and mints the
/// unkeyed world's key on it, wrapped to the machine that joined later, and
/// raises no question. A kit restore over that vault pins and keeps every
/// key and wraps each to the root, to the restored machine and to the
/// machine that joined later. A settings merge from the restored machine
/// keeps the wide world's key. Before FIX 8497, the key door refused the
/// unkeyed world with the way out, and the restore kept the wide world's
/// key in a bridge record to the root and itself alone while the later
/// machine waited for that merge.
#[test]
fn a_restore_past_two_wide_worlds_pins_and_wraps_every_key() {
    let host = host();
    enrol_own(&host);
    let flooder = keyed_machine(&host, 46);
    with_predecessor(&host, &host.vault, &host.owner);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let seed = kit_seed(host.vault_id, prepared.seed());
    host.vault
        .activate_owner_root(&host.owner, prepared, &BTreeSet::new())
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
    flood(&host, &flooder, wide);
    flood(&host, &flooder, unkeyed);
    // A machine of the owner's that joins after the flood.
    let late = keyed_machine(&host, 47);
    let fold = host.vault.authority_fold().unwrap();
    assert_eq!(fold.worlds[&wide].live.len(), 40);
    assert_eq!(fold.worlds[&unkeyed].live.len(), 40);

    // The key door joins the wide frontier and mints the unkeyed world's
    // key on it, wrapped to the machine that joined later; no question is
    // raised.
    let WorldKeyStatus::Minted(unkeyed_key) =
        host.vault.ensure_world_key(&host.owner, unkeyed).unwrap()
    else {
        panic!("the unkeyed world's first key mints on the joined frontier");
    };
    let fold = host.vault.authority_fold().unwrap();
    assert_eq!(fold.current_world_key(unkeyed).unwrap().id, unkeyed_key);
    let to_late = WrapRecipient::Machine(late.machine);
    assert!(
        fold.world_key(&unkeyed_key)
            .unwrap()
            .wraps
            .contains_key(&to_late)
    );
    assert!(host.vault.world_key_frontier_checks().is_empty());

    let Fresh {
        _backups,
        vault: fresh,
        owner,
        ..
    } = fresh_install(&host);
    let restore = fresh.restore_world_keys(&owner, &seed, None).unwrap();
    let here = fresh.local_machine().unwrap().unwrap();
    assert!(here.mine);
    // Every key stays usable, and each goes to the root, to this machine
    // and to the machine that joined later.
    let keys = [calm_key, wide_key, unkeyed_key];
    assert_eq!(
        restore.usable.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from(keys),
        "{restore:?}"
    );
    assert!(restore.withheld.is_empty(), "{restore:?}");
    assert!(restore.needs_rehome.is_empty());
    assert_eq!(fresh.world_key(calm).unwrap().id(), &calm_key);
    assert_eq!(fresh.world_key(wide).unwrap().id(), &wide_key);
    assert_eq!(fresh.world_key(unkeyed).unwrap().id(), &unkeyed_key);
    let root = WrapRecipient::RecoveryRoot(fresh.owner_root_view(None, 0).unwrap().pinned.unwrap());
    let fold = fresh.authority_fold().unwrap();
    for key in keys {
        let wraps = &fold.world_key(&key).unwrap().wraps;
        for to in [root, WrapRecipient::Machine(here.id), to_late] {
            assert!(wraps.contains_key(&to), "{key:?} {to:?}");
        }
    }
    assert!(fresh.world_key_frontier_checks().is_empty());

    // The restored machine, now mine, merges the world's settings and keeps
    // the same key.
    fresh
        .set_world_privacy_as(
            &owner,
            ActSurface::ThisInstall,
            wide,
            settings(ReadLocation::MyMachines),
            None,
        )
        .unwrap();
    assert_eq!(fresh.authority_fold().unwrap().worlds[&wide].live.len(), 1);
    assert_eq!(fresh.world_key(wide).unwrap().id(), &wide_key);
}

/// Astra S2-R2 A2-F5: a key whose root and own wraps already count stays
/// usable when another reader's wrap has to wait. Before, a same-root
/// restore withheld the whole key as `FrontierWide` because one machine
/// that joined later lacked a wrap. Since FIX 8497 the wrap step joins a
/// frontier wider than one record names first, so that reader no longer
/// waits: the restore wraps it too and raises no question.
#[test]
fn a_deferred_reader_never_hides_a_usable_restore_key() {
    let host = host();
    enrol_own(&host);
    let flooder = keyed_machine(&host, 46);
    with_predecessor(&host, &host.vault, &host.owner);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let seed = kit_seed(host.vault_id, prepared.seed());
    host.vault
        .activate_owner_root(&host.owner, prepared, &BTreeSet::new())
        .unwrap();
    let wide = world_row(&host);
    set(&host, wide, ReadLocation::MyMachines);
    let key = host
        .vault
        .authority_fold()
        .unwrap()
        .current_world_key(wide)
        .unwrap()
        .id;
    flood(&host, &flooder, wide);
    let late = keyed_machine(&host, 47);

    let restore = host
        .vault
        .restore_world_keys(&host.owner, &seed, None)
        .unwrap();
    assert_eq!(restore.usable, vec![key], "{restore:?}");
    assert!(restore.withheld.is_empty(), "{restore:?}");
    assert!(host.vault.world_key_frontier_checks().is_empty());
    let fold = host.vault.authority_fold().unwrap();
    assert!(
        fold.world_key(&key)
            .unwrap()
            .wraps
            .contains_key(&WrapRecipient::Machine(late.machine))
    );
}

/// The check pair (Engine, 2026-10-15, on Sol S2-R2 S2-F3 and Astra
/// A2-F2). R1 admits A and B, and A mints K for a `MyMachines` world,
/// wrapped to A, B and R1, every record A's. One machine of the owner's
/// floods the world. R2 is issued from an install that holds no K, carrying
/// neither. B re-pins to R2: its pre-wrap of K cannot name the frontier, so
/// a bridge record wraps K to R2 and to B alone, and the pin moves. B then
/// anchors its own request under R2, and the door reaches K from that
/// record. B merges the world's settings, and the flooder, a reader there,
/// gets the same K. Before, the pin move left B no record of K, the
/// anchoring reached nothing, and the merge minted another key.
#[test]
fn a_skipped_pre_wrap_keeps_the_key_for_a_re_run() {
    let host = host();
    let world = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let b = fresh_install(&host);
    profiled(&host, &a.vault, MachineRole::Owned(MachineOwnership::Yours));
    profiled(&host, &b.vault, MachineRole::Owned(MachineOwnership::Yours));
    with_predecessor(&host, &issuer.vault, &issuer.owner);
    let first = issue(&issuer, &[]);
    admit(&issuer, &first, &a);
    admit(&issuer, &first, &b);
    sync(&issuer.vault, &a.vault);
    set_on(&a, world, ReadLocation::MyMachines);
    let key = *a.vault.world_key(world).unwrap().id();
    sync(&a.vault, &b.vault);
    let flooder = keyed_machine(&host, 46);
    sync(&host.vault, &b.vault);
    flood_on(&b.vault, &host, &flooder, world);

    let other = fresh_install(&host);
    with_predecessor(&host, &other.vault, &other.owner);
    let second = issue(&other, &[]);
    sync(&other.vault, &b.vault);
    let report = b.vault.pin_owner_root(&b.owner, second.root).unwrap();
    assert_eq!(report.withheld, vec![(key, Withheld::FrontierWide)]);
    let me = b.machine();
    let to_second = WrapRecipient::RecoveryRoot(second.root);
    let bridges: Vec<_> = key_records(&b.vault, world)
        .into_iter()
        .filter(|record| record.key == key && record.machine == me)
        .collect();
    assert!(!bridges.is_empty());
    for record in &bridges {
        assert!(
            record
                .wraps
                .iter()
                .all(|(to, _)| *to == to_second || *to == WrapRecipient::Machine(me))
        );
    }

    let b = b.reopen();
    let own = own_request(&b.vault);
    let anchored = b
        .vault
        .anchor_machine(&b.owner, &second.seed, &own, None, None)
        .unwrap();
    assert_eq!(anchored.repin.unwrap().rewrapped, vec![key]);
    set_on(&b, world, ReadLocation::MyMachines);
    assert_eq!(
        b.vault.authority_fold().unwrap().worlds[&world].live.len(),
        1
    );
    assert_eq!(b.vault.world_key(world).unwrap().id(), &key);
    let fold = b.vault.authority_fold().unwrap();
    let held = fold.world_key(&key).unwrap();
    assert!(
        held.wraps
            .contains_key(&WrapRecipient::Machine(flooder.machine))
    );
    assert!(held.wraps.contains_key(&to_second));
}

/// Astra #1422d F1: the settings door counts each parent once. This machine
/// signs E, making the world its own, and machine B signs, concurrently
/// with E, as many edits making it B's as fill one entry beside E. Settings
/// edits are main-log rows, so these edits are then the main log's heads as
/// well as the world's live edits. No key record follows E, so E is this
/// machine's last row of the world. The owner resolves the conflict to B here in one edit,
/// with no move here first: E, the edit's chain parent, is one of the live
/// edits. Fails before: the door counted E twice, as the chain and as a
/// live edit, and refused the request for count.
#[test]
fn a_conflict_that_fills_one_entry_resolves_in_one_edit() {
    use super::world_privacy::{edit_by, enrol_here, land, other_machine, read_of};
    let host = host();
    let world = world_row(&host);
    let here = enrol_here(&host);
    let (other, other_key) = other_machine(&host, 69, MachineRole::Owned(MachineOwnership::Yours));
    let here_key = {
        let txn = host.vault.store.env.read_txn().unwrap();
        crate::identity::read_machine_signing_key_in_txn(&host.vault, &txn)
            .unwrap()
            .unwrap()
    };
    let mut concurrent = vec![edit_by(
        &host,
        here,
        &here_key,
        world,
        settings(ReadLocation::OneMachine(here)),
    )];
    concurrent.extend((0..MAX_PARENTS - 1).map(|ts| {
        let mut entry = edit_by(
            &host,
            other,
            &other_key,
            world,
            settings(ReadLocation::OneMachine(other)),
        );
        entry.ts = u64::try_from(ts).unwrap();
        sign_ed(entry, &other_key)
    }));
    land(&host, &concurrent);
    let fold = host.vault.authority_fold().unwrap();
    assert_eq!(fold.append_heads.len(), MAX_PARENTS);
    assert_eq!(fold.worlds[&world].live.len(), MAX_PARENTS);
    assert_eq!(
        read_of(&host, world),
        EffectiveRead::Conflicted {
            contenders: BTreeSet::from([here, other]),
        }
    );

    host.vault
        .set_world_privacy_as(
            &host.owner,
            ActSurface::ThisInstall,
            world,
            settings(ReadLocation::OneMachine(other)),
            None,
        )
        .unwrap();
    assert_eq!(read_of(&host, world), EffectiveRead::OneMachine(other));
    let fold = host.vault.authority_fold().unwrap();
    let [resolved]: [_; 1] = fold.worlds[&world]
        .live
        .keys()
        .copied()
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let by_here: Vec<_> = super::world_privacy::stored_entries(&host.vault)
        .into_iter()
        .filter(
            |entry| matches!(&entry.op, AuthorityOp::WorldPrivacy(edit) if edit.machine == here),
        )
        .collect();
    assert_eq!(by_here.len(), 2);
    let entry = by_here
        .iter()
        .find(|entry| authority_entry_hash(entry).unwrap() == resolved)
        .unwrap();
    assert_eq!(entry.parent_hashes.len(), MAX_PARENTS);
}
