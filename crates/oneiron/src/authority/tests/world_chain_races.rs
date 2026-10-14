//! World privacy P6b acceptance for the multi-chain race rule on a
//! self-host vault (contract §4, check 7c): the roster and an owner anchor
//! both admit machines there, and a chain that blocks a machine now is a
//! reason in the race whether or not it ever admitted it.
use super::machine_identity::request_for;
use super::owner_anchor::{YOURS, profile, publish, signed};
use super::support::{ed_key, genesis_entry};
use super::world_chain_reads::{edit, read_under, seeing};
use super::*;
use crate::HostingPrivacyPosture::SelfHostLocal;
use crate::world_keys::RecoveryRoot;

/// A self-host vault whose owner-held roster key is `root`, with an owner
/// root published on it, and machine A's request.
struct SelfHost {
    id: AuthorityVaultId,
    root: SigningKey,
    owner: (RecoveryRoot, SigningKey),
    genesis: AuthorityLogEntry,
    published: AuthorityLogEntry,
    a: (MachineEnrolmentRequest, SigningKey),
}

fn self_host(seed: u8) -> SelfHost {
    let genesis = genesis_entry(seed, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let (owner_root, owner_anchor, published) = publish(id, &genesis);
    let a_key = ed_key(seed.wrapping_add(1));
    let a = request_for(id, EntityId::now(), &a_key);
    SelfHost {
        id,
        root: ed_key(seed),
        owner: (owner_root, owner_anchor),
        genesis,
        published,
        a: (a, a_key),
    }
}

/// 7c, a blocker that never admitted (Sol R1p-F1, Wonder R1p-F1): on a
/// self-host vault A is the owner's at E's parents under the pinned anchor
/// alone. A widens W offline (E); the owner then removes A with the
/// owner-held roster key. With a removal that does not list E, E is
/// restriction-only on installs pinned to the anchor; with one that lists
/// E, it keeps full strength.
#[test]
fn a_roster_removal_that_never_admitted_still_judges_the_race() {
    for lists_the_widening in [false, true] {
        let vault = self_host(180);
        let owner = &vault.owner.0;
        let a = vault.a.0.machine;
        let mark = signed(
            vault.id,
            &[&vault.published],
            &vault.owner.1,
            2,
            profile(&vault.a.0, YOURS, 1),
        );
        let world = EntityId::now();
        let held = edit(
            vault.id,
            &[&mark],
            (a, &vault.a.1),
            1,
            world,
            ReadLocation::OneMachine(a),
        );
        let widened = edit(
            vault.id,
            &[&mark, &held],
            (a, &vault.a.1),
            2,
            world,
            ReadLocation::MyMachines,
        );
        let seen: Vec<&AuthorityLogEntry> = if lists_the_widening {
            vec![&widened]
        } else {
            vec![]
        };
        let removal = signed(
            vault.id,
            &[&mark],
            &vault.root,
            1,
            seeing(&vault.a.0, MachineRole::Removed, 1, &seen),
        );
        let entries = vec![
            vault.genesis.clone(),
            vault.published.clone(),
            mark,
            held,
            widened,
            removal,
        ];
        assert_eq!(
            read_under(&entries, SelfHostLocal, Some(owner), world),
            if lists_the_widening {
                EffectiveRead::MyMachines
            } else {
                EffectiveRead::OneMachine(a)
            }
        );
    }
}

/// 7c, roster plus anchor, a removal races a widening (Sol R1d-F3): on a
/// self-host vault A is the owner's through the roster and through the
/// owner's anchor, with one key. A sets W to `OneMachine(A)` and then,
/// offline, widens it to `MyMachines`; concurrently the owner removes A
/// under the anchor, listing only the first edit. Installs pinned to the
/// anchor read `OneMachine(A)`; an unpinned one (the roster alone) reads
/// `MyMachines`. Fails before: `read_X` was taken equal to the roster's
/// read until an anchor-only signer edited.
#[test]
fn an_anchor_removal_races_a_widening_beside_a_roster_mark() {
    let vault = self_host(190);
    let owner = &vault.owner.0;
    let a = vault.a.0.machine;
    let roster_mark = signed(
        vault.id,
        &[&vault.published],
        &vault.root,
        1,
        profile(&vault.a.0, YOURS, 1),
    );
    let anchor_mark = signed(
        vault.id,
        &[&vault.published],
        &vault.owner.1,
        2,
        profile(&vault.a.0, YOURS, 1),
    );
    let world = EntityId::now();
    let held = edit(
        vault.id,
        &[&roster_mark, &anchor_mark],
        (a, &vault.a.1),
        1,
        world,
        ReadLocation::OneMachine(a),
    );
    let widened = edit(
        vault.id,
        &[&roster_mark, &anchor_mark, &held],
        (a, &vault.a.1),
        2,
        world,
        ReadLocation::MyMachines,
    );
    let removal = signed(
        vault.id,
        &[&anchor_mark],
        &vault.owner.1,
        3,
        seeing(&vault.a.0, MachineRole::Removed, 2, &[&held]),
    );
    let entries = vec![
        vault.genesis.clone(),
        vault.published.clone(),
        roster_mark,
        anchor_mark,
        held,
        widened,
        removal,
    ];
    assert_eq!(
        read_under(&entries, SelfHostLocal, Some(owner), world),
        EffectiveRead::OneMachine(a)
    );
    assert_eq!(
        read_under(&entries, SelfHostLocal, None, world),
        EffectiveRead::MyMachines
    );
}
