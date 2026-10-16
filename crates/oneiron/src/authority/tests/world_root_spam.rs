//! World privacy P6b acceptance for root spam (contract §8, check 7b; Wonder
//! R1-F5, Sol R1b-F8): roots are bounded only by the entries a writer signs,
//! the root view pages and counts them, and no number of roots evicts one
//! from admission.
use super::machine_identity::{host, request_for};
use super::owner_anchor::{YOURS, hosted_genesis, pin, profile, publish, signed};
use super::support::ed_key;
use super::world_chain_reads::{edit, fold_under};
use super::world_hosted::anchor_on;
use super::world_key_doors::fresh_install;
use super::world_kit_gate::publish_root;
use super::world_reissue::sync;
use super::*;
use crate::HostingPrivacyPosture::Hosted;
use crate::world_keys::RecoveryRootSeed;

const HERE: EditOrigin = EditOrigin::ThisMachine;

/// Every foreign root `vault` shows, page by page.
fn every_page(vault: &crate::Vault, limit: usize) -> BTreeMap<RecoveryRootId, usize> {
    let mut seen = BTreeMap::new();
    let mut after = None;
    loop {
        let page = vault.owner_root_view(after, limit).unwrap();
        assert!(page.foreign.len() <= limit);
        let Some(last) = page.foreign.keys().next_back().copied() else {
            return seen;
        };
        seen.extend(page.foreign);
        after = Some(last);
    }
}

/// 7b: twenty roots from throwaway anchors, each marking a throwaway
/// machine, and five that mark nothing, beside an operative host root. The
/// owner's issuing install pages through every operative root, the host's
/// among them, and counts the inert ones; a fresh install still pins the
/// owner's root by its fingerprint.
#[test]
fn root_spam_pages_and_never_hides_an_operative_root() {
    let host = host();
    let issuer = fresh_install(&host);
    let prepared = issuer.vault.prepare_owner_root(&issuer.owner).unwrap();
    let ours = prepared.seed().public(&host.vault_id).unwrap().id;
    issuer
        .vault
        .activate_owner_root(&issuer.owner, HERE, prepared, &BTreeSet::new())
        .unwrap();
    sync(&issuer.vault, &host.vault);
    let host_seed = RecoveryRootSeed::generate().unwrap();
    let theirs = publish_root(&host, &host_seed);
    anchor_on(
        &host,
        &host_seed,
        &request_for(host.vault_id, EntityId::now(), &ed_key(230)),
    );
    for spam in 0..25u8 {
        let seed = RecoveryRootSeed::generate().unwrap();
        publish_root(&host, &seed);
        if spam < 20 {
            anchor_on(
                &host,
                &seed,
                &request_for(host.vault_id, EntityId::now(), &ed_key(spam)),
            );
        }
    }
    sync(&host.vault, &issuer.vault);
    let view = issuer.vault.owner_root_view(None, 4).unwrap();
    assert_eq!(view.pinned, Some(ours));
    assert_eq!((view.foreign_total, view.inert_foreign), (21, 5));
    let foreign = every_page(&issuer.vault, 4);
    assert_eq!(foreign.len(), 21);
    assert_eq!(foreign.get(&theirs), Some(&1));
    assert!(!foreign.contains_key(&ours));

    let fresh = fresh_install(&host);
    fresh
        .vault
        .pin_owner_root(&fresh.owner, HERE, ours)
        .unwrap();
    assert_eq!(
        fresh.vault.owner_root_view(None, 0).unwrap().pinned,
        Some(ours)
    );
}

/// 7b: twenty operative roots that all admit one host machine page through
/// the root view, each counting that machine, and `foreign_total` counts
/// twenty.
#[test]
fn many_roots_admitting_one_machine_page_and_count() {
    let host = host();
    let machine = request_for(host.vault_id, EntityId::now(), &ed_key(231));
    for _ in 0..20 {
        let seed = RecoveryRootSeed::generate().unwrap();
        publish_root(&host, &seed);
        anchor_on(&host, &seed, &machine);
    }
    let view = host.vault.owner_root_view(None, 3).unwrap();
    assert_eq!((view.foreign_total, view.inert_foreign), (20, 0));
    let foreign = every_page(&host.vault, 3);
    assert_eq!(foreign.len(), 20);
    assert!(foreign.values().all(|machines| *machines == 1));
}

/// 7b: on an install pinned to a newer root, spam roots whose ids sort below
/// an old owner root, placed in the causal past of that root's profiles,
/// leave those machines admitted. Their earlier narrowing still counts, as
/// restriction only, and an owner machine's re-pick on top of it is valid. Fails before (the
/// 9-record cap): the profiles folded invalid, the narrowing vanished, and
/// the world read everywhere.
#[test]
fn spam_roots_below_an_old_root_never_evict_its_admissions() {
    let cloud = ed_key(232);
    let genesis = hosted_genesis(&cloud);
    let id = genesis_vault_id(&genesis).unwrap();
    // An old root whose id sorts high, so spam can sort below it.
    let (old, old_anchor, old_published) = loop {
        let candidate = publish(id, &genesis);
        if candidate.0.id.0[0] >= 0xc0 {
            break candidate;
        }
    };
    let mut spam = Vec::new();
    while spam.len() < 12 {
        let (root, _, published) = publish(id, &genesis);
        if root.id < old.id {
            spam.push(published);
        }
    }
    let spam_heads: Vec<&AuthorityLogEntry> = spam.iter().collect();
    let mut parents = spam_heads.clone();
    parents.push(&old_published);
    let a_key = ed_key(233);
    let a = request_for(id, EntityId::now(), &a_key);
    let mark = signed(id, &parents, &old_anchor, 2, profile(&a, YOURS, 1));
    let (new, new_anchor, new_published) = publish(id, &genesis);
    let b_key = ed_key(234);
    let b = request_for(id, EntityId::now(), &b_key);
    let new_mark = signed(id, &[&new_published], &new_anchor, 2, profile(&b, YOURS, 1));
    let world = EntityId::now();
    let narrowing = edit(
        id,
        &[&mark, &new_mark],
        (a.machine, &a_key),
        1,
        world,
        ReadLocation::OneMachine(a.machine),
    );
    let after = edit(
        id,
        &[&mark, &new_mark, &narrowing],
        (b.machine, &b_key),
        1,
        world,
        ReadLocation::MyMachines,
    );
    let mut entries = vec![genesis, old_published, new_published];
    entries.extend(spam.iter().cloned());
    entries.extend([mark, new_mark, narrowing.clone()]);
    let fold = fold_under(&entries, Hosted, Some(&new));
    assert!(
        fold.machine(a.machine)
            .unwrap()
            .admits(&MachineAdmitter::Anchor(old.anchor_key))
    );
    assert!(!fold.machine(a.machine).unwrap().is_mine(Some(&pin(&new))));
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&narrowing).unwrap())
    );
    assert_eq!(
        fold.world_privacy(world).read,
        EffectiveRead::OneMachine(a.machine)
    );
    // Under the new root the narrowing names no machine mine there, so B
    // re-picks the world on top of it: nothing stalls.
    entries.push(after.clone());
    let fold = fold_under(&entries, Hosted, Some(&new));
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&after).unwrap())
    );
    assert_eq!(fold.world_privacy(world).read, EffectiveRead::MyMachines);
}
