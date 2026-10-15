//! World privacy P6b: an owner anchor's rows rest on no roster key, through
//! every pass of the fold and at every door (contract §4, R1). A host may enrol
//! the anchor's public key in its roster, retire it with a handoff, or set a
//! tier floor over it; none of that removes, prunes or refuses the owner's
//! root, its marks or its removals (Sol code-R2 S2-F2 to S2-F4). Nor does a
//! root the fold refuses make a roster key's row the anchor's, and a stale
//! roster mark vetoes none of the anchor's keys (Sol code-R3 S3-F1, S3-F3).
use super::history_transfer::re_root_entry;
use super::machine_identity::request_for;
use super::owner_anchor::{
    YOURS, agent, enrol_anchor, fold_seen_at, hosted_fold, hosted_genesis, pin, profile, publish,
    rekeyed, root_record, signed,
};
use super::support::{
    EnrollSpec, authority_key_from_ed, cosign_ed, device, ed_key, enroll_device_entry,
    genesis_entry,
};
use super::world_chain_reads::edit;
use super::*;
use crate::world_keys::{RecoveryRoot, RecoveryRootId, RecoveryRootSeed};
use crate::{Vault, VaultConfig};

/// A self-host log whose root key enrols a second key and then the owner
/// anchor's public key as agents, and hands the vault to a new key: the
/// handoff retires the anchor's key as a roster key.
struct RetiredAnchor {
    id: AuthorityVaultId,
    genesis: AuthorityLogEntry,
    host: [AuthorityLogEntry; 3],
    root: RecoveryRoot,
    anchor: SigningKey,
    published: AuthorityLogEntry,
}

fn retired_anchor(seed: u8) -> RetiredAnchor {
    let (owner, second, next) = (ed_key(seed), ed_key(seed + 1), ed_key(seed + 2));
    let genesis = genesis_entry(seed, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let (root, anchor, published) = publish(id, &genesis);
    let host_second = agent(id, &genesis, &owner, seed + 1);
    let enrolled = enrol_anchor(id, &host_second, (&owner, &second), 2, &root);
    let handoff = cosign_ed(
        re_root_entry(id, &enrolled, &owner, 3, &next),
        &owner,
        &second,
    );
    RetiredAnchor {
        id,
        genesis,
        host: [host_second, enrolled, handoff],
        root,
        anchor,
        published,
    }
}

fn put(vault: &Vault, entries: &[&AuthorityLogEntry]) -> crate::error::Result<Vec<EntityId>> {
    let rows: Vec<_> = entries
        .iter()
        .map(|entry| ((*entry).clone(), TimeRange { start: 2, end: 2 }, 2))
        .collect();
    vault.put_authority_log_entries(&rows)
}

/// A vault holding the log's genesis and the host's three rows, the anchor's
/// key retired.
fn vault_with(log: &RetiredAnchor) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let [second, enrolled, handoff] = &log.host;
    put(&vault, &[&log.genesis, second, enrolled, handoff]).unwrap();
    let fold = vault.authority_fold().unwrap();
    assert!(
        fold.retired_keys
            .contains(&AuthorityKey::Ed25519(log.root.anchor_key))
    );
    (dir, vault)
}

/// The anchor marks M, then removes it; a later anchor row on a sibling
/// branch arrives first, so the removal falls under this vault's sequence
/// floor. It still lands, restriction only (P2's rule, Astra #1430b B-F1),
/// and stands through its own proof as well. M stays removed in the anchor's
/// chain, retired roster key or not (S2-F2). Fails before: the fence forgot
/// the proved removal, since only rows the ordinary fold kept counted as the
/// anchor's.
#[test]
fn a_proved_anchor_removal_outlives_the_anchors_retired_roster_key() {
    let log = retired_anchor(160);
    let (_dir, vault) = vault_with(&log);
    let request = request_for(log.id, EntityId::now(), &ed_key(163));
    let other = request_for(log.id, EntityId::now(), &ed_key(164));
    let mark = signed(
        log.id,
        &[&log.published],
        &log.anchor,
        2,
        profile(&request, YOURS, 1),
    );
    let removal = signed(
        log.id,
        &[&mark],
        &log.anchor,
        3,
        profile(&request, MachineRole::Removed, 2),
    );
    let later = signed(log.id, &[&mark], &log.anchor, 4, profile(&other, YOURS, 1));
    for entry in [&log.published, &mark, &later, &removal] {
        put(&vault, &[entry]).unwrap();
    }
    let fold = vault.authority_fold().unwrap();
    let removal = authority_entry_hash(&removal).unwrap();
    assert!(
        fold.valid_entries.contains(&removal) && fold.install.held_back.contains(&removal),
        "the removal lands past the floor, restriction only"
    );
    let folded = fold.machine(request.machine).unwrap();
    assert!(folded.anchored[&log.root.anchor_key].removed);
    assert!(!folded.is_mine(Some(&pin(&log.root))));
}

/// A root and its mark arrive together, in one batch and in one history
/// import, on a vault where the anchor's key is already a retired roster key.
/// Both doors take them, as the fold does (S2-F4). Fails before: the doors
/// knew only roots already held, so they refused the mark as a retired key's.
#[test]
fn a_root_and_its_mark_arrive_together_past_a_retired_roster_key() {
    let log = retired_anchor(165);
    let request = request_for(log.id, EntityId::now(), &ed_key(168));
    let mark = signed(
        log.id,
        &[&log.published],
        &log.anchor,
        2,
        profile(&request, YOURS, 1),
    );
    let (_dir, batch) = vault_with(&log);
    put(&batch, &[&log.published, &mark]).unwrap();
    let (_other, imported) = vault_with(&log);
    imported
        .import_signed_authority_history(&batch.export_signed_authority_history().unwrap())
        .unwrap();
    for vault in [&batch, &imported] {
        let fold = vault.authority_fold().unwrap();
        let trusted = fold
            .machine(request.machine)
            .and_then(|folded| folded.trusted(Some(&pin(&log.root))))
            .map(|trusted| trusted.profile.machine_key);
        assert_eq!(trusted, Some(request.machine_key));
    }
}

/// On a hosted log the host enrols the anchor's public key as a Software
/// agent, the owner's mark builds on that enrolment, and on a sibling branch
/// the host raises the floor to CloudCustodial and hands its root on. The
/// floor prunes no anchor row: the mark stands and M is mine under the pin
/// (S2-F3). Fails before: the floor pass read the anchor's key as a roster
/// signer below the floor.
#[test]
fn a_concurrent_tier_floor_never_prunes_an_anchor_row() {
    let (cloud, second, next) = (ed_key(170), ed_key(171), ed_key(172));
    let genesis = hosted_genesis(&cloud);
    let id = genesis_vault_id(&genesis).unwrap();
    let (root, anchor, published) = publish(id, &genesis);
    let host_second = enroll_device_entry(
        id,
        &genesis,
        &cloud,
        EnrollSpec {
            seed: 171,
            roles: ROLE_AGENT,
            tier: AuthorityTier::CloudCustodial,
            seq: 1,
            ts: 2,
        },
    );
    let enrolled = enrol_anchor(id, &host_second, (&cloud, &second), 2, &root);
    let request = request_for(id, EntityId::now(), &ed_key(173));
    let mark = signed(
        id,
        &[&published, &enrolled],
        &anchor,
        2,
        profile(&request, YOURS, 1),
    );
    let floor = cosign_ed(
        signed(
            id,
            &[&enrolled],
            &cloud,
            3,
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::CloudCustodial,
            },
        ),
        &cloud,
        &second,
    );
    let handoff = cosign_ed(
        signed(
            id,
            &[&floor],
            &cloud,
            4,
            AuthorityOp::ReRoot {
                new_device: device(
                    authority_key_from_ed(&next),
                    ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                    AuthorityTier::CloudCustodial,
                ),
            },
        ),
        &cloud,
        &second,
    );
    let entries = [
        genesis,
        published,
        host_second,
        enrolled,
        mark.clone(),
        floor.clone(),
        handoff.clone(),
    ];
    let fold = hosted_fold(&entries);
    for entry in [&floor, &handoff, &mark] {
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(entry).unwrap())
        );
    }
    assert_eq!(fold.tier_floor, Some(AuthorityTier::CloudCustodial));
    assert!(
        fold.machine(request.machine)
            .is_some_and(|folded| folded.is_mine(Some(&pin(&root))))
    );
}

/// A self-host root key marks M and hands the vault on. On a sibling branch
/// it publishes a root naming itself the anchor, at a sequence it already
/// used, so every fold refuses that root, then removes M beneath it. The
/// removal's own proof skips the refused root and takes the removal through
/// the key's roster standing: it is the retired root's, and the handoff's
/// fence forgets it, so M stays mine (Sol code-R3 S3-F1, Wonder W3-F1). Fails
/// before: any root beneath the removal made it the anchor's.
#[test]
fn a_refused_root_never_makes_a_retired_keys_removal_the_anchors() {
    let (owner, next) = (ed_key(185), ed_key(186));
    let genesis = genesis_entry(185, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let request = request_for(id, EntityId::now(), &ed_key(187));
    let mark = signed(id, &[&genesis], &owner, 1, profile(&request, YOURS, 1));
    let handoff = re_root_entry(id, &mark, &owner, 2, &next);
    let recovery_key = RecoveryRootSeed::generate()
        .unwrap()
        .public(&id)
        .unwrap()
        .recovery_key;
    let anchor_key = owner.verifying_key().to_bytes();
    let root = RecoveryRoot {
        id: RecoveryRootId::of(&id, &recovery_key, &anchor_key),
        recovery_key,
        anchor_key,
    };
    let refused = signed(
        id,
        &[&mark],
        &owner,
        1,
        AuthorityOp::OwnerRoot(root_record(&root)),
    );
    let removal = signed(
        id,
        &[&refused],
        &owner,
        3,
        profile(&request, MachineRole::Removed, 2),
    );
    let entries = [genesis, mark, handoff, refused.clone(), removal];
    let fold = fold_seen_at(&entries, 100, crate::HostingPrivacyPosture::SelfHostLocal);
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&refused).unwrap())
    );
    assert!(fold.root_anchors().is_empty());
    let folded = fold.machine(request.machine).unwrap();
    assert!(!folded.roster_trusted.as_ref().unwrap().removed);
    assert!(folded.is_mine(None));
}

/// A self-host root key marks M with one encryption key and hands the vault
/// on; the owner's anchor then marks M with the same machine key and a fresh
/// encryption key. While both chains are live they disagree, so M is mine
/// only to an unpinned install. Past the stale-roster window the roster's
/// mark is stale, and M is mine under the pin with the anchor's keys: a stale
/// chain vetoes no live chain's keys (Sol code-R3 S3-F3). Fails before: the
/// stale roster head's key still made M not mine under the pin.
#[test]
fn a_stale_roster_mark_never_vetoes_the_anchors_keys() {
    let (owner, next, machine) = (ed_key(190), ed_key(191), ed_key(192));
    let genesis = genesis_entry(190, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let request = request_for(id, EntityId::now(), &machine);
    let mark = signed(id, &[&genesis], &owner, 1, profile(&request, YOURS, 1));
    let handoff = re_root_entry(id, &mark, &owner, 2, &next);
    let (root, anchor, published) = publish(id, &handoff);
    let rekeyed = rekeyed(id, &request, &machine);
    let anchored = signed(id, &[&published], &anchor, 2, profile(&rekeyed, YOURS, 1));
    let entries = [genesis, mark, handoff, published, anchored];
    let mine_at = |now| {
        let fold = fold_seen_at(&entries, now, crate::HostingPrivacyPosture::SelfHostLocal);
        let folded = fold.machine(request.machine).unwrap();
        let pinned = folded
            .trusted(Some(&pin(&root)))
            .map(|trusted| trusted.profile.encryption_key.clone());
        (pinned, folded.is_mine(None))
    };
    assert_eq!(mine_at(100), (None, true));
    assert_eq!(
        mine_at(101 + DEFAULT_STALE_ROSTER_WINDOW_SECS),
        (Some(rekeyed.encryption_key), false)
    );
}

/// The same graph, as the world-privacy fold counts M: M narrows a world to
/// itself and then widens it, on both marks. Before the stale-roster window
/// the live chains' keys disagree, so on an install pinned to the owner's
/// root the widening only narrows; past it the stale roster mark vetoes
/// nothing, M counts through the anchor, and the widening holds. Fails
/// before: the install's counting held the stale roster chain instead, and
/// its key still vetoed the anchor's (Sol code-S2-R1 S1-F2, Astra A1-F1).
#[test]
fn a_stale_roster_mark_never_vetoes_the_anchors_keys_in_a_world() {
    let (owner, next, machine) = (ed_key(193), ed_key(194), ed_key(195));
    let genesis = genesis_entry(193, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let request = request_for(id, EntityId::now(), &machine);
    let mark = signed(id, &[&genesis], &owner, 1, profile(&request, YOURS, 1));
    let handoff = re_root_entry(id, &mark, &owner, 2, &next);
    let (root, anchor, published) = publish(id, &handoff);
    let rekeyed = rekeyed(id, &request, &machine);
    let anchored = signed(id, &[&published], &anchor, 2, profile(&rekeyed, YOURS, 1));
    let world = EntityId::now();
    let m = (request.machine, &machine);
    let held = edit(id, &[&anchored], m, 1, world, ReadLocation::OneMachine(m.0));
    let widened = edit(id, &[&held], m, 2, world, ReadLocation::Everywhere);
    let entries = [genesis, mark, handoff, published, anchored, held, widened];
    let first_seen: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (authority_entry_hash(entry).unwrap(), 100))
        .collect();
    let read_at = |now| {
        fold_pinned_authority_log_for_posture(
            &entries,
            &first_seen,
            now,
            &BTreeMap::new(),
            crate::HostingPrivacyPosture::SelfHostLocal,
            Some(&pin(&root)),
        )
        .world_privacy(world)
        .read
    };
    assert_eq!(read_at(100), EffectiveRead::OneMachine(m.0));
    assert_eq!(
        read_at(101 + DEFAULT_STALE_ROSTER_WINDOW_SECS),
        EffectiveRead::Everywhere
    );
}
