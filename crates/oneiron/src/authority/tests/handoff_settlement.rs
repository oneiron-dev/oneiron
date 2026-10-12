//! Handoff settlement (engine-crates-03, Sol reviews 2 and 3): forks and
//! cycles of handoffs install no successor and keep their fences closed, a
//! handoff that stands on fenced rows or fails on its own rows retires
//! nothing, a fenced row's floor or collision prunes nothing, only an
//! authority row is resident history, and no door admits a new row that
//! stands on a retired key.
use super::history_transfer::{re_root_entry, store};
use super::support::*;
use super::*;
use crate::{TimeRange, Vault, VaultConfig};

fn hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).unwrap()
}

fn is_live(fold: &AuthorityFold, key: &SigningKey) -> bool {
    fold.roster
        .get(&authority_key_from_ed(key))
        .is_some_and(|device| !device.revoked)
}

/// Two forks the retired root signs build no quorum that replaces its
/// successor (Sol review 2, finding 1). Their merge stands on rows the
/// handoff fenced, so it installs nothing and retires nothing; the forks and
/// the handoff conflict, so the old root stays retired.
#[test]
fn forks_of_a_retired_root_build_no_quorum_over_its_successor() {
    let old = ed_key(180);
    let next = ed_key(181);
    let (first_heir, second_heir, merged_heir) = (ed_key(182), ed_key(183), ed_key(184));
    let genesis = genesis_entry(180, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let handoff = re_root_entry(id, &genesis, &old, 1, &next);
    let first_fork = re_root_entry(id, &genesis, &old, 2, &first_heir);
    let second_fork = re_root_entry(id, &genesis, &old, 3, &second_heir);
    let mut merge = re_root_entry(id, &handoff, &first_heir, 1, &merged_heir);
    merge.parent_hashes = vec![hash(&handoff), hash(&first_fork), hash(&second_fork)];
    merge.parent_hashes.sort();
    let merge = cosign_ed(merge, &first_heir, &second_heir);

    let fold = fold_authority_log(&[genesis, handoff, first_fork, second_fork, merge.clone()]);
    assert!(!fold.valid_entries.contains(&hash(&merge)));
    assert!(!is_live(&fold, &merged_heir));
    assert!(!fold.retired_keys.contains(&authority_key_from_ed(&next)));
    assert!(fold.retired_keys.contains(&authority_key_from_ed(&old)));
}

/// Three handoffs whose fences run round a cycle install no successor, and
/// every fence stays closed (Sol review 2, finding 6). On each branch the
/// retired root rotates to a fresh key, which enrolls the next branch's key
/// as a system writer, revokes it, and hands the vault on.
#[test]
fn a_cycle_of_fenced_handoffs_installs_no_successor() {
    let old = ed_key(190);
    let next = ed_key(191);
    let genesis = genesis_entry(190, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let handoff = re_root_entry(id, &genesis, &old, 1, &next);
    let rotated: [u8; 3] = [192, 193, 194];
    let heirs: [u8; 3] = [195, 196, 197];
    let mut entries = vec![genesis.clone(), handoff.clone()];
    let mut branches = vec![handoff];
    for (branch, (&seed, &heir)) in rotated.iter().zip(&heirs).enumerate() {
        let owner = ed_key(seed);
        let writer_seed = rotated[(branch + 1) % rotated.len()];
        let writer = authority_key_from_ed(&ed_key(writer_seed));
        let rotation = rotate_entry(id, &genesis, &old, authority_key_from_ed(&old), seed, 1);
        let enroll = enroll_device_entry(
            id,
            &rotation,
            &owner,
            EnrollSpec {
                seed: writer_seed,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 3,
            },
        );
        let bind = cosign_ed(
            unsigned_entry(
                Some(id),
                2,
                vec![hash(&enroll)],
                bind_op(&writer, scope_entity(seed), "system", 1),
                authority_key_from_ed(&owner),
                4,
            ),
            &owner,
            &ed_key(writer_seed),
        );
        let revoke = revoke_entry(id, &bind, &owner, writer, 3);
        let branch_handoff = re_root_entry(id, &revoke, &owner, 4, &ed_key(heir));
        branches.push(branch_handoff.clone());
        entries.extend([rotation, enroll, bind, revoke, branch_handoff]);
    }

    let fold = fold_authority_log(&entries);
    for branch in &branches {
        assert!(!fold.valid_entries.contains(&hash(branch)));
    }
    for heir in heirs {
        assert!(!is_live(&fold, &ed_key(heir)));
    }
    assert!(fold.retired_keys.contains(&authority_key_from_ed(&old)));
}

/// A handoff that its own confirmation collision prunes retires nothing
/// (Sol review 2, finding 3): the root that signed both confirmations stays
/// live, and one of them stands.
#[test]
fn a_handoff_its_own_collision_prunes_retires_nothing() {
    let old = ed_key(185);
    let next = ed_key(186);
    let genesis = genesis_entry(185, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let confirm = |confirm: u8| {
        sign_ed(
            unsigned_entry(
                Some(id),
                1,
                vec![hash(&genesis)],
                AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                    kind: AuthorityConfirmKind::Accept,
                    confirm_id: [confirm; 32],
                    peer_vault_id: [86; 32],
                    epoch: 1,
                    nonce: [87; 16],
                }),
                authority_key_from_ed(&old),
                2,
            ),
            &old,
        )
    };
    let (first, second) = (confirm(1), confirm(2));
    let mut handoff = re_root_entry(id, &first, &old, 2, &next);
    handoff.parent_hashes = vec![hash(&first), hash(&second)];
    handoff.parent_hashes.sort();
    let handoff = sign_ed(handoff, &old);

    let fold = fold_authority_log(&[genesis, first.clone(), second.clone(), handoff.clone()]);
    assert!(!fold.valid_entries.contains(&hash(&handoff)));
    assert_ne!(
        fold.valid_entries.contains(&hash(&first)),
        fold.valid_entries.contains(&hash(&second))
    );
    assert!(fold.retired_keys.is_empty());
    assert!(is_live(&fold, &old));
    assert!(!is_live(&fold, &next));
}

/// An EVENT that carries a fork's exact bytes at the fork's id is no resident
/// history (Sol review 2, finding 4): the append door still refuses the fork
/// for its retired signer, and the successor stays the root.
#[cfg(feature = "sync")]
#[test]
fn an_event_carrying_a_forks_bytes_replays_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let old = ed_key(187);
    let next = ed_key(188);
    let fork = ed_key(189);
    let genesis = genesis_entry(187, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&vault, &genesis);
    vault
        .apply_signed_re_root(&re_root_entry(id, &genesis, &old, 1, &next))
        .unwrap();
    let forked = re_root_entry(id, &genesis, &old, 1, &fork);
    vault
        .put_entity(
            &authority_log_entity_id(&forked).unwrap(),
            crate::registry::ENTITY_TYPE_EVENT,
            TimeRange { start: 2, end: 2 },
            2,
            &encode_authority_log_entry_body(&forked).unwrap(),
        )
        .unwrap();

    assert!(
        vault
            .put_authority_log_entry(&forked, TimeRange { start: 3, end: 3 }, 3)
            .is_err()
    );
    let fold = vault.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&hash(&forked)));
    assert!(is_live(&fold, &next));
}

/// An owner and admin device for `key` at `tier`.
fn owner_device(key: &SigningKey, tier: AuthorityTier) -> DeviceAuthority {
    device(authority_key_from_ed(key), ROLE_OWNER | ROLE_ADMIN, tier)
}

fn signed(
    id: AuthorityVaultId,
    parents: &[&AuthorityLogEntry],
    signer: &SigningKey,
    seq: u64,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    let mut parent_hashes: Vec<_> = parents.iter().map(|parent| hash(parent)).collect();
    parent_hashes.sort();
    sign_ed(
        unsigned_entry(
            Some(id),
            seq,
            parent_hashes,
            op,
            authority_key_from_ed(signer),
            5,
        ),
        signer,
    )
}

/// A handoff whose own rows fail is no handoff, and fences nothing (Sol
/// review 3, finding 1). The old root's fork stands on two confirmations that
/// collide; the full fold settles the real handoff. A row the old key signs
/// outside the real handoff's line, colliding with a confirmation inside it,
/// leaves that handoff a handoff all the same.
#[test]
fn a_handoff_that_fails_on_its_own_rows_fences_nothing() {
    let old = ed_key(200);
    let next = ed_key(201);
    let heir = ed_key(202);
    let genesis = genesis_entry(200, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let confirm = |confirm: u8, seq: u64, parent: &AuthorityLogEntry| {
        signed(
            id,
            &[parent],
            &old,
            seq,
            AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: AuthorityConfirmKind::Accept,
                confirm_id: [confirm; 32],
                peer_vault_id: [88; 32],
                epoch: 1,
                nonce: [89; 16],
            }),
        )
    };
    let (first, second) = (confirm(1, 1, &genesis), confirm(2, 1, &genesis));
    let fork = signed(
        id,
        &[&first, &second],
        &old,
        2,
        AuthorityOp::ReRoot {
            new_device: owner_device(&heir, AuthorityTier::Software),
        },
    );
    let handoff = re_root_entry(id, &genesis, &old, 3, &next);
    let fold = fold_authority_log(&[
        genesis.clone(),
        first,
        second,
        fork.clone(),
        handoff.clone(),
    ]);
    assert!(fold.valid_entries.contains(&hash(&handoff)));
    assert!(!fold.valid_entries.contains(&hash(&fork)));
    assert!(is_live(&fold, &next));
    assert!(fold.retired_keys.contains(&authority_key_from_ed(&old)));

    let own = confirm(3, 1, &genesis);
    let handoff = re_root_entry(id, &own, &old, 2, &next);
    let outside = confirm(4, 3, &genesis);
    let fold = fold_authority_log(&[genesis, own.clone(), handoff.clone(), outside.clone()]);
    assert!(fold.valid_entries.contains(&hash(&handoff)));
    assert!(fold.valid_entries.contains(&hash(&own)));
    assert!(!fold.valid_entries.contains(&hash(&outside)));
    assert!(is_live(&fold, &next));
}

/// A tier floor that stands on a fenced row prunes nothing (Sol review 3,
/// finding 4). The old root rotates to a hardware key on a branch beside its
/// handoff, which sets a hardware floor and hands the vault on: the fork and
/// the handoff conflict, so neither heir stands. The same branch alone, with
/// no handoff beside it, still installs its heir.
#[test]
fn a_forks_tier_floor_prunes_no_handoff() {
    let old = ed_key(203);
    let next = ed_key(204);
    let rotated = ed_key(205);
    let heir = ed_key(206);
    let genesis = genesis_entry(203, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let rotation = signed(
        id,
        &[&genesis],
        &old,
        1,
        AuthorityOp::RotateKey {
            old_key: authority_key_from_ed(&old),
            new_device: owner_device(&rotated, AuthorityTier::Hardware),
        },
    );
    let floor = signed(
        id,
        &[&rotation],
        &rotated,
        1,
        AuthorityOp::SetTierFloor {
            tier_floor: AuthorityTier::Hardware,
        },
    );
    let fork = signed(
        id,
        &[&floor],
        &rotated,
        2,
        AuthorityOp::ReRoot {
            new_device: owner_device(&heir, AuthorityTier::Hardware),
        },
    );
    let handoff = re_root_entry(id, &genesis, &old, 2, &next);

    let alone = fold_authority_log(&[
        genesis.clone(),
        rotation.clone(),
        floor.clone(),
        fork.clone(),
    ]);
    assert!(alone.valid_entries.contains(&hash(&fork)));
    assert!(is_live(&alone, &heir));

    let fold = fold_authority_log(&[genesis, rotation, floor, handoff.clone(), fork.clone()]);
    for entry in [&handoff, &fork] {
        assert!(!fold.valid_entries.contains(&hash(entry)));
    }
    assert!(!is_live(&fold, &heir));
    assert!(!is_live(&fold, &next));
    assert!(fold.retired_keys.contains(&authority_key_from_ed(&old)));
}

/// A replica that folded the real handoff first admits no new row that stands
/// on a row the old root signed, whoever signs the new one (Sol review 3,
/// finding 2). The old root's rotation was stored before the handoff, while
/// it could be; the rotated key's handoff on it is refused at the append door
/// and by history import, and the successor stays the root.
#[test]
fn no_door_admits_a_new_row_on_a_retired_roots_resident_row() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let old = ed_key(207);
    let next = ed_key(208);
    let rotated = ed_key(209);
    let heir = ed_key(210);
    let genesis = genesis_entry(207, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&vault, &genesis);
    let rotation = rotate_entry(id, &genesis, &old, authority_key_from_ed(&old), 209, 1);
    store(&vault, &rotation);
    vault
        .apply_signed_re_root(&re_root_entry(id, &genesis, &old, 2, &next))
        .unwrap();
    let fork = re_root_entry(id, &rotation, &rotated, 1, &heir);

    assert!(
        vault
            .put_authority_log_entry(&fork, TimeRange { start: 3, end: 3 }, 3)
            .is_err()
    );
    let mut history = vault.export_signed_authority_history().unwrap();
    history.push(encode_authority_log_entry_body(&fork).unwrap());
    assert!(vault.import_signed_authority_history(&history).is_err());
    #[cfg(feature = "sync")]
    assert!(
        vault
            .batch()
            .put_replicated(
                &authority_log_entity_id(&fork).unwrap(),
                crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
                TimeRange { start: 3, end: 3 },
                3,
                &encode_authority_log_entry_body(&fork).unwrap(),
            )
            .commit()
            .is_err()
    );
    let fold = vault.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&hash(&fork)));
    assert!(is_live(&fold, &next));
}

/// The replicated door judges retirement by the vault's own fold, under its
/// hosting posture (Sol review 3, finding 3). A Hosted vault hands its root to
/// a cloud-custodial successor; the old root's fork, replayed as a replicated
/// row, is refused, and the successor stays the root.
#[cfg(feature = "sync")]
#[test]
fn a_hosted_vaults_replicated_door_keeps_its_cloud_successor() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::default();
    config.privacy = crate::config::VaultPrivacyConfig {
        posture: crate::HostingPrivacyPosture::Hosted,
        data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
            key_ref: "hosted-handoff-test".into(),
        },
    };
    let vault = Vault::open(dir.path(), config).unwrap();
    let old = ed_key(211);
    let cloud = ed_key(212);
    let heir = ed_key(213);
    let genesis = genesis_entry(211, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&vault, &genesis);
    let handoff = signed(
        id,
        &[&genesis],
        &old,
        1,
        AuthorityOp::ReRoot {
            new_device: device(
                authority_key_from_ed(&cloud),
                ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                AuthorityTier::CloudCustodial,
            ),
        },
    );
    vault.apply_signed_re_root(&handoff).unwrap();
    let fork = re_root_entry(id, &genesis, &old, 2, &heir);

    assert!(
        vault
            .batch()
            .put_replicated(
                &authority_log_entity_id(&fork).unwrap(),
                crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
                TimeRange { start: 2, end: 2 },
                2,
                &encode_authority_log_entry_body(&fork).unwrap(),
            )
            .commit()
            .is_err()
    );
    let fold = vault.authority_fold().unwrap();
    assert!(is_live(&fold, &cloud));
    assert!(!fold.valid_entries.contains(&hash(&fork)));
}
