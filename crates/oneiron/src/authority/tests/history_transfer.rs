//! Full signed-history portability, account auth and independent recovery composition.
use super::support::*;
use super::*;
use crate::{TimeRange, Vault, VaultConfig};

pub(super) fn store(vault: &Vault, entry: &AuthorityLogEntry) {
    vault
        .put_authority_log_entry(entry, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
}

#[test]
fn signed_history_export_import_re_root_preserves_identity_and_bytes() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let a = Vault::open(a.path(), VaultConfig::default()).unwrap();
    let b = Vault::open(b.path(), VaultConfig::default()).unwrap();
    let c = Vault::open(c.path(), VaultConfig::default()).unwrap();
    let old = ed_key(110);
    let new = ed_key(111);
    let genesis = genesis_entry(110, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    store(&a, &genesis);
    let export = a.export_signed_authority_history().unwrap();
    b.import_signed_authority_history(&export).unwrap();
    assert_eq!(b.export_signed_authority_history().unwrap(), export);
    let reroot = b
        .re_root_authority(
            device(
                authority_key_from_ed(&new),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
            authority_key_from_ed(&old),
            |bytes| Ok(old.sign(bytes).to_bytes().to_vec()),
        )
        .unwrap();
    let fold = b.authority_fold().unwrap();
    assert_eq!(fold.vault_id, a.authority_fold().unwrap().vault_id);
    assert!(fold.roster[&authority_key_from_ed(&old)].revoked);
    assert!(!fold.roster[&authority_key_from_ed(&new)].revoked);
    let moved = b.export_signed_authority_history().unwrap();
    assert_eq!(moved[0], export[0]);
    c.import_signed_authority_history(&moved).unwrap();
    assert_eq!(c.authority_fold().unwrap().roster, fold.roster);
    assert_eq!(moved[1], encode_authority_log_entry_body(&reroot).unwrap());
    let mut corrupt = export;
    let last = corrupt[0].len() - 1;
    corrupt[0][last] ^= 1;
    assert!(c.import_signed_authority_history(&corrupt).is_err());
    assert_eq!(c.export_signed_authority_history().unwrap(), moved);
    let other =
        encode_authority_log_entry_body(&genesis_entry(112, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1))
            .unwrap();
    assert!(c.import_signed_authority_history(&[other]).is_err());
    assert_eq!(c.export_signed_authority_history().unwrap(), moved);
}

#[test]
fn account_auth_migrates_managed_root_without_widening() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::default();
    config.privacy = crate::config::VaultPrivacyConfig {
        posture: crate::HostingPrivacyPosture::Hosted,
        data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
            key_ref: "account-host-key".into(),
        },
    };
    let vault = Vault::open(dir.path(), config).unwrap();
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    let old = ed_key(140);
    let new = ed_key(141);
    let key = authority_key_from_ed(&old);
    let mut genesis = genesis_entry(140, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    if let AuthorityOp::Genesis { device, .. } = &mut genesis.op {
        device.roles |= ROLE_CLOUD;
        device.tier = AuthorityTier::CloudCustodial;
    }
    genesis = sign_ed(genesis, &old);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&vault, &genesis);
    let bind = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            bind_op(&key, actor, "human", 1),
            key.clone(),
            2,
        ),
        &old,
    );
    store(&vault, &bind);
    assert!(
        vault
            .authenticate_owner(
                actor,
                &actor.to_hex(),
                false,
                crate::store::GateDecisionId::now()
            )
            .is_err()
    );
    let owner = vault
        .authenticate_owner(
            actor,
            &actor.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    vault
        .recover_cloud_account(
            &owner,
            device(
                authority_key_from_ed(&new),
                ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                AuthorityTier::CloudCustodial,
            ),
            key.clone(),
            |bytes| Ok(old.sign(bytes).to_bytes().to_vec()),
        )
        .unwrap();
    let fold = vault.authority_fold().unwrap();
    assert_eq!(fold.vault_id, Some(id));
    assert!(fold.roster[&key].revoked);
    assert!(!fold.roster[&authority_key_from_ed(&new)].revoked);
}

#[test]
fn signed_pre_handoff_rotation_survives_hosted_transfer_and_cannot_be_reissued() {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source = Vault::open(source_dir.path(), VaultConfig::default()).unwrap();
    let hosted = VaultConfig {
        privacy: crate::config::VaultPrivacyConfig {
            posture: crate::HostingPrivacyPosture::Hosted,
            data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
                key_ref: "handoff-test".into(),
            },
        },
        ..VaultConfig::default()
    };
    let target = Vault::open(target_dir.path(), hosted).unwrap();
    let old = ed_key(115);
    let next = ed_key(116);
    let old_key = authority_key_from_ed(&old);
    let next_key = authority_key_from_ed(&next);
    let host = HostSlipIssuer::from_secret(b"handoff-root-for-one-2276").unwrap();
    let genesis = genesis_entry(115, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(id, &genesis, &old, old_key.clone(), 116, 1);
    store(&source, &genesis);
    store(&source, &rotation);
    let before = source.authority_fold().unwrap();
    assert!(!before.roster.contains_key(&next_key));
    mature_observed_widen(&source, &rotation);
    let handoff = sign_ed(
        unsigned_entry(
            Some(id),
            0,
            vec![authority_entry_hash(&rotation).unwrap()],
            AuthorityOp::ReRoot {
                new_device: device(
                    host.public_key(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            next_key.clone(),
            3,
        ),
        &next,
    );
    source.apply_signed_re_root(&handoff).unwrap();
    target
        .import_signed_authority_history(&source.export_signed_authority_history().unwrap())
        .unwrap();
    mature_observed_widen(&target, &rotation);
    let migrated = target.authority_fold().unwrap();
    assert!(
        migrated
            .valid_entries
            .contains(&authority_entry_hash(&handoff).unwrap())
    );
    assert!(migrated.roster[&old_key].revoked);
    assert!(migrated.roster[&next_key].revoked);
    assert!(!migrated.roster[&host.public_key()].revoked);
    let root_slip = target.ensure_host_root_slip(&host).unwrap();
    assert!(
        target
            .capability_slip_id_is_live(&root_slip.claims.slip_id)
            .unwrap()
    );
    let minted = target.authority_fold().unwrap();
    let parent = minted.slips.mints[&root_slip.claims.slip_id].entry_hash;
    let new_key = authority_key_from_ed(&ed_key(117));
    let enroll = host
        .sign_entry(
            Some(id),
            1,
            vec![parent],
            AuthorityOp::EnrollDevice {
                device: device(
                    new_key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Hardware,
                ),
            },
            4,
        )
        .unwrap();
    store(&target, &enroll);
    let rejected = target.authority_fold().unwrap();
    assert!(
        !rejected
            .valid_entries
            .contains(&authority_entry_hash(&enroll).unwrap())
    );
    assert!(!rejected.roster.contains_key(&new_key));
    assert!(rejected.roster[&old_key].revoked);
    assert!(rejected.slip_is_live(&root_slip.claims.slip_id));

    // A validly signed sibling floor is not an ancestor of the handoff.
    // Even its unrestricted probe must not restore the old root.
    let floor = sign_ed(
        unsigned_entry(
            Some(id),
            2,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            old_key.clone(),
            5,
        ),
        &old,
    );
    let floor_hash = authority_entry_hash(&floor).unwrap();
    for entries in [
        vec![
            genesis.clone(),
            rotation.clone(),
            handoff.clone(),
            floor.clone(),
        ],
        vec![floor.clone(), handoff.clone(), rotation.clone(), genesis],
    ] {
        let folded = fold_authority_log_for_posture(
            &entries,
            &BTreeMap::from([
                (authority_entry_hash(&rotation).unwrap(), 0),
                (floor_hash, 0),
            ]),
            DEFAULT_PENDING_WIDEN_DELAY_SECS,
            &BTreeMap::new(),
            crate::HostingPrivacyPosture::Hosted,
        );
        assert!(!folded.valid_entries.contains(&floor_hash));
        assert!(
            folded
                .valid_entries
                .contains(&authority_entry_hash(&handoff).unwrap())
        );
        assert!(folded.roster[&old_key].revoked);
        assert!(folded.roster[&next_key].revoked);
        assert!(!folded.roster[&host.public_key()].revoked);
    }
    // The append door refuses the retired key's row (engine-crates-03).
    assert!(
        target
            .put_authority_log_entry(&floor, TimeRange { start: 5, end: 5 }, 5)
            .is_err()
    );
    let after_floor = target.authority_fold().unwrap();
    assert!(!after_floor.valid_entries.contains(&floor_hash));
    assert!(
        after_floor
            .valid_entries
            .contains(&authority_entry_hash(&handoff).unwrap())
    );
    assert!(after_floor.roster[&old_key].revoked);
    assert!(after_floor.roster[&next_key].revoked);
    assert!(!after_floor.roster[&host.public_key()].revoked);
    assert!(
        target
            .capability_slip_id_is_live(&root_slip.claims.slip_id)
            .unwrap()
    );
}

#[test]
fn handoff_only_preserves_its_valid_pre_handoff_ancestors() {
    let old = ed_key(118);
    let next = ed_key(119);
    let host = ed_key(120);
    let client = ed_key(121);
    let successor = ed_key(122);
    let old_key = authority_key_from_ed(&old);
    let next_key = authority_key_from_ed(&next);
    let host_key = authority_key_from_ed(&host);
    let client_key = authority_key_from_ed(&client);
    let successor_key = authority_key_from_ed(&successor);
    let genesis = genesis_entry(118, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(id, &genesis, &old, old_key.clone(), 119, 1);
    let rotation_hash = authority_entry_hash(&rotation).unwrap();
    let handoff = sign_ed(
        unsigned_entry(
            Some(id),
            0,
            vec![rotation_hash],
            AuthorityOp::ReRoot {
                new_device: device(
                    host_key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            next_key.clone(),
            3,
        ),
        &next,
    );
    let mut invalid_device = device(
        host_key.clone(),
        ROLE_OWNER | ROLE_ADMIN | ROLE_AGENT,
        AuthorityTier::Software,
    );
    invalid_device.attestation.kind = "HostRoot".into();
    let invalid_handoff = sign_ed(
        unsigned_entry(
            Some(id),
            0,
            vec![rotation_hash],
            AuthorityOp::ReRoot {
                new_device: invalid_device,
            },
            next_key.clone(),
            3,
        ),
        &next,
    );
    let sibling = enroll_device_entry(
        id,
        &genesis,
        &old,
        EnrollSpec {
            seed: 121,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Hardware,
            seq: 2,
            ts: 2,
        },
    );
    let post_handoff = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![authority_entry_hash(&handoff).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(
                    client_key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Hardware,
                ),
            },
            host_key.clone(),
            4,
        ),
        &host,
    );
    let second_handoff = sign_ed(
        unsigned_entry(
            Some(id),
            0,
            vec![authority_entry_hash(&post_handoff).unwrap()],
            AuthorityOp::ReRoot {
                new_device: device(
                    successor_key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            client_key.clone(),
            5,
        ),
        &client,
    );
    let seen = [
        rotation_hash,
        authority_entry_hash(&sibling).unwrap(),
        authority_entry_hash(&post_handoff).unwrap(),
    ]
    .into_iter()
    .map(|hash| (hash, 1))
    .collect::<BTreeMap<_, _>>();
    for posture in [
        crate::HostingPrivacyPosture::Hosted,
        crate::HostingPrivacyPosture::SelfHostLocal,
        crate::HostingPrivacyPosture::Relay,
    ] {
        let no_handoff = fold_authority_log_for_posture(
            &[genesis.clone(), rotation.clone(), invalid_handoff.clone()],
            &seen,
            1 + DEFAULT_PENDING_WIDEN_DELAY_SECS,
            &BTreeMap::new(),
            posture,
        );
        assert!(
            !no_handoff.valid_entries.contains(&rotation_hash),
            "{posture:?}"
        );
        let entries = [
            genesis.clone(),
            rotation.clone(),
            handoff.clone(),
            sibling.clone(),
            post_handoff.clone(),
            second_handoff.clone(),
        ];
        for ordered in [entries.to_vec(), entries.iter().rev().cloned().collect()] {
            let folded = fold_authority_log_for_posture(
                &ordered,
                &seen,
                1 + DEFAULT_PENDING_WIDEN_DELAY_SECS,
                &BTreeMap::new(),
                posture,
            );
            assert!(folded.valid_entries.contains(&rotation_hash), "{posture:?}");
            assert!(
                folded
                    .valid_entries
                    .contains(&authority_entry_hash(&handoff).unwrap())
            );
            for rejected in [&sibling, &post_handoff, &second_handoff] {
                assert!(
                    !folded
                        .valid_entries
                        .contains(&authority_entry_hash(rejected).unwrap())
                );
            }
            assert!(!folded.roster[&host_key].revoked);
            assert!(folded.roster[&old_key].revoked);
            assert!(folded.roster[&next_key].revoked);
            assert!(!folded.roster.contains_key(&client_key));
            assert!(!folded.roster.contains_key(&successor_key));
        }
    }
}

pub(super) fn re_root_entry(
    id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &ed25519_dalek::SigningKey,
    seq: u64,
    successor: &ed25519_dalek::SigningKey,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::ReRoot {
                new_device: device(
                    authority_key_from_ed(successor),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(signer),
            2,
        ),
        signer,
    )
}

/// engine-crates-03: a handoff retires its predecessor on every branch. The
/// old root signs a second handoff parented to the genesis; it installs no
/// second root, on any arrival order, and the fork's own successor signs
/// nothing that stands. A fork is unsettled at any sequence (Sol review 2,
/// Engine ruling 2026-10-13): neither successor stands and the old root stays
/// retired. This once let the lower-sequence handoff stand, a pick a gap in
/// the old root's sequences could turn round.
#[test]
fn a_retired_root_installs_no_second_root() {
    let old = ed_key(160);
    let next = ed_key(161);
    let fork = ed_key(162);
    let after_fork = ed_key(163);
    let genesis = genesis_entry(160, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let handoff = re_root_entry(id, &genesis, &old, 1, &next);
    let forked = re_root_entry(id, &genesis, &old, 2, &fork);
    let onward = re_root_entry(id, &forked, &fork, 1, &after_fork);
    let (handoff_hash, forked_hash, onward_hash) = (
        authority_entry_hash(&handoff).unwrap(),
        authority_entry_hash(&forked).unwrap(),
        authority_entry_hash(&onward).unwrap(),
    );
    let mut entries = vec![genesis, handoff, forked, onward];
    for _ in 0..2 {
        let fold = fold_authority_log(&entries);
        assert!(!fold.valid_entries.contains(&handoff_hash));
        assert!(!fold.valid_entries.contains(&forked_hash));
        assert!(!fold.valid_entries.contains(&onward_hash));
        assert!(
            fold.issues
                .contains(&AuthorityFoldIssue::RetiredSigner(forked_hash))
        );
        assert!(fold.retired_keys.contains(&authority_key_from_ed(&old)));
        assert!(fold.roster.values().all(|device| device.revoked));
        assert!(
            !fold
                .roster
                .contains_key(&authority_key_from_ed(&after_fork))
        );
        entries.reverse();
    }
}

/// engine-crates-03 at the doors: after a handoff, a row the old root signs
/// is refused by the signed re-root door, by replicated replay and by
/// signed-history import, so the fork never reaches the log. The first
/// handoff a vault settles keeps it, and each refusal of the sibling is
/// recorded as evidence that the old key signed both (Engine ruling
/// 2026-10-14, the first record of OF-166).
#[test]
fn every_door_refuses_a_row_the_retired_root_signs() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let old = ed_key(164);
    let next = ed_key(165);
    let fork = ed_key(166);
    let genesis = genesis_entry(164, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&vault, &genesis);
    let handoff = re_root_entry(id, &genesis, &old, 1, &next);
    vault.apply_signed_re_root(&handoff).unwrap();
    let forked = re_root_entry(id, &genesis, &old, 2, &fork);
    let before = vault.export_signed_authority_history().unwrap();

    assert!(vault.apply_signed_re_root(&forked).is_err());
    assert!(
        vault
            .put_authority_log_entry(&forked, TimeRange { start: 2, end: 2 }, 2)
            .is_err()
    );
    let body = encode_authority_log_entry_body(&forked).unwrap();
    assert!(
        vault
            .import_signed_authority_history(std::slice::from_ref(&body))
            .is_err()
    );
    #[cfg(feature = "sync")]
    assert_eq!(
        vault
            .batch()
            .put_replicated(
                &authority_log_entity_id(&forked).unwrap(),
                crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
                TimeRange { start: 2, end: 2 },
                2,
                &body,
            )
            .commit()
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidAuthorityLogBody
    );
    assert_eq!(vault.export_signed_authority_history().unwrap(), before);
    let fold = vault.authority_fold().unwrap();
    assert!(!fold.roster[&authority_key_from_ed(&next)].revoked);
    assert!(!fold.roster.contains_key(&authority_key_from_ed(&fork)));
    assert_eq!(
        vault.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: authority_key_from_ed(&old),
            handoffs: BTreeSet::from([authority_entry_hash(&handoff).unwrap()]),
            refused: authority_entry_hash(&forked).unwrap(),
        }]
    );
}

fn re_root_to_host(
    id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &ed25519_dalek::SigningKey,
    seq: u64,
    host: &HostSlipIssuer,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::ReRoot {
                new_device: device(
                    host.public_key(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(signer),
            3,
        ),
        signer,
    )
}

/// A replica that imports `history` plus `extra` from scratch.
pub(super) fn replica_with(
    history: Vec<Vec<u8>>,
    extra: &AuthorityLogEntry,
) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let mut history = history;
    history.push(encode_authority_log_entry_body(extra).unwrap());
    replica.import_signed_authority_history(&history).unwrap();
    (dir, replica)
}

/// The old root withdraws no slip the new root minted (Sol review 1). Its
/// revoke on a branch beside the handoff is refused at the append door, and a
/// replica that imports it anyway proves no withdrawal from it.
#[test]
fn a_retired_root_withdraws_no_slip_the_new_root_minted() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let old = ed_key(167);
    let host = HostSlipIssuer::from_secret(b"successor root that mints").unwrap();
    let genesis = genesis_entry(167, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&vault, &genesis);
    vault
        .apply_signed_re_root(&re_root_to_host(id, &genesis, &old, 1, &host))
        .unwrap();
    let slip = vault.ensure_host_root_slip(&host).unwrap().claims.slip_id;
    let withdraw = sign_ed(
        unsigned_entry(
            Some(id),
            2,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::SlipRevoke { slip_id: slip },
            authority_key_from_ed(&old),
            4,
        ),
        &old,
    );
    assert!(
        vault
            .put_authority_log_entry(&withdraw, TimeRange { start: 4, end: 4 }, 4)
            .is_err()
    );

    let (_replica_dir, replica) =
        replica_with(vault.export_signed_authority_history().unwrap(), &withdraw);
    let fold = replica.authority_fold().unwrap();
    assert!(fold.issues.contains(&AuthorityFoldIssue::RetiredSigner(
        authority_entry_hash(&withdraw).unwrap()
    )));
    assert!(!fold.slips.revoked.contains(&slip));
    assert!(fold.slip_is_live(&slip));
}

/// A key a rotation superseded before the handoff forks no ReRoot (Sol
/// review 1). The handoff fences every key its parents' roster held, the
/// revoked one too, so the vault that folded the handoff refuses the fork at
/// its door and keeps the successor. A replica that imports both reads a
/// fork: neither successor stands and both keys stay retired (Sol review 2,
/// Engine ruling 2026-10-13). Round 1 let the rotation's successor win there;
/// that one-way yield is what a three-handoff cycle turned open.
#[test]
fn a_key_rotated_out_before_the_handoff_forks_no_root() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let old = ed_key(168);
    let next = ed_key(169);
    let fork = ed_key(171);
    let host = HostSlipIssuer::from_secret(b"successor after a rotation").unwrap();
    let genesis = genesis_entry(168, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(id, &genesis, &old, authority_key_from_ed(&old), 169, 1);
    store(&vault, &genesis);
    store(&vault, &rotation);
    mature_observed_widen(&vault, &rotation);
    let handoff = re_root_to_host(id, &rotation, &next, 0, &host);
    vault.apply_signed_re_root(&handoff).unwrap();
    let forked = re_root_entry(id, &genesis, &old, 2, &fork);
    assert!(vault.apply_signed_re_root(&forked).is_err());
    assert!(!vault.authority_fold().unwrap().roster[&host.public_key()].revoked);

    let (_replica_dir, replica) =
        replica_with(vault.export_signed_authority_history().unwrap(), &forked);
    mature_observed_widen(&replica, &rotation);
    let fold = replica.authority_fold().unwrap();
    for entry in [&handoff, &forked] {
        assert!(
            !fold
                .valid_entries
                .contains(&authority_entry_hash(entry).unwrap())
        );
    }
    for key in [&old, &next] {
        assert!(fold.retired_keys.contains(&authority_key_from_ed(key)));
    }
    assert!(fold.roster.values().all(|device| device.revoked));
}

/// A successor's handoff that merges a row its predecessor's handoff fenced
/// installs nothing, on a fresh replica as on one that holds the first
/// handoff (Sol review 2, finding 2). Round 1 widened the first handoff's line
/// through the second, so a fresh replica installed the third root while the
/// one holding the first handoff refused the merge at its door. Now both keep
/// the second root, and its route onward is a handoff from the heads it has.
#[test]
fn a_successor_merge_of_a_fenced_row_installs_nothing_anywhere() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let old = ed_key(172);
    let next = ed_key(173);
    let third = ed_key(174);
    let genesis = genesis_entry(172, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let missed = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::SlipRevoke { slip_id: [72; 32] },
            authority_key_from_ed(&old),
            2,
        ),
        &old,
    );
    let first = re_root_entry(id, &genesis, &old, 2, &next);
    let mut second = re_root_entry(id, &first, &next, 1, &third);
    second
        .parent_hashes
        .push(authority_entry_hash(&missed).unwrap());
    second.parent_hashes.sort();
    let second = sign_ed(second, &next);
    let bodies: Vec<Vec<u8>> = [&genesis, &missed, &first, &second]
        .into_iter()
        .map(|entry| encode_authority_log_entry_body(entry).unwrap())
        .collect();
    let keeps_next = |fold: &AuthorityFold| {
        !fold.roster[&authority_key_from_ed(&next)].revoked
            && fold
                .roster
                .get(&authority_key_from_ed(&third))
                .is_none_or(|device| device.revoked)
    };

    let fresh_dir = tempfile::tempdir().unwrap();
    let fresh = Vault::open(fresh_dir.path(), VaultConfig::default()).unwrap();
    fresh.import_signed_authority_history(&bodies).unwrap();
    let fold = fresh.authority_fold().unwrap();
    assert!(keeps_next(&fold), "a fresh replica installs no third root");
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&second).unwrap())
    );

    store(&vault, &genesis);
    vault.apply_signed_re_root(&first).unwrap();
    assert!(vault.import_signed_authority_history(&bodies).is_err());
    assert!(keeps_next(&vault.authority_fold().unwrap()));
    vault
        .apply_signed_re_root(&re_root_entry(id, &first, &next, 1, &third))
        .unwrap();
    let fold = vault.authority_fold().unwrap();
    assert!(!fold.roster[&authority_key_from_ed(&third)].revoked);
    assert!(fold.roster[&authority_key_from_ed(&next)].revoked);
}

/// A handoff in one vault erases no root conflict (Sol review 1): a second
/// genesis signed by the retired key still reads as a conflicting root.
#[test]
fn a_handoff_hides_no_second_genesis() {
    let old = ed_key(175);
    let next = ed_key(176);
    let genesis = genesis_entry(175, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let other = genesis_entry(175, DEFAULT_PENDING_WIDEN_DELAY_SECS, 2);
    assert_ne!(
        genesis_vault_id(&genesis).unwrap(),
        genesis_vault_id(&other).unwrap()
    );
    let id = genesis_vault_id(&genesis).unwrap();
    let handoff = re_root_entry(id, &genesis, &old, 1, &next);
    let fold = fold_authority_log(&[genesis, other, handoff]);
    assert!(fold.vault_root_is_conflicted());
}

/// A retired key's confirmation contends with nothing (Sol review 1): it
/// never wins a nonce collision against the new root's, so the new root's
/// confirmation and the slip it minted after it stand.
#[test]
fn a_retired_root_confirmation_displaces_no_confirmation_of_the_new_root() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let old = ed_key(177);
    let host = HostSlipIssuer::from_secret(b"successor root that confirms").unwrap();
    let genesis = genesis_entry(177, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&vault, &genesis);
    vault
        .apply_signed_re_root(&re_root_to_host(id, &genesis, &old, 1, &host))
        .unwrap();
    let action = |confirm: u8| {
        AuthorityOp::FederationConfirm(AuthorityConfirmAction {
            kind: AuthorityConfirmKind::Accept,
            confirm_id: [confirm; 32],
            peer_vault_id: [78; 32],
            epoch: 1,
            nonce: [79; 16],
        })
    };
    let fold = vault.authority_fold().unwrap();
    let theirs = host
        .sign_entry(
            Some(id),
            fold.append_sequences
                .get(&host.public_key())
                .copied()
                .unwrap_or(0)
                + 1,
            fold.append_heads.iter().copied().collect(),
            action(60),
            4,
        )
        .unwrap();
    vault
        .put_authority_log_entry(&theirs, TimeRange { start: 4, end: 4 }, 4)
        .unwrap();
    let theirs_hash = authority_entry_hash(&theirs).unwrap();
    let slip = vault.ensure_host_root_slip(&host).unwrap().claims.slip_id;
    let forged = (1..=u8::MAX)
        .filter(|confirm| *confirm != 60)
        .map(|confirm| {
            sign_ed(
                unsigned_entry(
                    Some(id),
                    2,
                    vec![authority_entry_hash(&genesis).unwrap()],
                    action(confirm),
                    authority_key_from_ed(&old),
                    5,
                ),
                &old,
            )
        })
        .find(|entry| authority_entry_hash(entry).unwrap() < theirs_hash)
        .expect("a confirmation hashes below the new root's");

    let (_replica_dir, replica) =
        replica_with(vault.export_signed_authority_history().unwrap(), &forged);
    let fold = replica.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&theirs_hash));
    assert!(fold.slip_is_live(&slip));
    assert!(fold.issues.contains(&AuthorityFoldIssue::RetiredSigner(
        authority_entry_hash(&forged).unwrap()
    )));
}
