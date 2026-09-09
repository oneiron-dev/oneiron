//! Fork quarantine limits, quorum-revoke resolution and vault attribution.

use super::support::*;
use super::*;

#[test]
fn quarantined_key_cannot_widen_enroll_or_set_ceiling_but_prefix_survives() {
    let owner = ed_key(60);
    let second = ed_key(61);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(60, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_entry(vault_id, &genesis, &owner, 61, 1, 2);
    let fork_enroll = cosign_ed(
        enroll_entry(vault_id, &enroll_second, &owner, 62, 2, 3),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 4),
        &owner,
        &second,
    );
    let fork_enroll_hash = authority_entry_hash(&fork_enroll).unwrap();
    let fork_fold = fold_authority_log_without_seen_time_delay(&[
        fork_ceiling.clone(),
        fork_enroll.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ]);
    let winner = if fork_fold.valid_entries.contains(&fork_enroll_hash) {
        fork_enroll.clone()
    } else {
        fork_ceiling.clone()
    };
    let child_enroll = cosign_ed(
        enroll_entry(vault_id, &winner, &owner, 63, 3, 5),
        &owner,
        &second,
    );
    let child_widen = cosign_ed(
        set_tier_floor_entry(vault_id, &winner, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let child_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &winner, &owner, 3, 6),
        &owner,
        &second,
    );
    let child_enroll_hash = authority_entry_hash(&child_enroll).unwrap();
    let child_widen_hash = authority_entry_hash(&child_widen).unwrap();
    let child_ceiling_hash = authority_entry_hash(&child_ceiling).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        child_enroll,
        child_widen,
        child_ceiling,
        fork_enroll,
        fork_ceiling,
        enroll_second.clone(),
        genesis.clone(),
    ]);

    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&genesis).unwrap())
    );
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&enroll_second).unwrap())
    );
    assert!(!fold.valid_entries.contains(&child_enroll_hash));
    assert!(!fold.valid_entries.contains(&child_widen_hash));
    assert!(!fold.valid_entries.contains(&child_ceiling_hash));
    // The three denied child mutations are themselves a second signed fork at
    // owner sequence 3, distinct from the original sequence-2 fork.
    assert_eq!(fold.authority_forks.len(), 2);
    assert_eq!(
        fold.authority_forks
            .iter()
            .map(|fork| fork.seq)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(fold.authority_forks.iter().all(|fork| {
        fork.signer == owner_key && fork.status == AuthorityForkStatus::Quarantined
    }));
    for child_hash in [child_enroll_hash, child_widen_hash, child_ceiling_hash] {
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == child_hash
        )));
    }
}

#[test]
fn quarantined_key_cannot_bypass_with_clean_prefix_parent() {
    let owner = ed_key(66);
    let second = ed_key(67);
    let genesis = genesis_entry(66, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_entry(vault_id, &genesis, &owner, 67, 1, 2);
    let fork_enroll = cosign_ed(
        enroll_entry(vault_id, &enroll_second, &owner, 68, 2, 3),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 4),
        &owner,
        &second,
    );
    let clean_prefix_child = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 5),
        &owner,
        &second,
    );
    let clean_prefix_child_hash = authority_entry_hash(&clean_prefix_child).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        clean_prefix_child,
        fork_ceiling,
        fork_enroll,
        enroll_second.clone(),
        genesis.clone(),
    ]);

    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&genesis).unwrap())
    );
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&enroll_second).unwrap())
    );
    assert!(!fold.valid_entries.contains(&clean_prefix_child_hash));
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == clean_prefix_child_hash
    )));
}

#[test]
fn quorum_revoke_resolves_authority_fork() {
    let owner = ed_key(70);
    let second = ed_key(71);
    let third = ed_key(72);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(70, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 71,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 72,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let fork_restrict = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );
    let restrict_hash = authority_entry_hash(&fork_restrict).unwrap();
    let fork_fold = fold_authority_log_without_seen_time_delay(&[
        fork_restrict.clone(),
        fork_ceiling.clone(),
        enroll_third.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ]);
    let winner = if fork_fold.valid_entries.contains(&restrict_hash) {
        fork_restrict.clone()
    } else {
        fork_ceiling.clone()
    };
    let revoke = cosign_ed(
        revoke_entry(vault_id, &winner, &second, owner_key.clone(), 0),
        &second,
        &third,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();
    let entries = vec![
        revoke.clone(),
        fork_ceiling.clone(),
        fork_restrict.clone(),
        enroll_third.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ];
    let permutations = [
        entries,
        vec![
            genesis,
            enroll_second,
            enroll_third,
            fork_restrict,
            fork_ceiling,
            revoke,
        ],
    ];

    for entries in permutations {
        let fold = fold_authority_log_without_seen_time_delay(&entries);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Resolved
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert!(
            fold.roster
                .get(&owner_key)
                .is_some_and(|device| device.revoked)
        );
        assert!(fold.valid_entries.contains(&revoke_hash));
    }
}

#[test]
fn quorum_revoke_on_clean_prefix_resolves_authority_fork() {
    let owner = ed_key(80);
    let second = ed_key(81);
    let third = ed_key(82);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(80, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 81,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 82,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let fork_restrict = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );
    let revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &second, owner_key.clone(), 0),
        &second,
        &third,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        revoke,
        fork_ceiling,
        fork_restrict,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&revoke_hash));
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Resolved
    );
    assert_eq!(fold.fork_alarms.len(), 1);
}

#[test]
fn conflicting_root_preserves_resolved_authority_fork_status() {
    let owner = ed_key(129);
    let second = ed_key(130);
    let third = ed_key(131);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(129, 86_400, 1);
    let foreign_genesis = genesis_entry(132, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 130,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 131,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let fork_restrict = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );
    let revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &second, owner_key.clone(), 0),
        &second,
        &third,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        foreign_genesis,
        revoke,
        fork_ceiling,
        fork_restrict,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert!(
        fold.issues
            .iter()
            .any(|issue| { matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }) })
    );
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Resolved
    );
    assert_eq!(fold.fork_alarms.len(), 1);
}

#[test]
fn conflicting_root_foreign_revoke_does_not_resolve_authority_fork() {
    let forked_owner = ed_key(152);
    let _local_second = ed_key(153);
    let foreign_owner = ed_key(154);
    let foreign_third = ed_key(155);
    let forked_key = authority_key_from_ed(&forked_owner);
    let local_genesis = genesis_entry(152, 86_400, 1);
    let local_vault_id = genesis_vault_id(&local_genesis).unwrap();
    let local_enroll_second = enroll_device_entry(
        local_vault_id,
        &local_genesis,
        &forked_owner,
        EnrollSpec {
            seed: 153,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let foreign_genesis = genesis_entry(154, 86_400, 1);
    let foreign_vault_id = genesis_vault_id(&foreign_genesis).unwrap();
    let foreign_enroll_forked_key = enroll_device_entry(
        foreign_vault_id,
        &foreign_genesis,
        &foreign_owner,
        EnrollSpec {
            seed: 152,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let foreign_enroll_third = cosign_ed(
        enroll_device_entry(
            foreign_vault_id,
            &foreign_enroll_forked_key,
            &foreign_owner,
            EnrollSpec {
                seed: 155,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &foreign_owner,
        &forked_owner,
    );
    let foreign_revoke = (0_u64..256)
        .map(|offset| {
            cosign_ed(
                revoke_entry_at(
                    foreign_vault_id,
                    &foreign_enroll_third,
                    &foreign_owner,
                    forked_key.clone(),
                    3,
                    40_000 + offset,
                ),
                &foreign_owner,
                &foreign_third,
            )
        })
        .max_by_key(|entry| authority_entry_hash(entry).unwrap())
        .unwrap();
    let foreign_revoke_hash = authority_entry_hash(&foreign_revoke).unwrap();
    let invalid_ceiling = (0_u64..256)
        .map(|offset| {
            set_ceiling_entry(
                local_vault_id,
                &local_enroll_second,
                &forked_owner,
                2,
                41_000 + offset,
            )
        })
        .min_by_key(|entry| authority_entry_hash(entry).unwrap())
        .unwrap();
    let invalid_tier = (0_u64..256)
        .map(|offset| {
            set_tier_floor_entry_at(
                local_vault_id,
                &local_enroll_second,
                &forked_owner,
                2,
                AuthorityTier::Hardware,
                42_000 + offset,
            )
        })
        .min_by_key(|entry| authority_entry_hash(entry).unwrap())
        .unwrap();
    let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    assert!(second_hash < foreign_revoke_hash);

    let fold = fold_authority_log_without_seen_time_delay(&[
        foreign_revoke,
        invalid_tier,
        invalid_ceiling,
        foreign_enroll_third,
        foreign_enroll_forked_key,
        foreign_genesis,
        local_enroll_second,
        local_genesis,
    ]);

    assert_eq!(fold.vault_id, None);
    assert_eq!(fold.valid_entries.len(), 0);
    assert_eq!(fold.roster.len(), 0);
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: forked_key.clone(),
            seq: 2,
            first_hash,
            second_hash,
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: forked_key,
            seq: 2,
            first_hash,
            second_hash,
        }]
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::MissingQuorum(_)))
            .count(),
        2
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
            .count(),
        6
    );
    assert_eq!(fold.issues.len(), 8);
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
            .count(),
        0
    );
}

#[test]
fn all_invalid_wrong_vault_fork_quarantines_signer_on_parent_vault() {
    let owner = ed_key(240);
    let second = ed_key(241);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(240, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let foreign_vault_id = genesis_vault_id(&genesis_entry(242, 86_400, 1)).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 241,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    // Same-(signer, seq) pair extending the local log while claiming a
    // foreign vault id: both fold as WrongVault, so the group resolves
    // all-invalid. The quarantine must scope to the parent vault the pair
    // tried to extend, not the bogus claimed id.
    let bogus_ceiling = set_ceiling_entry(foreign_vault_id, &enroll_second, &owner, 2, 3);
    let bogus_tier = set_tier_floor_entry_at(
        foreign_vault_id,
        &enroll_second,
        &owner,
        2,
        AuthorityTier::Hardware,
        4,
    );
    let ceiling_hash = authority_entry_hash(&bogus_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&bogus_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    // Later same-signer authorization on the real vault: the quarantined
    // owner cosigns a third-device enrollment signed by the second device.
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &second,
            EnrollSpec {
                seed: 243,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 0,
                ts: 5,
            },
        ),
        &second,
        &owner,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        enroll_third,
        bogus_tier,
        bogus_ceiling,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.roster.len(), 2);
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: owner_key.clone(),
            seq: 2,
            first_hash,
            second_hash,
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: owner_key,
            seq: 2,
            first_hash,
            second_hash,
        }]
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::WrongVault(_)))
            .count(),
        2
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(_)))
            .count(),
        1
    );
    assert_eq!(fold.issues.len(), 3);
}

#[test]
fn all_invalid_mixed_vault_claims_quarantine_every_plausible_vault() {
    let owner = ed_key(244);
    let second = ed_key(245);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(244, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    // Seed must stay below 246: genesis_nonce is [seed + 10; 32] via
    // wrapping_add, and an all-zero nonce fails body validation.
    let foreign_vault_id = genesis_vault_id(&genesis_entry(230, 86_400, 1)).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 245,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    // Neither candidate has a locally folded parent, and their claimed vault
    // ids disagree. Both claims remain plausible attack scopes, including the
    // real vault folded alongside this all-invalid group.
    let real_vault_claim = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![[0xfa; 32]],
            AuthorityOp::SetCeiling {
                authority_key: owner_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            owner_key.clone(),
            3,
        ),
        &owner,
    );
    let foreign_vault_claim = sign_ed(
        unsigned_entry(
            Some(foreign_vault_id),
            2,
            vec![[0xfb; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            owner_key.clone(),
            4,
        ),
        &owner,
    );
    let real_claim_hash = authority_entry_hash(&real_vault_claim).unwrap();
    let foreign_claim_hash = authority_entry_hash(&foreign_vault_claim).unwrap();
    let first_hash = real_claim_hash.min(foreign_claim_hash);
    let second_hash = real_claim_hash.max(foreign_claim_hash);
    let valid_later = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 5),
        &owner,
        &second,
    );
    let valid_later_hash = authority_entry_hash(&valid_later).unwrap();
    let forward = vec![
        valid_later,
        foreign_vault_claim,
        real_vault_claim,
        enroll_second,
        genesis,
    ];
    let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
    let mut expected = None;

    for entries in [forward, reverse] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 2);
        assert!(!fold.valid_entries.contains(&valid_later_hash));
        assert_eq!(fold.roster.len(), 2);
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: owner_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::InvalidAncestry(_)))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == valid_later_hash))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
        );
        assert_eq!(fold.issues.len(), 3);
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}
