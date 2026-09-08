//! Fork scoping across vaults, recovery winners and missing parents.

use super::support::*;
use super::*;

#[test]
fn mixed_scope_fork_resolves_each_vault_independently() {
    let forked = ed_key(165);
    let vault_a_owner = ed_key(166);
    let vault_a_third = ed_key(167);
    let vault_b_owner = ed_key(168);
    let vault_b_third = ed_key(169);
    let forked_key = authority_key_from_ed(&forked);

    let genesis_a = genesis_entry(166, 86_400, 1);
    let vault_a = genesis_vault_id(&genesis_a).unwrap();
    let enroll_third_a = enroll_device_entry(
        vault_a,
        &genesis_a,
        &vault_a_owner,
        EnrollSpec {
            seed: 167,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_forked_a = cosign_ed(
        enroll_device_entry(
            vault_a,
            &enroll_third_a,
            &vault_a_owner,
            EnrollSpec {
                seed: 165,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &vault_a_owner,
        &vault_a_third,
    );

    let genesis_b = genesis_entry(168, 86_400, 1);
    let vault_b = genesis_vault_id(&genesis_b).unwrap();
    let enroll_third_b = enroll_device_entry(
        vault_b,
        &genesis_b,
        &vault_b_owner,
        EnrollSpec {
            seed: 169,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_forked_b = cosign_ed(
        enroll_device_entry(
            vault_b,
            &enroll_third_b,
            &vault_b_owner,
            EnrollSpec {
                seed: 165,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &vault_b_owner,
        &vault_b_third,
    );

    // Both candidates are ancestry-invalid, but their claims make the one
    // signer fork gate both vaults.
    let fork_a = sign_ed(
        unsigned_entry(
            Some(vault_a),
            1,
            vec![[0xd1; 32]],
            AuthorityOp::SetCeiling {
                authority_key: forked_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            forked_key.clone(),
            4,
        ),
        &forked,
    );
    let fork_b = sign_ed(
        unsigned_entry(
            Some(vault_b),
            1,
            vec![[0xd2; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            forked_key.clone(),
            5,
        ),
        &forked,
    );
    let fork_a_hash = authority_entry_hash(&fork_a).unwrap();
    let fork_b_hash = authority_entry_hash(&fork_b).unwrap();

    let resolve_a = cosign_ed(
        revoke_entry(
            vault_a,
            &enroll_forked_a,
            &vault_a_third,
            forked_key.clone(),
            0,
        ),
        &vault_a_third,
        &vault_a_owner,
    );
    let resolve_a_hash = authority_entry_hash(&resolve_a).unwrap();
    let later_a = cosign_ed(
        set_ceiling_entry(vault_a, &resolve_a, &vault_a_owner, 3, 6),
        &vault_a_owner,
        &vault_a_third,
    );
    let later_a_hash = authority_entry_hash(&later_a).unwrap();
    let unresolved_later_b = cosign_ed(
        set_ceiling_entry(vault_b, &enroll_forked_b, &vault_b_owner, 3, 7),
        &vault_b_owner,
        &forked,
    );
    let unresolved_later_b_hash = authority_entry_hash(&unresolved_later_b).unwrap();

    let partially_resolved = vec![
        unresolved_later_b,
        later_a,
        resolve_a,
        fork_b.clone(),
        fork_a.clone(),
        enroll_third_b.clone(),
        enroll_forked_b.clone(),
        genesis_b.clone(),
        enroll_third_a.clone(),
        enroll_forked_a.clone(),
        genesis_a.clone(),
    ];
    let mut expected_partial = None;
    for entries in [
        partially_resolved.clone(),
        partially_resolved.iter().rev().cloned().collect(),
    ] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 0);
        assert_eq!(fold.roster.len(), 0);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, forked_key);
        assert_eq!(
            fold.authority_forks[0].first_hash,
            fork_a_hash.min(fork_b_hash)
        );
        assert_eq!(
            fold.authority_forks[0].second_hash,
            fork_a_hash.max(fork_b_hash)
        );
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
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
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash)
                        if *hash == unresolved_later_b_hash
                ))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash)
                        if *hash == later_a_hash || *hash == resolve_a_hash
                ))
                .count(),
            0
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
                .count(),
            8
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::ConflictingVaultRoot { entry, .. }
                        if *entry == later_a_hash || *entry == resolve_a_hash
                ))
                .count(),
            2
        );
        assert_eq!(fold.issues.len(), 11);
        if let Some(expected) = &expected_partial {
            assert_eq!(&fold, expected);
        } else {
            expected_partial = Some(fold);
        }
    }

    let resolve_b = cosign_ed(
        revoke_entry(
            vault_b,
            &enroll_forked_b,
            &vault_b_third,
            forked_key.clone(),
            0,
        ),
        &vault_b_third,
        &vault_b_owner,
    );
    let resolve_b_hash = authority_entry_hash(&resolve_b).unwrap();
    let later_b = cosign_ed(
        set_ceiling_entry(vault_b, &resolve_b, &vault_b_owner, 3, 8),
        &vault_b_owner,
        &vault_b_third,
    );
    let later_b_hash = authority_entry_hash(&later_b).unwrap();
    let fully_resolved = vec![
        later_b,
        resolve_b,
        partially_resolved[1].clone(),
        partially_resolved[2].clone(),
        fork_b,
        fork_a,
        enroll_third_b,
        enroll_forked_b,
        genesis_b,
        enroll_third_a,
        enroll_forked_a,
        genesis_a,
    ];
    let mut expected_full = None;
    for entries in [
        fully_resolved.clone(),
        fully_resolved.iter().rev().cloned().collect(),
    ] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 0);
        assert_eq!(fold.roster.len(), 0);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, forked_key);
        assert_eq!(
            fold.authority_forks[0].first_hash,
            fork_a_hash.min(fork_b_hash)
        );
        assert_eq!(
            fold.authority_forks[0].second_hash,
            fork_a_hash.max(fork_b_hash)
        );
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Resolved
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
                .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(_)))
                .count(),
            0
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
                .count(),
            10
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::ConflictingVaultRoot { entry, .. }
                        if *entry == later_a_hash
                            || *entry == later_b_hash
                            || *entry == resolve_a_hash
                            || *entry == resolve_b_hash
                ))
                .count(),
            4
        );
        assert_eq!(fold.issues.len(), 12);
        if let Some(expected) = &expected_full {
            assert_eq!(&fold, expected);
        } else {
            expected_full = Some(fold);
        }
    }
}

#[test]
fn empty_scope_genesis_shaped_fork_quarantines_signer_universally() {
    let owner = ed_key(153);
    let forked = ed_key(154);
    let owner_key = authority_key_from_ed(&owner);
    let forked_key = authority_key_from_ed(&forked);
    let genesis = genesis_entry(153, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_forked = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 154,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let prefork_entry = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_forked, &forked, 1, 3),
        &forked,
        &owner,
    );
    let prefork_hash = authority_entry_hash(&prefork_entry).unwrap();
    let later_entry = cosign_ed(
        set_ceiling_entry(vault_id, &prefork_entry, &forked, 3, 4),
        &forked,
        &owner,
    );
    let later_hash = authority_entry_hash(&later_entry).unwrap();
    let genesis_shaped = |nonce: u8, ts: u64| {
        sign_ed(
            unsigned_entry(
                None,
                2,
                Vec::new(),
                AuthorityOp::Genesis {
                    device: device(
                        forked_key.clone(),
                        ROLE_OWNER | ROLE_ADMIN,
                        AuthorityTier::Software,
                    ),
                    genesis_nonce: [nonce; 32],
                    tier_floor: AuthorityTier::Software,
                    pending_widen_delay_secs: 86_400,
                },
                forked_key.clone(),
                ts,
            ),
            &forked,
        )
    };
    let fork_left = genesis_shaped(0xa1, 5);
    let fork_right = genesis_shaped(0xa2, 6);
    let left_hash = authority_entry_hash(&fork_left).unwrap();
    let right_hash = authority_entry_hash(&fork_right).unwrap();
    let first_hash = left_hash.min(right_hash);
    let second_hash = left_hash.max(right_hash);
    let forward = vec![
        later_entry,
        fork_right,
        fork_left,
        prefork_entry,
        enroll_forked,
        genesis,
    ];
    let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
    let mut expected = None;

    for entries in [forward, reverse] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 3);
        assert!(fold.valid_entries.contains(&prefork_hash));
        assert!(!fold.valid_entries.contains(&later_hash));
        assert_eq!(fold.roster.len(), 2);
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
                signer: forked_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
            }]
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(_)))
                .count(),
            3
        );
        for rejected_hash in [left_hash, right_hash, later_hash] {
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::SignerNotInAncestry(hash)
                            if *hash == rejected_hash
                    ))
                    .count(),
                1
            );
        }
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
        );
        assert_eq!(fold.issues.len(), 3);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(false)
        );
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn recovery_fork_winner_requires_quorum_without_forked_signer() {
    let owner = ed_key(155);
    let second = ed_key(156);
    let third = ed_key(157);
    let owner_key = authority_key_from_ed(&owner);
    let recovered_bad_key = authority_key_from_ed(&ed_key(158));
    let recovered_independent_key = authority_key_from_ed(&ed_key(159));
    let genesis = genesis_entry(155, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 156,
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
                seed: 157,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let recovery_with_forked_quorum = cosign_ed(
        recovery_reboot_entry_at(vault_id, &enroll_third, &owner, 158, 3, 4),
        &owner,
        &second,
    );
    let bad_recovery_hash = authority_entry_hash(&recovery_with_forked_quorum).unwrap();

    for recovery_hash_is_first in [true, false] {
        let competing = (0_u64..4_096)
            .map(|offset| {
                cosign_ed(
                    set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 20_000 + offset),
                    &owner,
                    &second,
                )
            })
            .find(|entry| {
                (bad_recovery_hash < authority_entry_hash(entry).unwrap()) == recovery_hash_is_first
            })
            .expect("test fixture must cover both recovery candidate hash orders");
        let competing_hash = authority_entry_hash(&competing).unwrap();
        assert_eq!(bad_recovery_hash < competing_hash, recovery_hash_is_first);
        let first_hash = bad_recovery_hash.min(competing_hash);
        let second_hash = bad_recovery_hash.max(competing_hash);
        let forward = vec![
            competing,
            recovery_with_forked_quorum.clone(),
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ];
        let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
        let mut expected = None;

        for entries in [forward, reverse] {
            let fold = fold_authority_log_without_seen_time_delay(&entries);

            assert_eq!(fold.valid_entries.len(), 4);
            assert!(fold.valid_entries.contains(&competing_hash));
            assert!(!fold.valid_entries.contains(&bad_recovery_hash));
            assert_eq!(fold.roster.len(), 3);
            assert!(!fold.roster.contains_key(&recovered_bad_key));
            assert_eq!(
                fold.authority_forks,
                vec![AuthorityFork {
                    signer: owner_key.clone(),
                    seq: 3,
                    first_hash,
                    second_hash,
                    status: AuthorityForkStatus::Quarantined,
                }]
            );
            assert_eq!(fold.fork_alarms.len(), 1);
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::MissingQuorum(hash)
                            if *hash == bad_recovery_hash
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationDetected { signer, seq: 3 }
                            if *signer == owner_key
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationLoser {
                            entry,
                            signer,
                            seq: 3,
                            winner,
                        } if *entry == bad_recovery_hash
                            && *signer == owner_key
                            && *winner == competing_hash
                    ))
                    .count(),
                1
            );
            assert_eq!(fold.issues.len(), 3);
            if let Some(expected) = &expected {
                assert_eq!(&fold, expected);
            } else {
                expected = Some(fold);
            }
        }
    }

    let recovery_with_independent_quorum = cosign_ed_two(
        recovery_reboot_entry_at(vault_id, &enroll_third, &owner, 159, 3, 5),
        &owner,
        &second,
        &third,
    );
    let independent_recovery_hash =
        authority_entry_hash(&recovery_with_independent_quorum).unwrap();

    for recovery_hash_is_first in [true, false] {
        let competing = (0_u64..4_096)
            .map(|offset| {
                cosign_ed(
                    set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 30_000 + offset),
                    &owner,
                    &second,
                )
            })
            .find(|entry| {
                (independent_recovery_hash < authority_entry_hash(entry).unwrap())
                    == recovery_hash_is_first
            })
            .expect("test fixture must cover both independent recovery hash orders");
        let competing_hash = authority_entry_hash(&competing).unwrap();
        assert_eq!(
            independent_recovery_hash < competing_hash,
            recovery_hash_is_first
        );
        let first_hash = independent_recovery_hash.min(competing_hash);
        let second_hash = independent_recovery_hash.max(competing_hash);
        let forward = vec![
            competing,
            recovery_with_independent_quorum.clone(),
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ];
        let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
        let mut expected = None;

        for entries in [forward, reverse] {
            let fold = fold_authority_log_without_seen_time_delay(&entries);

            assert_eq!(fold.valid_entries.len(), 4);
            assert!(fold.valid_entries.contains(&independent_recovery_hash));
            assert!(!fold.valid_entries.contains(&competing_hash));
            assert_eq!(fold.roster.len(), 4);
            assert_eq!(
                fold.roster
                    .get(&recovered_independent_key)
                    .map(|device| device.revoked),
                Some(false)
            );
            assert_eq!(
                fold.authority_forks,
                vec![AuthorityFork {
                    signer: owner_key.clone(),
                    seq: 3,
                    first_hash,
                    second_hash,
                    status: AuthorityForkStatus::Resolved,
                }]
            );
            assert_eq!(fold.fork_alarms.len(), 1);
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationDetected { signer, seq: 3 }
                            if *signer == owner_key
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationLoser {
                            entry,
                            signer,
                            seq: 3,
                            winner,
                        } if *entry == competing_hash
                            && *signer == owner_key
                            && *winner == independent_recovery_hash
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::MissingQuorum(_)
                            | AuthorityFoldIssue::MissingAuthorityConsent(_)
                    ))
                    .count(),
                0
            );
            assert_eq!(fold.issues.len(), 2);
            if let Some(expected) = &expected {
                assert_eq!(&fold, expected);
            } else {
                expected = Some(fold);
            }
        }
    }
}

#[test]
fn missing_parent_fork_preserves_one_owner_prefork_consent() {
    let owner = ed_key(160);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(160, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let prefork_entry = set_ceiling_entry(vault_id, &genesis, &owner, 1, 2);
    let prefork_hash = authority_entry_hash(&prefork_entry).unwrap();
    let later_entry = set_ceiling_entry(vault_id, &prefork_entry, &owner, 3, 3);
    let later_hash = authority_entry_hash(&later_entry).unwrap();
    let missing_ceiling = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![[0xc1; 32]],
            AuthorityOp::SetCeiling {
                authority_key: owner_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            owner_key.clone(),
            4,
        ),
        &owner,
    );
    let missing_tier = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![[0xc2; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            owner_key.clone(),
            5,
        ),
        &owner,
    );
    let ceiling_hash = authority_entry_hash(&missing_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&missing_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    let forward = vec![
        later_entry,
        missing_tier,
        missing_ceiling,
        prefork_entry,
        genesis,
    ];
    let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
    let mut expected = None;

    for entries in [forward, reverse] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 2);
        assert!(fold.valid_entries.contains(&prefork_hash));
        assert!(!fold.valid_entries.contains(&later_hash));
        assert_eq!(fold.roster.len(), 1);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(false)
        );
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
        for missing_hash in [ceiling_hash, tier_hash] {
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::InvalidAncestry(hash) if *hash == missing_hash
                    ))
                    .count(),
                1
            );
        }
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == later_hash
                ))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::MissingAuthorityConsent(_)))
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

#[test]
fn missing_parent_cosigner_fork_fails_closed_for_unprovable_cosigns() {
    let owner = ed_key(175);
    let cosigner = ed_key(176);
    let cosigner_key = authority_key_from_ed(&cosigner);
    let genesis = genesis_entry(175, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_cosigner = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 176,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let cosigner_seq_zero = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_cosigner, &cosigner, 0, 3),
        &cosigner,
        &owner,
    );
    // Cosigned before the fork existed (ts 4), but the fork candidates have
    // missing parents, so no ancestry can prove it — indistinguishable from
    // a post-quarantine cosign by an attacker holding the cosigner's key,
    // and therefore rejected alongside it.
    let unprovable_prefix = cosign_ed(
        set_ceiling_entry(vault_id, &cosigner_seq_zero, &owner, 2, 4),
        &owner,
        &cosigner,
    );
    let unprovable_prefix_hash = authority_entry_hash(&unprovable_prefix).unwrap();
    let unproven_postfork = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_cosigner, &owner, 3, 7),
        &owner,
        &cosigner,
    );
    let unproven_postfork_hash = authority_entry_hash(&unproven_postfork).unwrap();
    let missing_ceiling = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![[0xe1; 32]],
            AuthorityOp::SetCeiling {
                authority_key: cosigner_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            cosigner_key.clone(),
            5,
        ),
        &cosigner,
    );
    let missing_tier = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![[0xe2; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            cosigner_key.clone(),
            6,
        ),
        &cosigner,
    );
    let missing_ceiling_hash = authority_entry_hash(&missing_ceiling).unwrap();
    let missing_tier_hash = authority_entry_hash(&missing_tier).unwrap();
    let entries = vec![
        unproven_postfork,
        missing_tier,
        missing_ceiling,
        unprovable_prefix,
        cosigner_seq_zero,
        enroll_cosigner,
        genesis,
    ];
    let mut expected = None;

    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 3);
        assert!(!fold.valid_entries.contains(&unprovable_prefix_hash));
        assert!(!fold.valid_entries.contains(&unproven_postfork_hash));
        assert_eq!(fold.roster.len(), 2);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, cosigner_key);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
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
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::InvalidAncestry(hash)
                        if *hash == missing_ceiling_hash || *hash == missing_tier_hash
                ))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash)
                        if *hash == unproven_postfork_hash || *hash == unprovable_prefix_hash
                ))
                .count(),
            2
        );
        assert_eq!(fold.issues.len(), 4);
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn self_rotation_winner_stays_quarantined_until_real_quorum_revoke() {
    let owner = ed_key(247);
    let second = ed_key(248);
    let rotated = ed_key(249);
    let owner_key = authority_key_from_ed(&owner);
    let rotated_key = authority_key_from_ed(&rotated);
    let genesis = genesis_entry(247, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 248,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    // Losing one role bit makes rotation the deterministic rank winner rather
    // than relying on its terminal hash. Exercise both relative hash orders.
    let rotate = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![authority_entry_hash(&enroll_second).unwrap()],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(rotated_key.clone(), ROLE_ADMIN, AuthorityTier::Software),
            },
            owner_key.clone(),
            3,
        ),
        &owner,
        &second,
    );
    let rotate_hash = authority_entry_hash(&rotate).unwrap();

    for rotate_hash_is_first in [true, false] {
        let competing = (0_u64..4_096)
            .map(|offset| {
                cosign_ed(
                    set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 10_000 + offset),
                    &owner,
                    &second,
                )
            })
            .find(|entry| {
                (rotate_hash < authority_entry_hash(entry).unwrap()) == rotate_hash_is_first
            })
            .expect("test fixture must cover both relative candidate hash orders");
        let competing_hash = authority_entry_hash(&competing).unwrap();
        assert_eq!(rotate_hash < competing_hash, rotate_hash_is_first);
        let first_hash = rotate_hash.min(competing_hash);
        let second_hash = rotate_hash.max(competing_hash);
        let quarantine_entries = vec![
            competing.clone(),
            rotate.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ];
        let mut expected_quarantine = None;

        for entries in [
            quarantine_entries.clone(),
            quarantine_entries.iter().rev().cloned().collect(),
        ] {
            let fold = fold_authority_log_without_seen_time_delay(&entries);

            assert_eq!(fold.valid_entries.len(), 3);
            assert!(fold.valid_entries.contains(&rotate_hash));
            assert!(!fold.valid_entries.contains(&competing_hash));
            assert_eq!(fold.roster.len(), 3);
            assert!(
                fold.roster
                    .get(&owner_key)
                    .is_some_and(|device| device.revoked)
            );
            assert!(
                fold.roster
                    .get(&rotated_key)
                    .is_some_and(|device| !device.revoked)
            );
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
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationDetected { .. }
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationLoser { .. }))
                    .count(),
                1
            );
            assert_eq!(fold.issues.len(), 2);
            if let Some(expected) = &expected_quarantine {
                assert_eq!(&fold, expected);
            } else {
                expected_quarantine = Some(fold);
            }
        }

        let real_revoke = cosign_ed(
            revoke_entry(vault_id, &rotate, &second, owner_key.clone(), 0),
            &second,
            &rotated,
        );
        let real_revoke_hash = authority_entry_hash(&real_revoke).unwrap();
        let resolved_entries = vec![
            real_revoke,
            competing,
            rotate.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ];
        let mut expected_resolved = None;

        for entries in [
            resolved_entries.clone(),
            resolved_entries.iter().rev().cloned().collect(),
        ] {
            let fold = fold_authority_log_without_seen_time_delay(&entries);

            assert_eq!(fold.valid_entries.len(), 4);
            assert!(fold.valid_entries.contains(&real_revoke_hash));
            assert_eq!(fold.roster.len(), 3);
            assert_eq!(
                fold.authority_forks,
                vec![AuthorityFork {
                    signer: owner_key.clone(),
                    seq: 2,
                    first_hash,
                    second_hash,
                    status: AuthorityForkStatus::Resolved,
                }]
            );
            assert_eq!(fold.fork_alarms.len(), 1);
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationDetected { .. }
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationLoser { .. }))
                    .count(),
                1
            );
            assert_eq!(fold.issues.len(), 2);
            if let Some(expected) = &expected_resolved {
                assert_eq!(&fold, expected);
            } else {
                expected_resolved = Some(fold);
            }
        }
    }
}
