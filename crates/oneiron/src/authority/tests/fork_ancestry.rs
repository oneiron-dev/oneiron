//! Restore markers and fork-candidate ancestry exemption rules.

use super::support::*;
use super::*;

#[test]
fn restore_prefix_divergence_suppresses_authority_fork_alarm() {
    let owner = ed_key(73);
    let second = ed_key(74);
    let genesis = genesis_entry(73, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 74,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_second, &owner, 75, 2),
        &owner,
        &second,
    );
    let short_branch = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 3),
        &owner,
        &second,
    );
    let restored_branch = cosign_ed(
        set_tier_floor_entry(vault_id, &recovery, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );

    for entries in [
        vec![
            restored_branch.clone(),
            short_branch.clone(),
            recovery.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ],
        vec![
            genesis,
            enroll_second,
            recovery,
            short_branch,
            restored_branch,
        ],
    ] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);
        assert!(fold.fork_alarms.is_empty());
        assert!(fold.authority_forks.is_empty());
        assert!(
            !fold
                .issues
                .iter()
                .any(|issue| { matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }) })
        );
    }
}

#[test]
fn strict_prefix_without_restore_marker_still_quarantines_and_alarms() {
    let owner = ed_key(76);
    let second = ed_key(77);
    let genesis = genesis_entry(76, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 77,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let short_branch = set_ceiling_entry(vault_id, &genesis, &owner, 2, 3);
    let longer_branch = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fold = fold_authority_log_without_seen_time_delay(&[
        longer_branch,
        short_branch,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.fork_alarms.len(), 1);
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
    assert!(fold.issues.iter().any(|issue| {
        matches!(
            issue,
            AuthorityFoldIssue::EquivocationDetected { seq: 2, .. }
        )
    }));
}

#[test]
fn shared_restore_marker_does_not_suppress_later_strict_prefix_fork() {
    let owner = ed_key(83);
    let second = ed_key(84);
    let recovered = ed_key(85);
    let recovered_key = authority_key_from_ed(&recovered);
    let genesis = genesis_entry(83, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 84,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_second, &owner, 85, 2),
        &owner,
        &second,
    );
    let shared_after_recovery = set_ceiling_entry(vault_id, &recovery, &recovered, 0, 3);
    let short_branch =
        set_tier_floor_entry(vault_id, &recovery, &recovered, 1, AuthorityTier::Hardware);
    let longer_branch = set_ceiling_entry(vault_id, &shared_after_recovery, &recovered, 1, 4);

    let fold = fold_authority_log_without_seen_time_delay(&[
        longer_branch,
        short_branch,
        shared_after_recovery,
        recovery,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.fork_alarms.len(), 1);
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, recovered_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
}

#[test]
fn invalid_restore_marker_does_not_suppress_strict_prefix_fork_group() {
    let owner = ed_key(86);
    let second = ed_key(87);
    let genesis = genesis_entry(86, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 87,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let owner_key = authority_key_from_ed(&owner);
    let second_key = authority_key_from_ed(&second);
    let invalid_recovery = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![authority_entry_hash(&enroll_second).unwrap()],
            AuthorityOp::RecoveryReboot {
                new_genesis_nonce: [87; 32],
                new_device: device(second_key, ROLE_OWNER | ROLE_ADMIN, AuthorityTier::Software),
                tier_floor: AuthorityTier::Software,
            },
            owner_key,
            3,
        ),
        &owner,
        &second,
    );
    let short_branch = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 4),
        &owner,
        &second,
    );
    let longer_branch = cosign_ed(
        set_tier_floor_entry(
            vault_id,
            &invalid_recovery,
            &owner,
            3,
            AuthorityTier::Hardware,
        ),
        &owner,
        &second,
    );
    let by_hash = BTreeMap::from_iter([
        (authority_entry_hash(&genesis).unwrap(), genesis),
        (authority_entry_hash(&enroll_second).unwrap(), enroll_second),
        (
            authority_entry_hash(&invalid_recovery).unwrap(),
            invalid_recovery,
        ),
        (authority_entry_hash(&short_branch).unwrap(), short_branch),
        (authority_entry_hash(&longer_branch).unwrap(), longer_branch),
    ]);
    let group = BTreeSet::from_iter([
        *by_hash
            .iter()
            .find_map(|(hash, entry)| {
                matches!(entry.op, AuthorityOp::SetCeiling { .. }).then_some(hash)
            })
            .expect("short branch present"),
        *by_hash
            .iter()
            .find_map(|(hash, entry)| {
                matches!(entry.op, AuthorityOp::SetTierFloor { .. }).then_some(hash)
            })
            .expect("longer branch present"),
    ]);
    let ancestors = entry_ancestor_index(&by_hash);

    let storage = LocalFoldContext::default();
    assert!(
        !restore_prefix_divergence(&group, &by_hash, &ancestors, storage.context()),
        "invalid recovery markers must not route an equivocation group away from fork handling"
    );
}

#[test]
fn group_internal_parent_still_records_authority_fork() {
    let owner = ed_key(88);
    let second = ed_key(89);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(88, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 89,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let first = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
        &owner,
        &second,
    );
    let second_parented_to_first = cosign_ed(
        set_tier_floor_entry(vault_id, &first, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let second_hash = authority_entry_hash(&second_parented_to_first).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        second_parented_to_first,
        first,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidAncestry(hash) if *hash == second_hash
    )));
}

#[test]
fn all_invalid_same_seq_group_quarantines_later_entry() {
    let owner = ed_key(96);
    let second = ed_key(97);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(96, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 97,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let invalid_ceiling = set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3);
    let invalid_tier =
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware);
    let invalid_ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let invalid_tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let valid_later = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 4),
        &owner,
        &second,
    );
    let valid_later_hash = authority_entry_hash(&valid_later).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        valid_later,
        invalid_tier,
        invalid_ceiling,
        enroll_second,
        genesis,
    ]);

    assert!(!fold.valid_entries.contains(&valid_later_hash));
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: owner_key.clone(),
            seq: 2,
            first_hash: invalid_ceiling_hash.min(invalid_tier_hash),
            second_hash: invalid_ceiling_hash.max(invalid_tier_hash),
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: owner_key,
            seq: 2,
            first_hash: invalid_ceiling_hash.min(invalid_tier_hash),
            second_hash: invalid_ceiling_hash.max(invalid_tier_hash),
        }]
    );
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
    );
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == valid_later_hash
    )));
}

#[test]
fn forged_candidate_ancestors_do_not_exempt_postfork_signer_entry() {
    let owner = ed_key(176);
    let second = ed_key(177);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(176, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 177,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let postfork = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 182,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 3,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let postfork_hash = authority_entry_hash(&postfork).unwrap();
    let invalid_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &postfork, &owner, 2, 4),
        &owner,
        &second,
    );
    let invalid_tier = cosign_ed(
        set_tier_floor_entry_at(vault_id, &postfork, &owner, 2, AuthorityTier::Hardware, 5),
        &owner,
        &second,
    );
    let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);

    // In isolation each forged child reaches the seq-3 parent and fails for
    // the intended reason. Pairing them must not turn that unvalidated parent
    // claim into a prefork proof for the seq-3 entry.
    for (candidate, candidate_hash) in [
        (invalid_ceiling.clone(), ceiling_hash),
        (invalid_tier.clone(), tier_hash),
    ] {
        let probe = fold_authority_log_without_seen_time_delay(&[
            candidate,
            postfork.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);
        assert_eq!(
            probe
                .issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::NonMonotonicSeq(hash) if *hash == candidate_hash
                ))
                .count(),
            1
        );
        assert_eq!(probe.issues.len(), 1);
    }

    let entries = vec![
        invalid_tier,
        invalid_ceiling,
        postfork,
        enroll_second,
        genesis,
    ];
    let mut expected = None;
    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 2);
        assert!(!fold.valid_entries.contains(&postfork_hash));
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
                signer: owner_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
            }]
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == postfork_hash
                ))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::InvalidAncestry(hash)
                        if *hash == ceiling_hash || *hash == tier_hash
                ))
                .count(),
            2
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

#[test]
fn validated_fork_candidates_preserve_genuine_prefork_ancestor() {
    let owner = ed_key(178);
    let second = ed_key(179);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(178, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let prefork = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 179,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let prefork_hash = authority_entry_hash(&prefork).unwrap();
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &prefork, &owner, 2, 3),
        &owner,
        &second,
    );
    let fork_tier = cosign_ed(
        set_tier_floor_entry_at(vault_id, &prefork, &owner, 2, AuthorityTier::Hardware, 4),
        &owner,
        &second,
    );
    let ceiling_hash = authority_entry_hash(&fork_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&fork_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    let entries = vec![fork_tier, fork_ceiling, prefork, genesis];
    let mut expected = None;

    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 3);
        assert!(fold.valid_entries.contains(&prefork_hash));
        assert_eq!(
            [ceiling_hash, tier_hash]
                .iter()
                .filter(|hash| fold.valid_entries.contains(*hash))
                .count(),
            1
        );
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
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
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
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == prefork_hash
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

#[test]
fn invalid_candidates_do_not_exempt_forked_cosigner_ancestor() {
    let owner = ed_key(180);
    let forked = ed_key(181);
    let owner_key = authority_key_from_ed(&owner);
    let forked_key = authority_key_from_ed(&forked);
    let forged_enrolled_key = authority_key_from_ed(&ed_key(182));
    let genesis = genesis_entry(180, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_forked = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 181,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let postfork_signer_entry = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_forked, &forked, 3, 3),
        &forked,
        &owner,
    );
    let postfork_signer_hash = authority_entry_hash(&postfork_signer_entry).unwrap();
    let forged_cosigner_ancestor = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_forked,
            &owner,
            EnrollSpec {
                seed: 182,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 4,
            },
        ),
        &owner,
        &forked,
    );
    let forged_cosigner_hash = authority_entry_hash(&forged_cosigner_ancestor).unwrap();
    let mut forged_parents = vec![postfork_signer_hash, forged_cosigner_hash];
    forged_parents.sort_unstable();
    let invalid_ceiling = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            forged_parents.clone(),
            AuthorityOp::SetCeiling {
                authority_key: forked_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            forked_key.clone(),
            5,
        ),
        &forked,
        &owner,
    );
    let invalid_tier = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            forged_parents,
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            forked_key.clone(),
            6,
        ),
        &forked,
        &owner,
    );
    let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    let entries = vec![
        invalid_tier,
        invalid_ceiling,
        forged_cosigner_ancestor,
        postfork_signer_entry,
        enroll_forked,
        genesis,
    ];
    let mut expected = None;

    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 2);
        assert!(!fold.valid_entries.contains(&forged_cosigner_hash));
        assert!(!fold.valid_entries.contains(&postfork_signer_hash));
        assert_eq!(fold.roster.len(), 2);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(false)
        );
        assert!(!fold.roster.contains_key(&forged_enrolled_key));
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
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash)
                        if *hash == forged_cosigner_hash || *hash == postfork_signer_hash
                ))
                .count(),
            2
        );
        for quarantined_hash in [forged_cosigner_hash, postfork_signer_hash] {
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::SignerNotInAncestry(hash)
                            if *hash == quarantined_hash
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
                    AuthorityFoldIssue::InvalidAncestry(hash)
                        if *hash == ceiling_hash || *hash == tier_hash
                ))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
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
fn all_invalid_same_seq_group_resolves_clean_prefix_revoke() {
    let owner = ed_key(103);
    let second = ed_key(104);
    let third = ed_key(105);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(103, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 104,
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
                seed: 105,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let invalid_ceiling = set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4);
    let invalid_tier =
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware);
    let invalid_ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let invalid_tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let revoke_owner = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &second, owner_key.clone(), 0),
        &second,
        &third,
    );
    let revoke_hash = authority_entry_hash(&revoke_owner).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        revoke_owner,
        invalid_tier,
        invalid_ceiling,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&revoke_hash));
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: owner_key.clone(),
            seq: 3,
            first_hash: invalid_ceiling_hash.min(invalid_tier_hash),
            second_hash: invalid_ceiling_hash.max(invalid_tier_hash),
            status: AuthorityForkStatus::Resolved,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: owner_key,
            seq: 3,
            first_hash: invalid_ceiling_hash.min(invalid_tier_hash),
            second_hash: invalid_ceiling_hash.max(invalid_tier_hash),
        }]
    );
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
    );
}

#[test]
fn recovery_reboot_sibling_resolves_all_invalid_fork_in_both_hash_orders() {
    let owner = ed_key(145);
    let second = ed_key(146);
    let third = ed_key(147);
    let recovered = ed_key(148);
    let owner_key = authority_key_from_ed(&owner);
    let recovered_key = authority_key_from_ed(&recovered);
    let genesis = genesis_entry(145, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 146,
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
                seed: 147,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let mut recovery_candidates: Vec<_> = (0_u64..256)
        .map(|offset| {
            cosign_ed(
                recovery_reboot_entry_at(vault_id, &enroll_third, &second, 148, 0, 10_000 + offset),
                &second,
                &third,
            )
        })
        .collect();
    let parent_hash = authority_entry_hash(&enroll_third).unwrap();
    recovery_candidates.sort_by_key(|entry| sibling_fold_order_key(parent_hash, entry));
    let middle = recovery_candidates.len() / 2;
    let recovery = recovery_candidates.remove(middle);
    let recovery_hash = authority_entry_hash(&recovery).unwrap();

    let reboot_first_ceiling = (0_u64..256)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 20_000 + offset))
        .max_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let reboot_first_tier = (0_u64..256)
        .map(|offset| {
            set_tier_floor_entry_at(
                vault_id,
                &enroll_third,
                &owner,
                3,
                AuthorityTier::Hardware,
                21_000 + offset,
            )
        })
        .max_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let fork_first_ceiling = (0_u64..256)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 22_000 + offset))
        .min_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let fork_first_tier = (0_u64..256)
        .map(|offset| {
            set_tier_floor_entry_at(
                vault_id,
                &enroll_third,
                &owner,
                3,
                AuthorityTier::Hardware,
                23_000 + offset,
            )
        })
        .min_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let expected_valid_entries = BTreeSet::from([
        authority_entry_hash(&genesis).unwrap(),
        authority_entry_hash(&enroll_second).unwrap(),
        authority_entry_hash(&enroll_third).unwrap(),
        recovery_hash,
    ]);
    let mut expected_roster = None;

    for (order, invalid_ceiling, invalid_tier) in [
        ("reboot-first", reboot_first_ceiling, reboot_first_tier),
        ("fork-first", fork_first_ceiling, fork_first_tier),
    ] {
        let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
        let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
        let first_hash = ceiling_hash.min(tier_hash);
        let second_hash = ceiling_hash.max(tier_hash);
        match order {
            "reboot-first" => {
                assert!(
                    sibling_fold_order_key(parent_hash, &recovery)
                        < sibling_fold_order_key(parent_hash, &invalid_ceiling)
                );
                assert!(
                    sibling_fold_order_key(parent_hash, &recovery)
                        < sibling_fold_order_key(parent_hash, &invalid_tier)
                );
            }
            "fork-first" => {
                assert!(
                    sibling_fold_order_key(parent_hash, &invalid_ceiling)
                        < sibling_fold_order_key(parent_hash, &recovery)
                );
                assert!(
                    sibling_fold_order_key(parent_hash, &invalid_tier)
                        < sibling_fold_order_key(parent_hash, &recovery)
                );
            }
            _ => unreachable!(),
        }

        let fold = fold_authority_log_without_seen_time_delay(&[
            recovery.clone(),
            invalid_tier,
            invalid_ceiling,
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);

        assert_eq!(fold.valid_entries, expected_valid_entries);
        assert_eq!(fold.roster.len(), 4);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(true)
        );
        assert_eq!(
            fold.roster.get(&recovered_key).map(|device| device.revoked),
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
        assert_eq!(
            fold.fork_alarms,
            vec![AuthorityForkAlarm {
                signer: owner_key.clone(),
                seq: 3,
                first_hash,
                second_hash,
            }]
        );
        assert_eq!(fold.issues.len(), 2);
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
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
        );
        match &expected_roster {
            Some(roster) => assert_eq!(&fold.roster, roster),
            None => expected_roster = Some(fold.roster),
        }
    }
}
