//! Late fork rechecks, waiting, rank tiebreaks and seq-zero roots.

use super::support::*;
use super::*;

#[test]
fn late_all_invalid_quarantine_rechecks_previously_accepted_revoke() {
    let owner = ed_key(149);
    let second = ed_key(150);
    let third = ed_key(151);
    let owner_key = authority_key_from_ed(&owner);
    let third_key = authority_key_from_ed(&third);
    let genesis = genesis_entry(149, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 150,
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
                seed: 151,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let mut revoke_candidates: Vec<_> = (0_u64..256)
        .map(|offset| {
            cosign_ed(
                revoke_entry_at(
                    vault_id,
                    &enroll_third,
                    &second,
                    third_key.clone(),
                    0,
                    30_000 + offset,
                ),
                &second,
                &third,
            )
        })
        .collect();
    let parent_hash = authority_entry_hash(&enroll_third).unwrap();
    revoke_candidates.sort_by_key(|entry| sibling_fold_order_key(parent_hash, entry));
    let middle = revoke_candidates.len() / 2;
    let revoke = revoke_candidates.remove(middle);
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let revoke_first_ceiling = (0_u64..256)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 31_000 + offset))
        .max_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let revoke_first_tier = (0_u64..256)
        .map(|offset| {
            set_tier_floor_entry_at(
                vault_id,
                &enroll_third,
                &owner,
                3,
                AuthorityTier::Hardware,
                32_000 + offset,
            )
        })
        .max_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let fork_first_ceiling = (0_u64..256)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 33_000 + offset))
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
                34_000 + offset,
            )
        })
        .min_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let expected_valid_entries = BTreeSet::from([
        authority_entry_hash(&genesis).unwrap(),
        authority_entry_hash(&enroll_second).unwrap(),
        authority_entry_hash(&enroll_third).unwrap(),
    ]);
    let mut expected_roster = None;

    for (order, invalid_ceiling, invalid_tier) in [
        ("revoke-first", revoke_first_ceiling, revoke_first_tier),
        ("fork-first", fork_first_ceiling, fork_first_tier),
    ] {
        let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
        let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
        let first_hash = ceiling_hash.min(tier_hash);
        let second_hash = ceiling_hash.max(tier_hash);
        match order {
            "revoke-first" => {
                assert!(
                    sibling_fold_order_key(parent_hash, &revoke)
                        < sibling_fold_order_key(parent_hash, &invalid_ceiling)
                );
                assert!(
                    sibling_fold_order_key(parent_hash, &revoke)
                        < sibling_fold_order_key(parent_hash, &invalid_tier)
                );
            }
            "fork-first" => {
                assert!(
                    sibling_fold_order_key(parent_hash, &invalid_ceiling)
                        < sibling_fold_order_key(parent_hash, &revoke)
                );
                assert!(
                    sibling_fold_order_key(parent_hash, &invalid_tier)
                        < sibling_fold_order_key(parent_hash, &revoke)
                );
            }
            _ => unreachable!(),
        }

        let fold = fold_authority_log_without_seen_time_delay(&[
            revoke.clone(),
            invalid_tier,
            invalid_ceiling,
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);

        assert_eq!(fold.valid_entries, expected_valid_entries);
        assert_eq!(fold.roster.len(), 3);
        assert!(fold.roster.values().all(|device| !device.revoked));
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
        assert_eq!(
            fold.fork_alarms,
            vec![AuthorityForkAlarm {
                signer: owner_key.clone(),
                seq: 3,
                first_hash,
                second_hash,
            }]
        );
        assert_eq!(fold.issues.len(), 3);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::MissingQuorum(_)))
                .count(),
            3
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::MissingQuorum(hash) if *hash == revoke_hash
                ))
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
        match &expected_roster {
            Some(roster) => assert_eq!(&fold.roster, roster),
            None => expected_roster = Some(fold.roster),
        }
    }
}

#[test]
fn late_resolved_fork_rechecks_only_entries_outside_resolution_ancestry() {
    let owner = ed_key(172);
    let second = ed_key(173);
    let third = ed_key(174);
    let owner_key = authority_key_from_ed(&owner);
    let third_key = authority_key_from_ed(&third);
    let genesis = genesis_entry(172, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 173,
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
                seed: 174,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let parent_hash = authority_entry_hash(&enroll_third).unwrap();

    let revoke_third = (0_u64..4_096)
        .map(|offset| {
            cosign_ed(
                revoke_entry_at(
                    vault_id,
                    &enroll_third,
                    &second,
                    third_key.clone(),
                    0,
                    40_000 + offset,
                ),
                &second,
                &third,
            )
        })
        .min_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let revoke_third_hash = authority_entry_hash(&revoke_third).unwrap();
    let revoke_order = sibling_fold_order_key(parent_hash, &revoke_third);

    let invalid_ceiling = (0_u64..4_096)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 50_000 + offset))
        .find(|entry| sibling_fold_order_key(parent_hash, entry) > revoke_order)
        .expect("fixture must discover the fork after the sibling revoke");
    let invalid_ceiling_order = sibling_fold_order_key(parent_hash, &invalid_ceiling);
    let invalid_tier = (0_u64..4_096)
        .map(|offset| {
            set_tier_floor_entry_at(
                vault_id,
                &enroll_third,
                &owner,
                3,
                AuthorityTier::Hardware,
                60_000 + offset,
            )
        })
        .find(|entry| sibling_fold_order_key(parent_hash, entry) > revoke_order)
        .expect("fixture must discover both fork candidates after the sibling revoke");
    let invalid_tier_order = sibling_fold_order_key(parent_hash, &invalid_tier);
    let fork_order = invalid_ceiling_order.max(invalid_tier_order);

    let resolve_owner = (0_u64..4_096)
        .map(|offset| {
            cosign_ed(
                revoke_entry_at(
                    vault_id,
                    &enroll_third,
                    &third,
                    owner_key.clone(),
                    0,
                    70_000 + offset,
                ),
                &third,
                &second,
            )
        })
        .find(|entry| sibling_fold_order_key(parent_hash, entry) > fork_order)
        .expect("fixture must resolve the fork later in the same pass");
    let resolve_owner_hash = authority_entry_hash(&resolve_owner).unwrap();
    let after_resolution = cosign_ed(
        set_ceiling_entry(vault_id, &resolve_owner, &second, 1, 80_000),
        &second,
        &third,
    );
    let after_resolution_hash = authority_entry_hash(&after_resolution).unwrap();
    let invalid_ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let invalid_tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let entries = vec![
        after_resolution,
        resolve_owner,
        invalid_tier,
        invalid_ceiling,
        revoke_third,
        enroll_third,
        enroll_second,
        genesis,
    ];
    let mut expected = None;

    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 5);
        assert!(!fold.valid_entries.contains(&revoke_third_hash));
        assert!(fold.valid_entries.contains(&resolve_owner_hash));
        assert!(fold.valid_entries.contains(&after_resolution_hash));
        assert_eq!(fold.roster.len(), 3);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(true)
        );
        assert_eq!(
            fold.roster.get(&third_key).map(|device| device.revoked),
            Some(false)
        );
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Resolved
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::MissingQuorum(_)))
                .count(),
            3
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::MissingQuorum(hash) if *hash == revoke_third_hash
                ))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::MissingQuorum(hash)
                        if *hash == invalid_ceiling_hash || *hash == invalid_tier_hash
                ))
                .count(),
            2
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
fn post_revocation_same_seq_group_is_reported_resolved_with_denial_facts() {
    let owner = ed_key(139);
    let second = ed_key(140);
    let third = ed_key(141);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(139, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 140,
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
                seed: 141,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let revoke_owner = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &second, owner_key.clone(), 0),
        &second,
        &third,
    );
    let post_revoke_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &revoke_owner, &owner, 3, 4),
        &owner,
        &second,
    );
    let post_revoke_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &revoke_owner, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let revoke_hash = authority_entry_hash(&revoke_owner).unwrap();
    let ceiling_hash = authority_entry_hash(&post_revoke_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&post_revoke_tier).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        post_revoke_tier,
        post_revoke_ceiling,
        revoke_owner,
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
            first_hash: ceiling_hash.min(tier_hash),
            second_hash: ceiling_hash.max(tier_hash),
            status: AuthorityForkStatus::Resolved,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: owner_key,
            seq: 3,
            first_hash: ceiling_hash.min(tier_hash),
            second_hash: ceiling_hash.max(tier_hash),
        }]
    );
    let denial_hashes: Vec<_> = fold
        .issues
        .iter()
        .filter_map(|issue| match issue {
            AuthorityFoldIssue::SignerNotInAncestry(hash) => Some(*hash),
            _ => None,
        })
        .collect();
    assert_eq!(denial_hashes.len(), 2);
    assert_eq!(
        denial_hashes.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([ceiling_hash, tier_hash])
    );
}

#[test]
fn clean_prefix_entry_waits_when_unresolved_fork_key_is_cosigner() {
    let owner = ed_key(109);
    let second = ed_key(110);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(109, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 110,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
        &owner,
        &second,
    );
    let fork_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let clean_prefix_child = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &second, 0, 4),
        &second,
        &owner,
    );
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let enroll_second_hash = authority_entry_hash(&enroll_second).unwrap();
    let clean_prefix_child_hash = authority_entry_hash(&clean_prefix_child).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        genesis,
        enroll_second,
        fork_ceiling,
        fork_tier,
        clean_prefix_child,
    ]);

    assert!(fold.valid_entries.contains(&genesis_hash));
    assert!(fold.valid_entries.contains(&enroll_second_hash));
    assert!(!fold.valid_entries.contains(&clean_prefix_child_hash));
    assert!(fold.authority_forks.iter().any(|fork| {
        fork.signer == owner_key
            && fork.seq == 2
            && matches!(fork.status, AuthorityForkStatus::Quarantined)
    }));
}

#[test]
fn equivocation_group_waits_on_other_unresolved_equivocation() {
    let owner = ed_key(111);
    let second = ed_key(112);
    let owner_key = authority_key_from_ed(&owner);
    let second_key = authority_key_from_ed(&second);
    let genesis = genesis_entry(111, 86_400, 1);
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 112,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_second_hash = authority_entry_hash(&enroll_second).unwrap();
    let owner_fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
        &owner,
        &second,
    );
    let owner_fork_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let second_fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &second, 0, 4),
        &second,
        &owner,
    );
    let second_fork_tier = cosign_ed(
        set_tier_floor_entry(
            vault_id,
            &enroll_second,
            &second,
            0,
            AuthorityTier::Hardware,
        ),
        &second,
        &owner,
    );
    let owner_fork_ceiling_hash = authority_entry_hash(&owner_fork_ceiling).unwrap();
    let owner_fork_tier_hash = authority_entry_hash(&owner_fork_tier).unwrap();
    let second_fork_ceiling_hash = authority_entry_hash(&second_fork_ceiling).unwrap();
    let second_fork_tier_hash = authority_entry_hash(&second_fork_tier).unwrap();
    let by_hash = BTreeMap::from([
        (genesis_hash, genesis.clone()),
        (enroll_second_hash, enroll_second.clone()),
        (owner_fork_ceiling_hash, owner_fork_ceiling),
        (owner_fork_tier_hash, owner_fork_tier),
        (second_fork_ceiling_hash, second_fork_ceiling),
        (second_fork_tier_hash, second_fork_tier),
    ]);
    let entry_ancestors = entry_ancestor_index(&by_hash);
    let mut states = BTreeMap::new();
    let genesis_state = match fold_entry_state_for_test(&genesis, genesis_hash, &states) {
        EntryFold::Ready(state) => state,
        _ => panic!("genesis should fold"),
    };
    states.insert(genesis_hash, genesis_state);
    let enroll_state = match fold_entry_state_for_test(&enroll_second, enroll_second_hash, &states)
    {
        EntryFold::Ready(state) => state,
        _ => panic!("enrollment should fold"),
    };
    states.insert(enroll_second_hash, enroll_state);
    let owner_group_key = (owner_key, 2);
    let second_group_key = (second_key, 0);
    let owner_group = BTreeSet::from([owner_fork_ceiling_hash, owner_fork_tier_hash]);
    let second_group = BTreeSet::from([second_fork_ceiling_hash, second_fork_tier_hash]);
    let pending = BTreeSet::from([
        owner_fork_ceiling_hash,
        owner_fork_tier_hash,
        second_fork_ceiling_hash,
        second_fork_tier_hash,
    ]);
    let storage = LocalFoldContext {
        equivocation_groups: BTreeMap::from([
            (owner_group_key.clone(), owner_group),
            (second_group_key.clone(), second_group.clone()),
        ]),
        unresolved_equivocation_groups: BTreeSet::from([owner_group_key, second_group_key.clone()]),
        ..LocalFoldContext::default()
    };
    let context = FoldContext {
        entry_ancestors: Some(&entry_ancestors),
        ..storage.context()
    };

    assert!(matches!(
        resolve_equivocation_group(
            &second_group_key,
            &second_group,
            &by_hash,
            &states,
            &pending,
            context
        ),
        EquivocationResolution::Waiting
    ));
}

#[test]
fn resolved_fork_does_not_mask_unresolved_later_fork_for_same_key() {
    let (_, key, _, mut state) = single_owner_state(98);
    state.authority_forks.insert(
        (key.clone(), 1),
        AuthorityFork {
            signer: key.clone(),
            seq: 1,
            first_hash: [1; 32],
            second_hash: [2; 32],
            status: AuthorityForkStatus::Resolved,
        },
    );
    let authority_forks = BTreeMap::from([(
        (key.clone(), 2),
        AuthorityFork {
            signer: key.clone(),
            seq: 2,
            first_hash: [3; 32],
            second_hash: [4; 32],
            status: AuthorityForkStatus::Quarantined,
        },
    )]);
    let authority_fork_vault_ids =
        BTreeMap::from([((key.clone(), 2), BTreeSet::from([state.vault_id]))]);
    let storage = LocalFoldContext {
        authority_forks,
        authority_fork_vault_ids,
        ..LocalFoldContext::default()
    };
    let context = storage.context();

    assert!(key_is_quarantined_for_entry(
        &state, context, &key, [9; 32], None
    ));
}

#[test]
fn quarantined_keys_do_not_count_as_revoke_survivors() {
    let owner = ed_key(90);
    let second = ed_key(91);
    let third = ed_key(92);
    let second_key = authority_key_from_ed(&second);
    let genesis = genesis_entry(90, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 91,
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
            &second,
            EnrollSpec {
                seed: 92,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 0,
                ts: 3,
            },
        ),
        &second,
        &owner,
    );
    let fork_restrict = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 2, 4),
        &owner,
        &second,
    );
    let fork_fold = fold_authority_log_without_seen_time_delay(&[
        fork_restrict.clone(),
        fork_ceiling.clone(),
        enroll_third.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ]);
    let winner = if fork_fold
        .valid_entries
        .contains(&authority_entry_hash(&fork_restrict).unwrap())
    {
        fork_restrict.clone()
    } else {
        fork_ceiling.clone()
    };
    let revoke_second = cosign_ed(
        revoke_entry(vault_id, &winner, &second, second_key, 1),
        &second,
        &third,
    );
    let revoke_hash = authority_entry_hash(&revoke_second).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        revoke_second,
        fork_ceiling,
        fork_restrict,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 1);
    assert!(!fold.valid_entries.contains(&revoke_hash));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingQuorum(hash) if *hash == revoke_hash
    )));
}

#[test]
fn fork_winner_revoke_rechecks_quorum_without_quarantined_signer() {
    let owner = ed_key(106);
    let second = ed_key(107);
    let third = ed_key(108);
    let owner_key = authority_key_from_ed(&owner);
    let second_key = authority_key_from_ed(&second);
    let genesis = genesis_entry(106, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 107,
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
                seed: 108,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let bad_revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &owner, second_key, 3),
        &owner,
        &third,
    );
    let good_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );
    let bad_revoke_hash = authority_entry_hash(&bad_revoke).unwrap();
    let good_ceiling_hash = authority_entry_hash(&good_ceiling).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        bad_revoke,
        good_ceiling,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&good_ceiling_hash));
    assert!(!fold.valid_entries.contains(&bad_revoke_hash));
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
    assert_eq!(fold.fork_alarms.len(), 1);
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingQuorum(hash) if *hash == bad_revoke_hash
    )));
}

#[test]
fn winning_self_revoke_marks_authority_fork_resolved() {
    let owner = ed_key(93);
    let second = ed_key(94);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(93, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 94,
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
                seed: 95,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let self_revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &owner, owner_key.clone(), 3),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        fork_ceiling,
        self_revoke,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Resolved
    );
    assert_eq!(fold.fork_alarms.len(), 1);
}

#[test]
fn recovery_reboot_resolves_inherited_authority_fork() {
    let owner = ed_key(100);
    let second = ed_key(101);
    let third = ed_key(102);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(100, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 101,
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
                seed: 102,
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
    let fork_fold = fold_authority_log_without_seen_time_delay(&[
        fork_restrict.clone(),
        fork_ceiling.clone(),
        enroll_third.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ]);
    let winner = if fork_fold
        .valid_entries
        .contains(&authority_entry_hash(&fork_restrict).unwrap())
    {
        fork_restrict.clone()
    } else {
        fork_ceiling.clone()
    };
    let recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &winner, &second, 103, 0),
        &second,
        &third,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        recovery,
        fork_ceiling,
        fork_restrict,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Resolved
    );
    assert_eq!(fold.fork_alarms.len(), 1);
}

#[test]
fn independent_recovery_equivocation_groups_resolve_without_deadlock() {
    let owner = ed_key(133);
    let second = ed_key(134);
    let third = ed_key(135);
    let fourth = ed_key(136);
    let owner_key = authority_key_from_ed(&owner);
    let second_key = authority_key_from_ed(&second);
    let genesis = genesis_entry(133, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 134,
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
                seed: 135,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let enroll_fourth = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_third,
            &owner,
            EnrollSpec {
                seed: 136,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 3,
                ts: 4,
            },
        ),
        &owner,
        &second,
    );
    let owner_recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_fourth, &owner, 137, 4),
        &owner,
        &third,
    );
    let owner_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_fourth, &owner, 4, 5),
        &owner,
        &third,
    );
    let second_recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_fourth, &second, 138, 0),
        &second,
        &fourth,
    );
    let second_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_fourth, &second, 0, 6),
        &second,
        &fourth,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        second_ceiling,
        owner_recovery,
        enroll_fourth,
        second_recovery,
        owner_ceiling,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert_eq!(
        fold.authority_forks.len(),
        2,
        "forks: {:#?}",
        fold.authority_forks
    );
    assert_eq!(
        fold.authority_forks
            .iter()
            .map(|fork| fork.signer.clone())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([owner_key, second_key])
    );
    assert_eq!(fold.fork_alarms.len(), 2);
    let detections: Vec<_> = fold
        .issues
        .iter()
        .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
        .collect();
    assert_eq!(detections.len(), 2, "detections: {detections:#?}");
}

#[test]
fn same_signer_recovery_fork_does_not_wait_on_higher_sequence_fork() {
    let owner = ed_key(142);
    let second = ed_key(143);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(142, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 143,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_second, &owner, 144, 2),
        &owner,
        &second,
    );
    let recovery_peer = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
        &owner,
        &second,
    );
    let later_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let later_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 4),
        &owner,
        &second,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        later_ceiling,
        recovery_peer,
        later_tier,
        recovery,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 2);
    assert_eq!(
        fold.authority_forks
            .iter()
            .map(|fork| (fork.signer.clone(), fork.seq))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([(owner_key.clone(), 2), (owner_key, 3)]),
    );
    assert_eq!(fold.fork_alarms.len(), 2);
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
            .count(),
        1,
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(_)))
            .count(),
        2,
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::InvalidAncestry(_)))
            .count(),
        0,
    );
}

#[test]
fn fold_equivocation_fork_rank_prefers_more_restrictive_state_before_hash() {
    let owner = ed_key(34);
    let second = ed_key(35);
    let genesis = genesis_entry(34, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_entry(vault_id, &genesis, &owner, 35, 1, 2);
    let enroll_third = cosign_ed(
        enroll_entry(vault_id, &enroll_second, &owner, 36, 2, 3),
        &owner,
        &second,
    );
    let restrict_floor = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let restrict_hash = authority_entry_hash(&restrict_floor).unwrap();
    let grant_hash = authority_entry_hash(&enroll_third).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        enroll_third,
        restrict_floor,
        enroll_second,
        genesis,
    ]);
    assert!(fold.valid_entries.contains(&restrict_hash));
    assert!(!fold.valid_entries.contains(&grant_hash));
    assert_eq!(fold.tier_floor, Some(AuthorityTier::Hardware));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationDetected { signer: key, seq: 2 }
            if *key == authority_key_from_ed(&owner)
    )));
}

#[test]
fn pending_widen_equivocation_rank_uses_eventual_state() {
    let owner = ed_key(42);
    let genesis = genesis_entry(42, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let mut chosen = None;
    for seed in 43..96 {
        let pending = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: u64::from(seed),
            },
        );
        let ceiling = set_ceiling_entry(vault_id, &genesis, &owner, 1, u64::from(seed) + 100);
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let ceiling_hash = authority_entry_hash(&ceiling).unwrap();
        if pending_hash < ceiling_hash {
            chosen = Some((pending, pending_hash, ceiling, ceiling_hash));
            break;
        }
    }
    let (pending, pending_hash, ceiling, ceiling_hash) =
        chosen.expect("test seeds must include a pending hash below the ceiling hash");
    let first_seen = BTreeMap::from([(pending_hash, 0)]);

    let fold = fold_authority_log_with_seen_times(
        &[pending, ceiling, genesis],
        &first_seen,
        DEFAULT_PENDING_WIDEN_DELAY_SECS - 1,
    );

    assert!(fold.valid_entries.contains(&ceiling_hash));
    assert!(!fold.valid_entries.contains(&pending_hash));
    assert!(fold.pending_widens.is_empty());
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationDetected { signer: key, seq: 1 }
            if *key == authority_key_from_ed(&owner)
    )));
}

#[test]
fn fold_allows_newly_enrolled_signer_to_start_at_seq_zero() {
    let owner = ed_key(32);
    let new_signer = ed_key(33);
    let genesis = genesis_entry(32, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let owner_key = authority_key_from_ed(&owner);
    let new_key = authority_key_from_ed(&new_signer);
    let enroll_admin = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(new_key, ROLE_ADMIN, AuthorityTier::Software),
            },
            owner_key,
            2,
        ),
        &owner,
    );
    let first_new_signer_entry = cosign_ed(
        set_tier_floor_entry(
            vault_id,
            &enroll_admin,
            &new_signer,
            0,
            AuthorityTier::Hardware,
        ),
        &new_signer,
        &owner,
    );
    let first_hash = authority_entry_hash(&first_new_signer_entry).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        first_new_signer_entry,
        enroll_admin,
        genesis,
    ]);
    assert!(fold.valid_entries.contains(&first_hash));
    assert!(!fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::NonMonotonicSeq(hash) if *hash == first_hash
    )));
}

#[test]
fn fold_rejects_cross_vault_root_contamination() {
    let local = genesis_entry(26, 86_400, 1);
    let foreign = genesis_entry(27, 86_400, 1);

    let fold = fold_authority_log(&[local, foreign]);
    assert_eq!(fold.vault_id, None);
    assert!(fold.valid_entries.is_empty());
    assert!(fold.roster.is_empty());
    assert!(
        fold.issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
    );
}
