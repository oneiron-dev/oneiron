//! Tier-widen delay, owner veto, seen-time convergence and permutation.

use super::support::*;
use super::*;

#[test]
fn software_tier_widen_waits_for_local_seen_time_window() {
    let owner = ed_key(60);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(60, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 61,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let first_seen = BTreeMap::from([(enroll_hash, 10)]);
    let new_key = authority_key_from_ed(&ed_key(61));

    let before = fold_authority_log_with_seen_times(
        &[genesis.clone(), enroll.clone()],
        &first_seen,
        10 + delay - 1,
    );
    assert!(!before.roster.contains_key(&new_key));
    let pending = before.pending_widens.get(&enroll_hash).unwrap();
    assert_eq!(pending.first_seen_at_secs, Some(10));
    assert_eq!(pending.eligible_at_secs, Some(10 + delay));
    assert_eq!(pending.delay_secs, delay);

    let after = fold_authority_log_with_seen_times(&[genesis, enroll], &first_seen, 10 + delay);
    assert!(after.roster.contains_key(&new_key));
    assert!(after.pending_widens.is_empty());
}

#[test]
fn hardware_tier_widen_is_instant() {
    let owner = ed_key(62);
    let owner_key = authority_key_from_ed(&owner);
    let op = AuthorityOp::Genesis {
        device: device(
            owner_key.clone(),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Hardware,
        ),
        genesis_nonce: [72; 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
    };
    let genesis = sign_ed(
        unsigned_entry(None, 0, Vec::new(), op, owner_key, 1),
        &owner,
    );
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 63,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let first_seen = BTreeMap::from([(enroll_hash, 1)]);
    let fold = fold_authority_log_with_seen_times(&[genesis, enroll], &first_seen, 1);

    assert!(
        fold.roster
            .contains_key(&authority_key_from_ed(&ed_key(63)))
    );
    assert!(fold.pending_widens.is_empty());
}

#[test]
fn veto_from_owner_kills_pending_widen_in_every_arrival_order() {
    let owner = ed_key(64);
    let genesis = genesis_entry(64, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 65,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let veto = veto_entry(vault_id, &genesis, &owner, pending_hash, 2);
    let first_seen = BTreeMap::from([(pending_hash, 0)]);
    let permutations = [
        vec![genesis.clone(), pending.clone(), veto.clone()],
        vec![genesis.clone(), veto.clone(), pending.clone()],
        vec![pending.clone(), genesis.clone(), veto.clone()],
        vec![pending.clone(), veto.clone(), genesis.clone()],
        vec![veto.clone(), genesis.clone(), pending.clone()],
        vec![veto, pending, genesis],
    ];

    for entries in permutations {
        let fold = fold_authority_log_with_seen_times(&entries, &first_seen, 200);
        assert!(
            !fold
                .roster
                .contains_key(&authority_key_from_ed(&ed_key(65)))
        );
        assert!(fold.vetoed_widens.contains(&pending_hash));
        assert!(fold.pending_widens.is_empty());
    }
}

#[test]
fn veto_after_local_seen_time_window_does_not_revoke_active_widen() {
    let owner = ed_key(95);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(95, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 96,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let veto = veto_entry(vault_id, &genesis, &owner, pending_hash, 2);
    let veto_hash = authority_entry_hash(&veto).unwrap();
    let first_seen = BTreeMap::from([(pending_hash, 0)]);

    let fold = fold_authority_log_with_seen_times(&[veto, pending, genesis], &first_seen, delay);

    assert!(
        fold.roster
            .contains_key(&authority_key_from_ed(&ed_key(96)))
    );
    assert!(!fold.valid_entries.contains(&veto_hash));
    assert!(!fold.vetoed_widens.contains(&pending_hash));
}

#[test]
fn admin_without_owner_role_cannot_veto_pending_widen() {
    let owner = ed_key(81);
    let admin = ed_key(82);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(81, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_admin = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 82,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_admin_hash = authority_entry_hash(&enroll_admin).unwrap();
    let pending = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_admin,
            &owner,
            EnrollSpec {
                seed: 83,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &admin,
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let veto = veto_entry(vault_id, &pending, &admin, pending_hash, 0);
    let veto_hash = authority_entry_hash(&veto).unwrap();
    let first_seen = BTreeMap::from([(enroll_admin_hash, 0), (pending_hash, delay)]);

    let fold = fold_authority_log_with_seen_times(
        &[veto, pending, enroll_admin, genesis],
        &first_seen,
        delay,
    );

    assert!(!fold.valid_entries.contains(&veto_hash));
    assert!(!fold.vetoed_widens.contains(&pending_hash));
    assert!(fold.pending_widens.contains_key(&pending_hash));
}

#[test]
fn veto_child_of_delayed_rotation_survives_when_old_key_lands_revoked() {
    let owner = ed_key(73);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(73, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(vault_id, &genesis, &owner, owner_key.clone(), 74, 1);
    let rotation_hash = authority_entry_hash(&rotation).unwrap();
    let malicious_widen = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 75,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 2,
            ts: 2,
        },
    );
    let malicious_hash = authority_entry_hash(&malicious_widen).unwrap();
    let veto = veto_entry(vault_id, &rotation, &owner, malicious_hash, 3);
    let veto_hash = authority_entry_hash(&veto).unwrap();
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let first_seen = BTreeMap::from([(rotation_hash, 0), (malicious_hash, delay)]);

    let fold = fold_authority_log_with_seen_times(
        &[veto, malicious_widen, rotation, genesis],
        &first_seen,
        delay,
    );

    assert!(fold.valid_entries.contains(&veto_hash));
    assert!(fold.vetoed_widens.contains(&malicious_hash));
    assert!(
        !fold
            .roster
            .contains_key(&authority_key_from_ed(&ed_key(75)))
    );
    assert!(
        fold.roster
            .get(&owner_key)
            .is_some_and(|device| device.revoked)
    );
}

#[test]
fn delayed_rotation_veto_key_cannot_veto_descendant_widen() {
    let owner = ed_key(76);
    let owner_key = authority_key_from_ed(&owner);
    let new_owner = ed_key(77);
    let genesis = genesis_entry(76, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(vault_id, &genesis, &owner, owner_key, 77, 1);
    let rotation_hash = authority_entry_hash(&rotation).unwrap();
    let future_widen = enroll_device_entry(
        vault_id,
        &rotation,
        &new_owner,
        EnrollSpec {
            seed: 78,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 0,
            ts: 2,
        },
    );
    let future_hash = authority_entry_hash(&future_widen).unwrap();
    let veto = veto_entry(vault_id, &rotation, &owner, future_hash, 2);
    let veto_hash = authority_entry_hash(&veto).unwrap();
    let first_seen = BTreeMap::from([(rotation_hash, 0), (future_hash, 0)]);

    let fold = fold_authority_log_with_seen_times(
        &[veto, future_widen, rotation, genesis],
        &first_seen,
        DEFAULT_PENDING_WIDEN_DELAY_SECS,
    );

    assert!(!fold.valid_entries.contains(&veto_hash));
    assert!(!fold.vetoed_widens.contains(&future_hash));
    assert!(
        fold.roster
            .contains_key(&authority_key_from_ed(&ed_key(78)))
    );
}

#[test]
fn child_of_pending_widen_waits_for_parent_seen_time_eligibility() {
    let owner = ed_key(97);
    let admin = ed_key(98);
    let child = ed_key(99);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(97, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending_admin = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 98,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending_admin).unwrap();
    let child_widen = cosign_ed(
        enroll_device_entry(
            vault_id,
            &pending_admin,
            &owner,
            EnrollSpec {
                seed: 99,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &admin,
    );
    let child_hash = authority_entry_hash(&child_widen).unwrap();
    let first_seen = BTreeMap::from([(pending_hash, 0), (child_hash, 0)]);

    let before = fold_authority_log_with_seen_times(
        &[child_widen.clone(), pending_admin.clone(), genesis.clone()],
        &first_seen,
        delay - 1,
    );
    assert!(!before.valid_entries.contains(&child_hash));
    assert!(!before.roster.contains_key(&authority_key_from_ed(&child)));

    let after = fold_authority_log_with_seen_times(
        &[child_widen, pending_admin, genesis],
        &first_seen,
        delay,
    );
    assert!(after.valid_entries.contains(&child_hash));
    assert!(after.roster.contains_key(&authority_key_from_ed(&child)));
}

#[test]
fn non_widen_child_of_pending_widen_waits_for_parent_seen_time_eligibility() {
    let owner = ed_key(100);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(100, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending_admin = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 101,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending_admin).unwrap();
    let child_ceiling = set_ceiling_entry(vault_id, &pending_admin, &owner, 2, 3);
    let child_hash = authority_entry_hash(&child_ceiling).unwrap();
    let first_seen = BTreeMap::from([(pending_hash, 0)]);

    let before = fold_authority_log_with_seen_times(
        &[
            child_ceiling.clone(),
            pending_admin.clone(),
            genesis.clone(),
        ],
        &first_seen,
        delay - 1,
    );
    assert!(!before.valid_entries.contains(&child_hash));
    assert!(before.pending_widens.contains_key(&pending_hash));

    let after = fold_authority_log_with_seen_times(
        &[child_ceiling, pending_admin, genesis],
        &first_seen,
        delay,
    );
    assert!(!after.valid_entries.contains(&child_hash));
    assert!(after.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingQuorum(hash) if *hash == child_hash
    )));
}

#[test]
fn devices_with_different_first_seen_times_temporarily_diverge_then_converge() {
    let owner = ed_key(66);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(66, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 67,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let new_key = authority_key_from_ed(&ed_key(67));
    let early_seen = BTreeMap::from([(pending_hash, 0)]);
    let late_seen = BTreeMap::from([(pending_hash, delay - 25)]);

    let early_fold = fold_authority_log_with_seen_times(
        &[genesis.clone(), pending.clone()],
        &early_seen,
        delay + 50,
    );
    let late_fold = fold_authority_log_with_seen_times(
        &[genesis.clone(), pending.clone()],
        &late_seen,
        delay + 50,
    );
    assert!(early_fold.roster.contains_key(&new_key));
    assert!(!late_fold.roster.contains_key(&new_key));
    assert!(late_fold.pending_widens.contains_key(&pending_hash));

    let late_after = fold_authority_log_with_seen_times(&[genesis, pending], &late_seen, delay * 2);
    assert_eq!(early_fold.roster, late_after.roster);
    assert!(late_after.pending_widens.is_empty());
}

#[test]
fn concurrent_restriction_beats_pending_widen_after_delay() {
    let owner = ed_key(68);
    let second = ed_key(69);
    let target = ed_key(70);
    let target_key = authority_key_from_ed(&target);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(68, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 69,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Hardware,
            seq: 1,
            ts: 2,
        },
    );
    let pending = enroll_device_entry(
        vault_id,
        &enroll_second,
        &owner,
        EnrollSpec {
            seed: 70,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 2,
            ts: 3,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_second, &second, target_key.clone(), 0),
        &second,
        &owner,
    );
    let first_seen = BTreeMap::from([
        (authority_entry_hash(&enroll_second).unwrap(), 0),
        (pending_hash, delay),
    ]);

    let fold = fold_authority_log_with_seen_times(
        &[pending, revoke, enroll_second, genesis],
        &first_seen,
        delay * 2,
    );
    let folded = fold
        .roster
        .get(&target_key)
        .expect("restriction tombstone should keep the target visible");
    assert!(folded.revoked);
    assert_eq!(folded.roles, 0);
}

#[test]
fn genesis_delay_knob_defaults_within_band_and_custom_delay_is_honored() {
    let owner = ed_key(71);
    let custom_delay = MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(71, custom_delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 72,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let first_seen = BTreeMap::from([(pending_hash, 0)]);

    let before = fold_authority_log_with_seen_times(
        &[genesis.clone(), pending.clone()],
        &first_seen,
        custom_delay - 1,
    );
    assert_eq!(
        before.pending_widens[&pending_hash].delay_secs,
        custom_delay
    );
    assert!(
        !before
            .roster
            .contains_key(&authority_key_from_ed(&ed_key(72)))
    );

    let after = fold_authority_log_with_seen_times(&[genesis, pending], &first_seen, custom_delay);
    assert!(
        after
            .roster
            .contains_key(&authority_key_from_ed(&ed_key(72)))
    );
}

#[test]
fn timestamp_is_advisory_for_fold_output() {
    let owner = ed_key(7);
    let genesis_a = genesis_entry(7, 86_400, 1);
    let genesis_b = genesis_entry(7, 86_400, 999_999);
    let vault_a = genesis_vault_id(&genesis_a).unwrap();
    let vault_b = genesis_vault_id(&genesis_b).unwrap();
    let enroll_a = enroll_entry(vault_a, &genesis_a, &owner, 8, 1, 2);
    let enroll_b = enroll_entry(vault_b, &genesis_b, &owner, 8, 1, 999_998);

    let fold_a = fold_authority_log(&[genesis_a, enroll_a]);
    let fold_b = fold_authority_log(&[genesis_b, enroll_b]);
    let roles_a: Vec<_> = fold_a
        .roster
        .values()
        .map(|device| (device.roles, device.revoked))
        .collect();
    let roles_b: Vec<_> = fold_b
        .roster
        .values()
        .map(|device| (device.roles, device.revoked))
        .collect();
    assert_eq!(roles_a, roles_b);
}

proptest! {
    #[test]
    fn equivocation_alarm_is_permutation_invariant(
        perm in prop::collection::vec(0_usize..4, 4),
    ) {
        let owner = ed_key(90);
        let genesis = genesis_entry(90, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll = enroll_entry(vault_id, &genesis, &owner, 91, 1, 2);
        let left = set_ceiling_entry(vault_id, &enroll, &owner, 2, 3);
        let right = set_tier_floor_entry(vault_id, &enroll, &owner, 2, AuthorityTier::Hardware);
        let entries = vec![genesis, enroll, left, right];
        let baseline = fold_authority_log_without_seen_time_delay(&entries);

        let mut permuted = Vec::new();
        for index in perm {
            if let Some(entry) = entries.get(index % entries.len()) {
                permuted.push(entry.clone());
            }
        }
        for entry in &entries {
            if !permuted.iter().any(|candidate| candidate == entry) {
                permuted.push(entry.clone());
            }
        }

        let folded = fold_authority_log_without_seen_time_delay(&permuted);
        prop_assert_eq!(folded.authority_forks, baseline.authority_forks);
        prop_assert_eq!(folded.fork_alarms, baseline.fork_alarms);
        prop_assert_eq!(folded.valid_entries, baseline.valid_entries);
    }

    #[test]
    fn fold_permutation_property_including_pending_widen_delay(
        delay in 86_400_u64..=172_800,
        include_revoke in any::<bool>(),
        perm in prop::collection::vec(0_usize..4, 4),
    ) {
        let owner = ed_key(10);
        let genesis = genesis_entry(10, delay, 11);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_a = enroll_entry(vault_id, &genesis, &owner, 11, 1, 12);
        let enroll_b = enroll_entry(vault_id, &genesis, &owner, 12, 2, 13);
        let revoke = revoke_entry(
            vault_id,
            &enroll_a,
            &owner,
            authority_key_from_ed(&ed_key(11)),
            3,
        );
        let mut entries = vec![genesis, enroll_a, enroll_b];
        if include_revoke {
            entries.push(revoke);
        }
        let baseline = fold_authority_log(&entries);

        let mut permuted = Vec::new();
        for index in perm {
            if let Some(entry) = entries.get(index % entries.len()) {
                permuted.push(entry.clone());
            }
        }
        for entry in &entries {
            if !permuted.iter().any(|candidate| candidate == entry) {
                permuted.push(entry.clone());
            }
        }
        let folded = fold_authority_log(&permuted);
        prop_assert_eq!(folded.vault_id, baseline.vault_id);
        prop_assert_eq!(folded.roster, baseline.roster);
        prop_assert_eq!(folded.tier_floor, baseline.tier_floor);
    }

    #[test]
    fn fold_seen_time_veto_race_is_permutation_invariant(
        delay in 86_400_u64..=172_800,
        include_veto in any::<bool>(),
        perm in prop::collection::vec(0_usize..3, 3),
    ) {
        let owner = ed_key(20);
        let genesis = genesis_entry(20, delay, 21);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let pending = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 21,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 22,
            },
        );
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let veto = veto_entry(vault_id, &genesis, &owner, pending_hash, 2);
        let mut entries = vec![genesis, pending];
        if include_veto {
            entries.push(veto);
        }
        let first_seen = BTreeMap::from([(pending_hash, 0)]);
        let baseline = fold_authority_log_with_seen_times(&entries, &first_seen, delay - 1);

        let mut permuted = Vec::new();
        for index in perm {
            if let Some(entry) = entries.get(index % entries.len()) {
                permuted.push(entry.clone());
            }
        }
        for entry in &entries {
            if !permuted.iter().any(|candidate| candidate == entry) {
                permuted.push(entry.clone());
            }
        }
        let folded = fold_authority_log_with_seen_times(&permuted, &first_seen, delay - 1);
        prop_assert_eq!(folded.vault_id, baseline.vault_id);
        prop_assert_eq!(folded.roster, baseline.roster);
        prop_assert_eq!(folded.pending_widens, baseline.pending_widens);
        prop_assert_eq!(folded.vetoed_widens, baseline.vetoed_widens);
        prop_assert_eq!(folded.tier_floor, baseline.tier_floor);
    }
}
