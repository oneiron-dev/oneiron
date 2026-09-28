//! Fold validation for enroll, rotate, recovery, revoke and divergent ancestry.

use super::support::*;
use super::*;

#[test]
fn fold_rejects_duplicate_active_enroll_key_before_role_intersection() {
    let (owner, owner_key, parent, state) = single_owner_state(42);
    let entry = sign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![parent],
            AuthorityOp::EnrollDevice {
                device: device(owner_key.clone(), ROLE_AGENT, AuthorityTier::Software),
            },
            owner_key,
            1,
        ),
        &owner,
    );
    let hash = authority_entry_hash(&entry).unwrap();

    assert!(matches!(
        fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
        EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(issue_hash))
            if issue_hash == hash
    ));
}

#[test]
fn fold_rejects_rotation_to_revoked_destination_key() {
    let (owner, owner_key, parent, mut state) = single_owner_state(43);
    let revoked = ed_key(44);
    let revoked_key = authority_key_from_ed(&revoked);
    state.roster.insert(
        revoked_key.clone(),
        FoldedDevice {
            key: revoked_key.clone(),
            tier: AuthorityTier::Software,
            roles: ROLE_ADMIN,
            revoked: true,
        },
    );
    let entry = sign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![parent],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(revoked_key, ROLE_ADMIN, AuthorityTier::Software),
            },
            owner_key,
            1,
        ),
        &owner,
    );
    let hash = authority_entry_hash(&entry).unwrap();

    assert!(matches!(
        fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
        EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(issue_hash))
            if issue_hash == hash
    ));
}

#[test]
fn fold_rejects_rotation_that_leaves_no_authority_consent() {
    let (owner, owner_key, parent, state) = single_owner_state(45);
    let agent = ed_key(46);
    let entry = sign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![parent],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(
                    authority_key_from_ed(&agent),
                    ROLE_AGENT,
                    AuthorityTier::Software,
                ),
            },
            owner_key,
            1,
        ),
        &owner,
    );
    let hash = authority_entry_hash(&entry).unwrap();

    assert!(matches!(
        fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
        EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(issue_hash))
            if issue_hash == hash
    ));
}

#[test]
fn rotation_that_would_leave_no_authority_consent_is_rejected_by_the_seen_time_fold() {
    let owner = ed_key(115);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(115, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let agent_key = authority_key_from_ed(&ed_key(116));
    let rotate = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![genesis_hash],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(agent_key.clone(), ROLE_AGENT, AuthorityTier::Software),
            },
            owner_key,
            2,
        ),
        &owner,
    );
    let rotate_hash = authority_entry_hash(&rotate).unwrap();
    let first_seen = BTreeMap::from([(rotate_hash, 10)]);

    let fold = fold_authority_log_with_seen_times(&[genesis, rotate], &first_seen, 10);

    assert!(!fold.roster.contains_key(&agent_key));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingAuthorityConsent(issue_hash) if *issue_hash == rotate_hash
    )));
}

#[test]
fn re_root_requires_consenting_new_device() {
    let owner = ed_key(47);
    let agent = ed_key(48);
    let owner_key = authority_key_from_ed(&owner);
    let op = AuthorityOp::ReRoot {
        new_device: device(
            authority_key_from_ed(&agent),
            ROLE_AGENT,
            AuthorityTier::Software,
        ),
    };
    let entry = unsigned_entry(Some([47; 32]), 1, vec![[48; 32]], op, owner_key, 1);

    let err = encode_authority_log_entry_body(&entry)
        .expect_err("recovery reboot must install a consenting authority");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn fold_rejects_re_root_reusing_existing_key() {
    let (owner, owner_key, parent, state) = single_owner_state(49);
    let entry = sign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![parent],
            AuthorityOp::ReRoot {
                new_device: device(owner_key.clone(), ROLE_OWNER, AuthorityTier::Software),
            },
            owner_key,
            1,
        ),
        &owner,
    );
    let hash = authority_entry_hash(&entry).unwrap();

    assert!(matches!(
        fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
        EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(issue_hash))
            if issue_hash == hash
    ));
}

#[test]
fn dangling_sibling_does_not_block_valid_ancestor() {
    let owner = ed_key(50);
    let genesis = genesis_entry(50, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let ready = set_tier_floor_entry(vault_id, &genesis, &owner, 1, AuthorityTier::Hardware);
    let dangling = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![[0xDA; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::CloudCustodial,
            },
            authority_key_from_ed(&owner),
            3,
        ),
        &owner,
    );
    let ready_hash = authority_entry_hash(&ready).unwrap();
    let dangling_hash = authority_entry_hash(&dangling).unwrap();

    let fold = fold_authority_log(&[dangling, ready, genesis]);
    assert!(fold.valid_entries.contains(&ready_hash));
    assert!(!fold.valid_entries.contains(&dangling_hash));
    assert_eq!(fold.tier_floor, Some(AuthorityTier::Hardware));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidAncestry(hash) if *hash == dangling_hash
    )));
}

#[test]
fn fold_rejects_entries_signed_by_revoked_key() {
    let owner = ed_key(4);
    let revoked_signer = ed_key(5);
    let cosigner = ed_key(6);
    let genesis = genesis_entry(4, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_entry(vault_id, &genesis, &owner, 5, 1, 2);
    let enroll_cosigner = cosign_ed(
        enroll_entry(vault_id, &enroll, &owner, 6, 2, 3),
        &owner,
        &revoked_signer,
    );
    let revoke = cosign_ed(
        revoke_entry(
            vault_id,
            &enroll_cosigner,
            &owner,
            authority_key_from_ed(&revoked_signer),
            3,
        ),
        &owner,
        &cosigner,
    );
    let invalid_child = enroll_entry(vault_id, &revoke, &revoked_signer, 7, 1, 4);

    let fold = fold_authority_log(&[
        invalid_child.clone(),
        revoke,
        enroll_cosigner,
        enroll,
        genesis,
    ]);
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&invalid_child).unwrap())
    );
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::SignerNotInAncestry(hash)
            if *hash == authority_entry_hash(&invalid_child).unwrap()
    )));
}

#[test]
fn fold_rejects_revoke_without_surviving_quorum() {
    let owner = ed_key(14);
    let revoked_signer = ed_key(15);
    let genesis = genesis_entry(14, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_entry(vault_id, &genesis, &owner, 15, 1, 2);
    let revoke = revoke_entry(
        vault_id,
        &enroll,
        &owner,
        authority_key_from_ed(&revoked_signer),
        2,
    );

    let fold = fold_authority_log(&[revoke.clone(), enroll, genesis]);
    assert!(fold.issues.iter().any(|issue| matches!(
    issue,
    AuthorityFoldIssue::MissingQuorum(hash)
        if *hash == authority_entry_hash(&revoke).unwrap()
    )));
}

#[test]
fn same_signer_same_sequence_siblings_fold_by_ancestry_without_quarantine() {
    let owner = ed_key(16);
    let genesis = genesis_entry(16, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let left = enroll_entry(vault_id, &genesis, &owner, 17, 1, 2);
    let right = enroll_entry(vault_id, &genesis, &owner, 18, 1, 3);
    let left_hash = authority_entry_hash(&left).unwrap();
    let right_hash = authority_entry_hash(&right).unwrap();
    let entries = [genesis, left, right];
    let fold = fold_authority_log(&entries);

    assert!(fold.valid_entries.contains(&left_hash), "{:?}", fold.issues);
    assert!(
        fold.valid_entries.contains(&right_hash),
        "{:?}",
        fold.issues
    );
    assert_eq!(fold.roster.len(), 3);
    assert!(fold.issues.is_empty(), "{:?}", fold.issues);

    let reversed: Vec<_> = entries.into_iter().rev().collect();
    assert_eq!(fold_authority_log(&reversed), fold);
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

    let fold = fold_authority_log(&[first_new_signer_entry, enroll_admin, genesis]);
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
    fn divergent_same_sequence_entries_are_permutation_invariant(
        perm in prop::collection::vec(0_usize..4, 4),
    ) {
        let owner = ed_key(90);
        let genesis = genesis_entry(90, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll = enroll_entry(vault_id, &genesis, &owner, 91, 1, 2);
        let left = set_ceiling_entry(vault_id, &enroll, &owner, 2, 3);
        let right = set_tier_floor_entry(vault_id, &enroll, &owner, 2, AuthorityTier::Hardware);
        let entries = vec![genesis, enroll, left, right];
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
        prop_assert_eq!(folded.valid_entries, baseline.valid_entries);
    }

    #[test]
    fn fold_permutation_property_across_legacy_genesis_delay_values(
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
}
