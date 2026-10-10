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

    let fold = fold_legacy_authority_log(&[dangling, ready, genesis]);
    assert!(fold.valid_entries.contains(&ready_hash));
    assert!(!fold.valid_entries.contains(&dangling_hash));
    assert_eq!(fold.tier_floor, Some(AuthorityTier::Hardware));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidAncestry(hash) if *hash == dangling_hash
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

    let fold = fold_legacy_authority_log(&[revoke.clone(), enroll, genesis]);
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
    let fold = fold_legacy_authority_log(&entries);

    assert!(fold.valid_entries.contains(&left_hash), "{:?}", fold.issues);
    assert!(
        fold.valid_entries.contains(&right_hash),
        "{:?}",
        fold.issues
    );
    assert_eq!(fold.roster.len(), 3);
    assert!(fold.issues.is_empty(), "{:?}", fold.issues);

    let reversed: Vec<_> = entries.into_iter().rev().collect();
    assert_eq!(fold_legacy_authority_log(&reversed), fold);
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
