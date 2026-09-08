//! Fold validation for enroll, rotate, recovery, revoke and equivocation.

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
fn delayed_rotation_that_would_leave_no_authority_consent_is_not_pending() {
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

    assert!(!fold.pending_widens.contains_key(&rotate_hash));
    assert!(!fold.roster.contains_key(&agent_key));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingAuthorityConsent(issue_hash) if *issue_hash == rotate_hash
    )));
}

#[test]
fn recovery_reboot_requires_consenting_new_device() {
    let owner = ed_key(47);
    let agent = ed_key(48);
    let owner_key = authority_key_from_ed(&owner);
    let op = AuthorityOp::RecoveryReboot {
        new_genesis_nonce: [47; 32],
        new_device: device(
            authority_key_from_ed(&agent),
            ROLE_AGENT,
            AuthorityTier::Software,
        ),
        tier_floor: AuthorityTier::Software,
    };
    let entry = unsigned_entry(Some([47; 32]), 1, vec![[48; 32]], op, owner_key, 1);

    let err = encode_authority_log_entry_body(&entry)
        .expect_err("recovery reboot must install a consenting authority");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn fold_rejects_recovery_reboot_reusing_existing_key() {
    let (owner, owner_key, parent, state) = single_owner_state(49);
    let entry = sign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![parent],
            AuthorityOp::RecoveryReboot {
                new_genesis_nonce: [49; 32],
                new_device: device(owner_key.clone(), ROLE_OWNER, AuthorityTier::Software),
                tier_floor: AuthorityTier::Software,
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
fn fold_equivocation_dangling_fork_does_not_block_ready_winner() {
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

    let fold = fold_authority_log_without_seen_time_delay(&[
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

    let fold = fold_authority_log_without_seen_time_delay(&[revoke.clone(), enroll, genesis]);
    assert!(fold.issues.iter().any(|issue| matches!(
    issue,
    AuthorityFoldIssue::MissingQuorum(hash)
        if *hash == authority_entry_hash(&revoke).unwrap()
    )));
}

#[test]
fn fold_detects_equivocation_by_signer_and_seq() {
    let left = genesis_entry(16, 86_400, 1);
    let right = genesis_entry(16, 86_400, 2);
    let signer = authority_key_from_ed(&ed_key(16));
    let left_hash = authority_entry_hash(&left).unwrap();
    let right_hash = authority_entry_hash(&right).unwrap();
    let winner_hash = left_hash.min(right_hash);
    let winner_vault_id = if winner_hash == left_hash {
        genesis_vault_id(&left).unwrap()
    } else {
        genesis_vault_id(&right).unwrap()
    };

    let fold = fold_authority_log(&[left, right]);
    assert_eq!(fold.vault_id, Some(winner_vault_id));
    assert!(fold.valid_entries.contains(&winner_hash));
    assert_eq!(fold.valid_entries.len(), 1);
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationDetected { signer: key, seq: 0 }
            if *key == signer
    )));
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: signer.clone(),
            seq: 0,
            first_hash: left_hash.min(right_hash),
            second_hash: left_hash.max(right_hash),
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer,
            seq: 0,
            first_hash: left_hash.min(right_hash),
            second_hash: left_hash.max(right_hash),
        }]
    );
    assert_eq!(AuthorityForkAlarm::KIND, AUTHORITY_FORK_ALARM_KIND);
}

#[test]
fn fold_records_equivocation_loser_denial_fact() {
    let left = genesis_entry(124, 86_400, 1);
    let right = genesis_entry(124, 86_400, 2);
    let signer = authority_key_from_ed(&ed_key(124));
    let left_hash = authority_entry_hash(&left).unwrap();
    let right_hash = authority_entry_hash(&right).unwrap();
    let winner_hash = left_hash.min(right_hash);
    let loser_hash = left_hash.max(right_hash);

    let fold = fold_authority_log(&[left, right]);

    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationLoser {
            entry,
            signer: key,
            seq: 0,
            winner,
        } if *entry == loser_hash && *key == signer && *winner == winner_hash
    )));
    assert!(!fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidEntry(hash) if *hash == loser_hash
    )));
}

#[test]
fn fold_records_signed_invalid_equivocation_candidate_as_loser() {
    let left = genesis_entry(125, 86_400, 1);
    let right = genesis_entry(125, 86_400, 2);
    let signer = ed_key(125);
    let signer_key = authority_key_from_ed(&signer);
    let signed_invalid = sign_ed(
        unsigned_entry(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: device(
                    authority_key_from_ed(&ed_key(126)),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
                genesis_nonce: [126; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: 86_400,
            },
            signer_key.clone(),
            3,
        ),
        &signer,
    );
    let mut ordinary_invalid = genesis_entry(127, 86_400, 4);
    ordinary_invalid.signer.signature[0] ^= 0xff;
    let left_hash = authority_entry_hash(&left).unwrap();
    let right_hash = authority_entry_hash(&right).unwrap();
    let winner_hash = left_hash.min(right_hash);
    let ready_loser_hash = left_hash.max(right_hash);
    let signed_invalid_hash = authority_entry_hash(&signed_invalid).unwrap();
    let ordinary_invalid_hash = authority_entry_hash(&ordinary_invalid).unwrap();

    let fold = fold_authority_log(&[left, right, signed_invalid, ordinary_invalid]);

    assert!(fold.valid_entries.contains(&winner_hash));
    for loser_hash in [ready_loser_hash, signed_invalid_hash] {
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::EquivocationLoser {
                entry,
                signer,
                seq: 0,
                winner,
            } if *entry == loser_hash && *signer == signer_key && *winner == winner_hash
        )));
    }
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == signed_invalid_hash
    )));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidEntry(hash) if *hash == ordinary_invalid_hash
    )));
    assert!(!fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationLoser { entry, .. } if *entry == ordinary_invalid_hash
    )));
}

#[test]
fn fold_records_missing_parent_equivocation_candidate_as_loser() {
    let owner = ed_key(128);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(128, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let valid_candidate = set_ceiling_entry(vault_id, &genesis, &owner, 1, 2);
    let missing_parent_candidate = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![[0xfe; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            owner_key.clone(),
            3,
        ),
        &owner,
    );
    let winner_hash = authority_entry_hash(&valid_candidate).unwrap();
    let loser_hash = authority_entry_hash(&missing_parent_candidate).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        missing_parent_candidate,
        valid_candidate,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&winner_hash));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidAncestry(hash) if *hash == loser_hash
    )));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationLoser {
            entry,
            signer,
            seq: 1,
            winner,
        } if *entry == loser_hash && *signer == owner_key && *winner == winner_hash
    )));
}

#[test]
fn multiway_equivocation_alarm_spans_min_and_max_hashes() {
    let owner = ed_key(64);
    let second = ed_key(65);
    let signer = authority_key_from_ed(&owner);
    let genesis = genesis_entry(64, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_entry(vault_id, &genesis, &owner, 65, 1, 2);
    let fork_enroll = cosign_ed(
        enroll_entry(vault_id, &enroll_second, &owner, 66, 2, 3),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 4),
        &owner,
        &second,
    );
    let fork_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let mut hashes = [
        authority_entry_hash(&fork_enroll).unwrap(),
        authority_entry_hash(&fork_ceiling).unwrap(),
        authority_entry_hash(&fork_tier).unwrap(),
    ];
    hashes.sort();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fork_ceiling,
        fork_tier,
        fork_enroll,
        enroll_second,
        genesis,
    ]);

    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: signer.clone(),
            seq: 2,
            first_hash: hashes[0],
            second_hash: hashes[2],
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer,
            seq: 2,
            first_hash: hashes[0],
            second_hash: hashes[2],
        }]
    );
}
