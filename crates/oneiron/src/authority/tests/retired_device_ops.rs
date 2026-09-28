//! Retired device-key ops at the vault door.
//!
//! Client enrollment is pairing-only, and `SetTierFloor`, `RotateKey` and the
//! delayed veto died with the device-key ceremony plane (identity canon,
//! op-vocabulary amendment 2026-08-05). A retired op still folds as a verified
//! re-root's pre-handoff ancestry. The host enrolling an agent-only key for an
//! engine MACHINE writer is not a client enrollment (ARCH-0053: system actors
//! are seeded through the authority registry at bootstrap).

use super::support::*;
use super::*;

#[test]
fn hardware_tier_and_attestation_do_not_authorize_any_device_widen() {
    let owner = ed_key(62);
    let owner_key = authority_key_from_ed(&owner);
    for (tier, kind) in [
        (AuthorityTier::Software, "SoftwareArgon2id"),
        (AuthorityTier::Hardware, "Hardware"),
    ] {
        let mut root = device(owner_key.clone(), ROLE_OWNER | ROLE_ADMIN, tier);
        root.attestation.kind = kind.into();
        let genesis = sign_ed(
            unsigned_entry(
                None,
                0,
                Vec::new(),
                AuthorityOp::Genesis {
                    device: root,
                    genesis_nonce: [72; 32],
                    recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
                    tier_floor: AuthorityTier::Software,
                    pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
                },
                owner_key.clone(),
                1,
            ),
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
        let entries = [genesis, enroll];
        for now in [1, 1 + DEFAULT_PENDING_WIDEN_DELAY_SECS] {
            let fold = fold_authority_log_with_seen_times(&entries, &first_seen, now);
            assert!(!fold.valid_entries.contains(&enroll_hash));
            assert!(
                !fold
                    .roster
                    .contains_key(&authority_key_from_ed(&ed_key(63)))
            );
        }
    }
}

#[test]
fn rejected_client_enrollment_does_not_strand_independent_actor_revocation() {
    let owner = ed_key(231);
    let owner_key = authority_key_from_ed(&owner);
    let actor = scope_entity(232);
    let genesis = genesis_entry(231, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let bind = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            bind_op(&owner_key, actor, "human", 1),
            owner_key.clone(),
            2,
        ),
        &owner,
    );
    let enroll = enroll_device_entry(
        vault_id,
        &bind,
        &owner,
        EnrollSpec {
            seed: 233,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 2,
            ts: 3,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let prior = fold_authority_log(&[genesis.clone(), bind.clone()]);
    assert!(actor_binding_is_active(&prior, &actor, "human"));
    let revoke = sign_ed(
        unsigned_entry(
            Some(vault_id),
            3,
            vec![enroll_hash],
            revoke_actor_op(&owner_key, 5),
            owner_key.clone(),
            4,
        ),
        &owner,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();
    let entries = [genesis.clone(), bind.clone(), enroll.clone(), revoke];
    for ordered in [entries.to_vec(), entries.iter().rev().cloned().collect()] {
        let fold =
            fold_authority_log_with_seen_times(&ordered, &BTreeMap::from([(enroll_hash, 1)]), 1);
        assert!(!fold.valid_entries.contains(&enroll_hash));
        assert!(
            fold.valid_entries.contains(&revoke_hash),
            "issues: {:?}; status: {:?}",
            fold.issues,
            folded_status(&fold, &owner_key)
        );
        assert!(!actor_binding_is_active(&fold, &actor, "human"));
        assert_eq!(
            folded_status(&fold, &owner_key),
            Some(ActorBindingStatus::Revoked)
        );
    }
    // A signature from the rejected device has no independent ancestry.
    let rejected_key = ed_key(233);
    let wrong = sign_ed(
        unsigned_entry(
            Some(vault_id),
            0,
            vec![enroll_hash],
            revoke_actor_op(&owner_key, 5),
            authority_key_from_ed(&rejected_key),
            5,
        ),
        &rejected_key,
    );
    let wrong_hash = authority_entry_hash(&wrong).unwrap();
    let fold = fold_authority_log(&[genesis, bind, enroll, wrong]);
    assert!(!fold.valid_entries.contains(&wrong_hash));
    assert!(actor_binding_is_active(&fold, &actor, "human"));
}

#[test]
fn host_signed_agent_enrollment_is_not_a_retired_device_op() {
    let owner = ed_key(236);
    let genesis = genesis_entry(236, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    for (roles, retired) in [(ROLE_AGENT, false), (ROLE_AGENT | ROLE_ADMIN, true)] {
        let enroll = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 237,
                roles,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 2,
            },
        );
        let enroll_hash = authority_entry_hash(&enroll).unwrap();
        let enrolled_key = authority_key_from_ed(&ed_key(237));
        let entries = [genesis.clone(), enroll];
        for fold in [
            fold_authority_log(&entries),
            fold_authority_log_with_seen_times(&entries, &BTreeMap::from([(enroll_hash, 1)]), 1),
            fold_peer_authority_log(&entries),
        ] {
            assert_eq!(
                fold.valid_entries.contains(&enroll_hash),
                !retired,
                "{roles:#x}"
            );
            assert_eq!(
                fold.roster.contains_key(&enrolled_key),
                !retired,
                "{roles:#x}"
            );
        }
        assert!(
            fold_legacy_authority_log(&entries)
                .valid_entries
                .contains(&enroll_hash),
            "the legacy reference fold keeps the historical rule"
        );
    }
}
