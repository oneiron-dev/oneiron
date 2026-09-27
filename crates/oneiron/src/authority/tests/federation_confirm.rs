//! Federation-confirm replay and live-roster binding laws.
use super::support::*;
use super::*;

fn confirm(
    parent: &AuthorityLogEntry,
    genesis: &AuthorityLogEntry,
    seed: u8,
    seq: u64,
    id: u8,
    nonce: u8,
) -> AuthorityLogEntry {
    let signing = ed_key(seed);
    sign_ed(
        unsigned_entry(
            Some(genesis_vault_id(genesis).unwrap()),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: AuthorityConfirmKind::Accept,
                confirm_id: [id; 32],
                peer_vault_id: [77; 32],
                epoch: 1,
                nonce: [nonce; 16],
            }),
            authority_key_from_ed(&signing),
            3,
        ),
        &signing,
    )
}

#[test]
fn federation_confirm_consumes_ids_nonces_and_requires_live_roster() {
    let genesis = genesis_entry(21, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let first = confirm(&genesis, &genesis, 21, 1, 1, 1);
    for (id, nonce) in [(1, 2), (2, 1), (1, 1)] {
        let replay = confirm(&first, &genesis, 21, 2, id, nonce);
        let fold = fold_authority_log(&[replay.clone(), first.clone(), genesis.clone()]);
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&first).unwrap())
        );
        assert!(
            !fold
                .valid_entries
                .contains(&authority_entry_hash(&replay).unwrap())
        );
        assert_eq!(fold.federation_confirms.len(), 1);
    }
    let outsider = confirm(&first, &genesis, 22, 2, 2, 2);
    let fold = fold_authority_log(&[genesis, first, outsider.clone()]);
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&outsider).unwrap())
    );
}

#[test]
fn federation_confirm_sibling_replay_is_permutation_independent() {
    let genesis = genesis_entry(21, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let a = confirm(&genesis, &genesis, 21, 1, 1, 1);
    let b = confirm(&genesis, &genesis, 21, 2, 2, 1);
    let first = fold_authority_log(&[genesis.clone(), a.clone(), b.clone()]);
    let second = fold_authority_log(&[b.clone(), genesis, a.clone()]);
    assert_eq!(first, second);
    assert_eq!(first.federation_confirms.len(), 1);
    let hashes = [
        authority_entry_hash(&a).unwrap(),
        authority_entry_hash(&b).unwrap(),
    ];
    assert_eq!(
        hashes
            .iter()
            .filter(|h| first.valid_entries.contains(*h))
            .count(),
        1
    );
}

#[test]
fn federation_confirm_codec_all_kinds_and_zero_rejection() {
    let genesis = genesis_entry(21, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    for kind in [
        AuthorityConfirmKind::Accept,
        AuthorityConfirmKind::Rescope,
        AuthorityConfirmKind::A2aConnect,
        AuthorityConfirmKind::Revoke,
    ] {
        let mut entry = confirm(&genesis, &genesis, 21, 1, 1, 1);
        let AuthorityOp::FederationConfirm(ref mut action) = entry.op else {
            unreachable!()
        };
        action.kind = kind;
        entry = sign_ed(entry, &ed_key(21));
        let bytes = encode_authority_log_entry_body(&entry).unwrap();
        assert_eq!(decode_authority_log_entry_body(&bytes).unwrap(), entry);
        for zero_id in [false, true] {
            let mut bad = entry.clone();
            let AuthorityOp::FederationConfirm(ref mut action) = bad.op else {
                unreachable!()
            };
            if zero_id {
                action.confirm_id = [0; 32];
            } else {
                action.nonce = [0; 16];
            }
            assert!(encode_authority_log_entry_body(&bad).is_err());
        }
    }
}

/// A later nonce collision can invalidate the ENROLLMENT that authorized a
/// previously verified revoke. Only the enrollment drops; its verified revoke
/// floor cannot resurrect an independently valid owner binding.
#[test]
fn verified_revoke_survives_rejection_of_its_signers_enrollment() {
    let owner_seed = 81;
    let owner = ed_key(owner_seed);
    let owner_key = authority_key_from_ed(&owner);
    let actor = scope_entity(0x71);
    let genesis = genesis_entry(owner_seed, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
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
    let first = confirm(&bind, &genesis, owner_seed, 2, 55, 77);
    let first_hash = authority_entry_hash(&first).unwrap();
    let signer_seed = 82;
    let signer = ed_key(signer_seed);
    let signer_key = authority_key_from_ed(&signer);
    let enroll = enroll_device_entry(
        vault_id,
        &first,
        &owner,
        EnrollSpec {
            seed: signer_seed,
            roles: ROLE_AGENT,
            tier: AuthorityTier::Software,
            seq: 3,
            ts: 4,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let revoke = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![enroll_hash],
            revoke_actor_op(&owner_key, 2),
            signer_key.clone(),
            5,
        ),
        &signer,
        &owner,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();
    let mut entries = vec![genesis.clone(), bind.clone(), first, enroll, revoke];
    let before = fold_authority_log_without_seen_time_delay(&entries);
    assert!(
        before.issues.is_empty(),
        "valid revoke fixture: {:?}",
        before.issues
    );
    assert!(before.valid_entries.contains(&revoke_hash));
    assert_eq!(
        folded_status(&before, &owner_key),
        Some(ActorBindingStatus::Revoked)
    );

    // A signed sibling confirm has a different id and a different signer seq,
    // but reuses the nonce. Pick a lower hash so the collision rejects `first`.
    let replacement = (1..=u8::MAX)
        .map(|id| confirm(&bind, &genesis, owner_seed, 4, id, 77))
        .find(|entry| authority_entry_hash(entry).unwrap() < first_hash)
        .expect("at least one distinct confirmation hashes below the first");
    let replacement_hash = authority_entry_hash(&replacement).unwrap();
    entries.push(replacement);
    let after = fold_authority_log_without_seen_time_delay(&entries);
    assert!(after.valid_entries.contains(&replacement_hash));
    assert!(!after.valid_entries.contains(&first_hash));
    assert!(!after.valid_entries.contains(&enroll_hash));
    assert!(!after.valid_entries.contains(&revoke_hash));
    assert_eq!(
        after.roster.get(&signer_key),
        None,
        "invalid enrollment must not survive"
    );
    assert!(
        after
            .issues
            .contains(&AuthorityFoldIssue::InvalidAncestry(revoke_hash))
    );
    assert_eq!(
        folded_status(&after, &owner_key),
        Some(ActorBindingStatus::Revoked)
    );
    assert!(!actor_binding_is_active(&after, &actor, "human"));
    let mut bad_entries = entries.clone();
    bad_entries[4].cosigns[0].signature[0] ^= 1;
    let bad = fold_authority_log_without_seen_time_delay(&bad_entries);
    assert_eq!(
        folded_status(&bad, &owner_key),
        Some(ActorBindingStatus::Active)
    );
    entries.reverse();
    assert_eq!(fold_authority_log_without_seen_time_delay(&entries), after);
}
