//! Signer assurance is constrained by causal and concurrent vault floors.
use super::support::*;
use super::*;

#[test]
fn hardware_floor_rejects_software_signer_under_every_arrival_order() {
    let hardware = p256_key(90);
    let software = ed_key(91);
    let hardware_key = authority_key_from_p256(&hardware);
    let software_key = authority_key_from_ed(&software);
    let genesis = sign_p256(
        unsigned_entry(
            None,
            0,
            vec![],
            AuthorityOp::Genesis {
                device: device(
                    hardware_key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Hardware,
                ),
                genesis_nonce: [90; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
                recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            },
            hardware_key.clone(),
            1,
        ),
        &hardware,
    );
    let vault = genesis_vault_id(&genesis).unwrap();
    let enroll = sign_p256(
        unsigned_entry(
            Some(vault),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(software_key.clone(), ROLE_AGENT, AuthorityTier::Software),
            },
            hardware_key.clone(),
            2,
        ),
        &hardware,
    );
    let signed = |op, seq, software_signer| {
        let (signer, cosigner) = if software_signer {
            (software_key.clone(), hardware_key.clone())
        } else {
            (hardware_key.clone(), software_key.clone())
        };
        let mut entry = unsigned_entry(
            Some(vault),
            seq,
            vec![authority_entry_hash(&enroll).unwrap()],
            op,
            signer,
            3,
        );
        entry.cosigns.push(AuthoritySignature {
            suite: cosigner.suite(),
            public_key: cosigner,
            signature: vec![0; 64],
        });
        let transcript = authority_transcript(&entry).unwrap();
        let mut hs: P256Signature = hardware.sign(&transcript);
        if let Some(normalized) = hs.normalize_s() {
            hs = normalized;
        }
        let ss = software.sign(&transcript).to_bytes().to_vec();
        if software_signer {
            entry.signer.signature = ss;
            entry.cosigns[0].signature = hs.to_bytes().to_vec();
        } else {
            entry.signer.signature = hs.to_bytes().to_vec();
            entry.cosigns[0].signature = ss;
        }
        entry
    };
    let floor = signed(
        AuthorityOp::SetTierFloor {
            tier_floor: AuthorityTier::Hardware,
        },
        2,
        false,
    );
    let action = |id| {
        AuthorityOp::FederationConfirm(AuthorityConfirmAction {
            kind: AuthorityConfirmKind::Accept,
            confirm_id: [id; 32],
            peer_vault_id: [8; 32],
            epoch: 1,
            nonce: [id; 16],
        })
    };
    let weak = signed(action(1), 1, true);
    let strong = signed(action(2), 3, false);
    let mut entries = vec![genesis, enroll, floor.clone(), weak.clone(), strong.clone()];
    let expected = fold_legacy_authority_log(&entries);
    // At the Software floor in its own ancestry the software cosigner still
    // makes quorum for the floor raise. A row concurrent with the raise is
    // judged under it, its cosigners too (H71 residual, W2-T8): neither the
    // software signer's row nor the hardware signer's row, whose second
    // participant is the software key, stands.
    assert!(
        expected
            .valid_entries
            .contains(&authority_entry_hash(&floor).unwrap())
    );
    assert!(
        !expected
            .valid_entries
            .contains(&authority_entry_hash(&weak).unwrap())
    );
    assert!(
        !expected
            .valid_entries
            .contains(&authority_entry_hash(&strong).unwrap())
    );
    assert!(expected.issues.contains(&AuthorityFoldIssue::MissingQuorum(
        authority_entry_hash(&strong).unwrap()
    )));
    assert_eq!(expected.tier_floor, Some(AuthorityTier::Hardware));
    entries.reverse();
    assert_eq!(expected, fold_legacy_authority_log(&entries));
}

/// H71 residual (W2-T8): under a Hardware floor a software cosigner is no
/// quorum participant. Two hardware participants still meet quorum.
#[test]
fn hardware_floor_counts_no_software_cosigner_toward_quorum() {
    let owner = p256_key(92);
    let second = p256_key(93);
    let software = ed_key(94);
    let owner_key = authority_key_from_p256(&owner);
    let second_key = authority_key_from_p256(&second);
    let software_key = authority_key_from_ed(&software);
    let p256_sig = |key: &P256SigningKey, transcript: &[u8]| {
        let mut signature: P256Signature = key.sign(transcript);
        if let Some(normalized) = signature.normalize_s() {
            signature = normalized;
        }
        signature.to_bytes().to_vec()
    };
    let genesis = sign_p256(
        unsigned_entry(
            None,
            0,
            vec![],
            AuthorityOp::Genesis {
                device: device(
                    owner_key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Hardware,
                ),
                genesis_nonce: [92; 32],
                tier_floor: AuthorityTier::Hardware,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
                recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            },
            owner_key.clone(),
            1,
        ),
        &owner,
    );
    let vault = genesis_vault_id(&genesis).unwrap();
    let enroll_second = sign_p256(
        unsigned_entry(
            Some(vault),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(second_key.clone(), ROLE_AGENT, AuthorityTier::Hardware),
            },
            owner_key.clone(),
            2,
        ),
        &owner,
    );
    // Two active participants from here on: every quorum op needs a cosigner.
    let cosigned = |parent: &AuthorityLogEntry, seq, op, software_cosigner: bool| {
        let cosigner = if software_cosigner {
            software_key.clone()
        } else {
            second_key.clone()
        };
        let mut entry = unsigned_entry(
            Some(vault),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            op,
            owner_key.clone(),
            3,
        );
        entry.cosigns.push(AuthoritySignature {
            suite: cosigner.suite(),
            public_key: cosigner,
            signature: vec![0; 64],
        });
        let transcript = authority_transcript(&entry).unwrap();
        entry.signer.signature = p256_sig(&owner, &transcript);
        entry.cosigns[0].signature = if software_cosigner {
            software.sign(&transcript).to_bytes().to_vec()
        } else {
            p256_sig(&second, &transcript)
        };
        entry
    };
    let enroll_software = cosigned(
        &enroll_second,
        2,
        AuthorityOp::EnrollDevice {
            device: device(software_key.clone(), ROLE_AGENT, AuthorityTier::Software),
        },
        false,
    );
    let confirm = |id| {
        AuthorityOp::FederationConfirm(AuthorityConfirmAction {
            kind: AuthorityConfirmKind::Accept,
            confirm_id: [id; 32],
            peer_vault_id: [8; 32],
            epoch: 1,
            nonce: [id; 16],
        })
    };
    let software_quorum = cosigned(&enroll_software, 3, confirm(1), true);
    let hardware_quorum = cosigned(&enroll_software, 4, confirm(2), false);
    let entries = vec![
        genesis,
        enroll_second,
        enroll_software.clone(),
        software_quorum.clone(),
        hardware_quorum.clone(),
    ];
    let fold = fold_authority_log(&entries);
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&enroll_software).unwrap())
    );
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&software_quorum).unwrap()),
        "a software cosigner must not meet quorum under a Hardware floor"
    );
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&hardware_quorum).unwrap())
    );
}

/// H411 (F18): a software owner key the vault has since outranked keeps its
/// old signatures. Its `RevokeActor` on a branch from before the hardware
/// floor is refused by the fold (below a concurrent floor), yet the
/// independent revoke proof used to project it anyway, at the epoch the key
/// chose, and so killed the hardware owner's binding for good.
#[test]
fn an_outranked_key_cannot_revoke_from_a_branch_below_the_floor() {
    let software = ed_key(92);
    let hardware = p256_key(93);
    let second = p256_key(94);
    let software_key = authority_key_from_ed(&software);
    let hardware_key = authority_key_from_p256(&hardware);
    let second_key = authority_key_from_p256(&second);
    let p256_sig = |key: &P256SigningKey, transcript: &[u8]| {
        let mut signature: P256Signature = key.sign(transcript);
        if let Some(normalized) = signature.normalize_s() {
            signature = normalized;
        }
        signature.to_bytes().to_vec()
    };
    let genesis = genesis_entry(92, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault = genesis_vault_id(&genesis).unwrap();
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let enroll = sign_ed(
        unsigned_entry(
            Some(vault),
            1,
            vec![genesis_hash],
            AuthorityOp::EnrollDevice {
                device: device(
                    hardware_key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Hardware,
                ),
            },
            software_key.clone(),
            2,
        ),
        &software,
    );
    // A roster of two keys or more needs two participants: a hardware signer
    // and one cosigner.
    // `None` cosigns with the software key.
    let cosigned = |parent: &AuthorityLogEntry,
                    signer: &P256SigningKey,
                    seq,
                    op,
                    ts,
                    cosigner: Option<&P256SigningKey>| {
        let mut entry = unsigned_entry(
            Some(vault),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            op,
            authority_key_from_p256(signer),
            ts,
        );
        let cosigner_key = cosigner.map_or_else(|| software_key.clone(), authority_key_from_p256);
        entry.cosigns.push(AuthoritySignature {
            suite: cosigner_key.suite(),
            public_key: cosigner_key,
            signature: vec![0; 64],
        });
        let transcript = authority_transcript(&entry).unwrap();
        entry.signer.signature = p256_sig(signer, &transcript);
        entry.cosigns[0].signature = match cosigner {
            Some(key) => p256_sig(key, &transcript),
            None => software.sign(&transcript).to_bytes().to_vec(),
        };
        entry
    };
    let enroll_second = cosigned(
        &enroll,
        &hardware,
        1,
        AuthorityOp::EnrollDevice {
            device: device(
                second_key.clone(),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Hardware,
            ),
        },
        3,
        None,
    );
    let bind = cosigned(
        &enroll_second,
        &hardware,
        2,
        bind_op(&hardware_key, scope_entity(0x93), "human", 1),
        4,
        None,
    );
    let floor = cosigned(
        &bind,
        &hardware,
        3,
        AuthorityOp::SetTierFloor {
            tier_floor: AuthorityTier::Hardware,
        },
        5,
        None,
    );
    // The outranked key alone, on the branch from before the hardware owner.
    let stale_revoke = sign_ed(
        unsigned_entry(
            Some(vault),
            2,
            vec![genesis_hash],
            revoke_actor_op(&hardware_key, u64::MAX),
            software_key.clone(),
            6,
        ),
        &software,
    );
    let mut entries = vec![
        genesis,
        enroll,
        enroll_second,
        bind,
        floor.clone(),
        stale_revoke.clone(),
    ];

    let fold = fold_legacy_authority_log(&entries);
    assert_eq!(fold.tier_floor, Some(AuthorityTier::Hardware));
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&stale_revoke).unwrap()),
        "the fold refuses the below-floor revoke"
    );
    assert_eq!(
        folded_status(&fold, &hardware_key),
        Some(ActorBindingStatus::Active),
        "a revoke the fold refused must not land through the revoke proof"
    );
    entries.reverse();
    assert_eq!(fold, fold_legacy_authority_log(&entries));

    // Positive control: a revoke the live floor admits still lands.
    let live_revoke = cosigned(
        &floor,
        &hardware,
        4,
        revoke_actor_op(&hardware_key, 1),
        7,
        Some(&second),
    );
    entries.push(live_revoke.clone());
    let fold = fold_legacy_authority_log(&entries);
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&live_revoke).unwrap())
    );
    assert_eq!(
        folded_status(&fold, &hardware_key),
        Some(ActorBindingStatus::Revoked)
    );
}
