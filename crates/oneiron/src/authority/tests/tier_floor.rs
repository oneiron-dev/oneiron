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
    let mut entries = vec![genesis, enroll, floor, weak.clone(), strong.clone()];
    let expected = fold_legacy_authority_log(&entries);
    assert!(
        !expected
            .valid_entries
            .contains(&authority_entry_hash(&weak).unwrap())
    );
    assert!(
        expected
            .valid_entries
            .contains(&authority_entry_hash(&strong).unwrap())
    );
    assert_eq!(expected.tier_floor, Some(AuthorityTier::Hardware));
    entries.reverse();
    assert_eq!(expected, fold_legacy_authority_log(&entries));
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
    let software_key = authority_key_from_ed(&software);
    let hardware_key = authority_key_from_p256(&hardware);
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
    // The hardware owner signs and the software owner cosigns: a two-key
    // roster needs both.
    let by_hardware = |parent: &AuthorityLogEntry, seq, op, ts| {
        let mut entry = unsigned_entry(
            Some(vault),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            op,
            hardware_key.clone(),
            ts,
        );
        entry.cosigns.push(AuthoritySignature {
            suite: software_key.suite(),
            public_key: software_key.clone(),
            signature: vec![0; 64],
        });
        let transcript = authority_transcript(&entry).unwrap();
        let mut signature: P256Signature = hardware.sign(&transcript);
        if let Some(normalized) = signature.normalize_s() {
            signature = normalized;
        }
        entry.signer.signature = signature.to_bytes().to_vec();
        entry.cosigns[0].signature = software.sign(&transcript).to_bytes().to_vec();
        entry
    };
    let bind = by_hardware(
        &enroll,
        1,
        bind_op(&hardware_key, scope_entity(0x93), "human", 1),
        3,
    );
    let floor = by_hardware(
        &bind,
        2,
        AuthorityOp::SetTierFloor {
            tier_floor: AuthorityTier::Hardware,
        },
        4,
    );
    // The outranked key alone, on the branch from before the hardware owner.
    let stale_revoke = sign_ed(
        unsigned_entry(
            Some(vault),
            2,
            vec![genesis_hash],
            revoke_actor_op(&hardware_key, u64::MAX),
            software_key.clone(),
            5,
        ),
        &software,
    );
    let mut entries = vec![genesis, enroll, bind, floor.clone(), stale_revoke.clone()];

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
    let live_revoke = by_hardware(&floor, 3, revoke_actor_op(&hardware_key, 1), 6);
    entries.push(live_revoke);
    assert_eq!(
        folded_status(&fold_legacy_authority_log(&entries), &hardware_key),
        Some(ActorBindingStatus::Revoked)
    );
}
