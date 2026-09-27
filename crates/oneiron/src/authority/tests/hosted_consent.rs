//! Managed host-root consent is explicit, never inferred in self-host mode.
use super::support::*;
use super::*;

#[test]
fn managed_host_genesis_passes_consent_and_self_host_refuses_it() {
    let signing = ed_key(81);
    let key = authority_key_from_ed(&signing);
    let genesis = sign_ed(
        unsigned_entry(
            None,
            0,
            vec![],
            AuthorityOp::Genesis {
                device: device(
                    key.clone(),
                    ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                    AuthorityTier::CloudCustodial,
                ),
                genesis_nonce: [82; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
                recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            },
            key.clone(),
            1,
        ),
        &signing,
    );
    let bind = sign_ed(
        unsigned_entry(
            Some(genesis_vault_id(&genesis).unwrap()),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            bind_op(&key, scope_entity(1), "human", 1),
            key.clone(),
            2,
        ),
        &signing,
    );
    let confirm = sign_ed(
        unsigned_entry(
            Some(genesis_vault_id(&genesis).unwrap()),
            2,
            vec![authority_entry_hash(&bind).unwrap()],
            AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
                schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
                confirm_id: [1; 32],
                gate_decision_id: [2; 16],
                claim_id: scope_entity(3),
                effect_digest: [4; 32],
                read_frontier_hash: [5; 32],
                nonce: [6; 16],
                expires_at: 99,
                disposition: CriticalWriteConfirmDisposition::Clear,
                method: CriticalWriteConfirmMethod::TokenReauth,
            }),
            key.clone(),
            3,
        ),
        &signing,
    );
    let entries = vec![genesis, bind, confirm];
    let managed = fold_authority_log_for_posture(
        &entries,
        &BTreeMap::new(),
        10,
        &BTreeMap::new(),
        crate::HostingPrivacyPosture::Hosted,
    );
    assert_eq!(managed.valid_entries.len(), 3);
    assert_eq!(managed.critical_write_confirms.len(), 1);
    assert_eq!(
        managed.actor_bindings[&key].status,
        ActorBindingStatus::Active
    );
    for posture in [
        crate::HostingPrivacyPosture::Relay,
        crate::HostingPrivacyPosture::SelfHostLocal,
    ] {
        let fold = fold_authority_log_for_posture(
            &entries,
            &BTreeMap::new(),
            10,
            &BTreeMap::new(),
            posture,
        );
        assert!(fold.roster.is_empty());
    }
}

#[test]
fn cached_snapshot_rechecks_posture_for_host_root() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let signer = ed_key(244);
    let key = authority_key_from_ed(&signer);
    let genesis = sign_ed(
        unsigned_entry(
            None,
            0,
            vec![],
            AuthorityOp::Genesis {
                device: device(
                    key.clone(),
                    ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                    AuthorityTier::CloudCustodial,
                ),
                genesis_nonce: [244; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
                recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            },
            key.clone(),
            1,
        ),
        &signer,
    );
    vault
        .put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let local = crate::authority::authority_fold_readonly_for_store_in_txn(
        &vault.store,
        crate::HostingPrivacyPosture::SelfHostLocal,
        &txn,
    )
    .unwrap();
    let hosted = crate::authority::authority_fold_readonly_for_store_in_txn(
        &vault.store,
        crate::HostingPrivacyPosture::Hosted,
        &txn,
    )
    .unwrap();
    assert!(local.roster.is_empty());
    assert!(hosted.roster.contains_key(&key));
    assert!(
        crate::authority::authority_fold_readonly_for_store_in_txn(
            &vault.store,
            crate::HostingPrivacyPosture::SelfHostLocal,
            &txn,
        )
        .unwrap()
        .roster
        .is_empty()
    );
}

#[test]
fn managed_root_accepts_logged_slips_but_never_device_key_widens() {
    let issuer = HostSlipIssuer::from_secret(b"hosted test signing root").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = crate::VaultConfig::default();
    config.privacy = crate::config::VaultPrivacyConfig {
        posture: crate::HostingPrivacyPosture::Hosted,
        data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
            key_ref: "hosted-test".into(),
        },
    };
    let vault = crate::Vault::open(dir.path(), config).unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let root_fold = vault.authority_fold().unwrap();
    assert!(root_fold.slip_is_live(&root.claims.slip_id));
    let root_mint_hash = root_fold.slips.mints[&root.claims.slip_id].entry_hash;
    let mint = vault
        .get_authority_log_entry(&authority_log_entity_id_from_hash(&root_mint_hash).unwrap())
        .unwrap()
        .unwrap();
    let genesis = vault
        .get_authority_log_entry(
            &authority_log_entity_id_from_hash(&mint.parent_hashes[0]).unwrap(),
        )
        .unwrap()
        .unwrap();
    let next_key = AuthorityKey::Ed25519(ed_key(67).verifying_key().to_bytes());
    for tier in [AuthorityTier::Software, AuthorityTier::Hardware] {
        let mut candidate = device(next_key.clone(), ROLE_OWNER | ROLE_ADMIN, tier);
        candidate.attestation.kind = "HostRoot".into();
        for op in [
            AuthorityOp::EnrollDevice {
                device: candidate.clone(),
            },
            AuthorityOp::RotateKey {
                old_key: issuer.public_key(),
                new_device: candidate,
            },
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Software,
            },
        ] {
            let attempt = issuer
                .sign_entry(
                    Some(root.claims.vault_id),
                    2,
                    vec![root_mint_hash],
                    op,
                    root.claims.issued_at,
                )
                .unwrap();
            let hash = authority_entry_hash(&attempt).unwrap();
            let observed = BTreeMap::from([(hash, 1)]);
            let fold = fold_authority_log_for_posture(
                &[genesis.clone(), mint.clone(), attempt],
                &observed,
                1 + DEFAULT_PENDING_WIDEN_DELAY_SECS,
                &BTreeMap::new(),
                crate::HostingPrivacyPosture::Hosted,
            );
            assert!(!fold.valid_entries.contains(&hash));
            assert!(!fold.roster.contains_key(&next_key));
            assert!(fold.roster.contains_key(&issuer.public_key()));
            assert!(fold.slip_is_live(&root.claims.slip_id));
        }
    }
}
