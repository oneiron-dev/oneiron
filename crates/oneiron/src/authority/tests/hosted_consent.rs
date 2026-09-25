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
