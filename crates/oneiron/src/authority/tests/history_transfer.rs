//! Full signed-history portability, account auth and independent recovery composition.
use super::support::*;
use super::*;
use crate::{TimeRange, Vault, VaultConfig};

fn store(vault: &Vault, entry: &AuthorityLogEntry) {
    vault
        .put_authority_log_entry(entry, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
}

#[test]
fn signed_history_export_import_re_root_preserves_identity_and_bytes() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let a = Vault::open(a.path(), VaultConfig::default()).unwrap();
    let b = Vault::open(b.path(), VaultConfig::default()).unwrap();
    let c = Vault::open(c.path(), VaultConfig::default()).unwrap();
    let old = ed_key(110);
    let new = ed_key(111);
    let genesis = genesis_entry(110, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    store(&a, &genesis);
    let export = a.export_signed_authority_history().unwrap();
    b.import_signed_authority_history(&export).unwrap();
    assert_eq!(b.export_signed_authority_history().unwrap(), export);
    let reroot = b
        .re_root_authority(
            device(
                authority_key_from_ed(&new),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
            authority_key_from_ed(&old),
            |bytes| Ok(old.sign(bytes).to_bytes().to_vec()),
        )
        .unwrap();
    let fold = b.authority_fold().unwrap();
    assert_eq!(fold.vault_id, a.authority_fold().unwrap().vault_id);
    assert!(fold.roster[&authority_key_from_ed(&old)].revoked);
    assert!(!fold.roster[&authority_key_from_ed(&new)].revoked);
    let moved = b.export_signed_authority_history().unwrap();
    assert_eq!(moved[0], export[0]);
    c.import_signed_authority_history(&moved).unwrap();
    assert_eq!(c.authority_fold().unwrap().roster, fold.roster);
    assert_eq!(moved[1], encode_authority_log_entry_body(&reroot).unwrap());
    let mut corrupt = export;
    let last = corrupt[0].len() - 1;
    corrupt[0][last] ^= 1;
    assert!(c.import_signed_authority_history(&corrupt).is_err());
    assert_eq!(c.export_signed_authority_history().unwrap(), moved);
    let other =
        encode_authority_log_entry_body(&genesis_entry(112, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1))
            .unwrap();
    assert!(c.import_signed_authority_history(&[other]).is_err());
    assert_eq!(c.export_signed_authority_history().unwrap(), moved);
}

#[test]
fn two_vaults_recover_with_independent_genesis_and_signatures() {
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let vaults = dirs
        .iter()
        .map(|dir| Vault::open(dir.path(), VaultConfig::default()).unwrap())
        .collect::<Vec<_>>();
    let mut requests = Vec::new();
    let mut roots = Vec::new();
    for (i, vault) in vaults.iter().enumerate() {
        let seed = 120 + i as u8;
        let signer = ed_key(seed);
        let genesis = genesis_entry(seed, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        store(vault, &genesis);
        let root = genesis_vault_id(&genesis).unwrap();
        roots.push(root);
        let entry = sign_ed(
            unsigned_entry(
                Some(root),
                1,
                vec![authority_entry_hash(&genesis).unwrap()],
                AuthorityOp::ReRoot {
                    new_device: device(
                        authority_key_from_ed(&ed_key(seed + 10)),
                        ROLE_OWNER | ROLE_ADMIN,
                        AuthorityTier::Software,
                    ),
                },
                authority_key_from_ed(&signer),
                2,
            ),
            &signer,
        );
        requests.push(VaultRecoveryRequest { vault, entry });
    }
    assert_ne!(roots[0], roots[1]);
    assert_ne!(
        requests[0].entry.signer.public_key,
        requests[1].entry.signer.public_key
    );
    let outcomes = recover_vaults_independently(&requests);
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.iter().all(Result::is_ok));
    for (i, vault) in vaults.iter().enumerate() {
        assert_eq!(vault.authority_fold().unwrap().vault_id, Some(roots[i]));
    }
}

#[test]
fn account_auth_migrates_managed_root_without_widening() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::default();
    config.privacy = crate::config::VaultPrivacyConfig {
        posture: crate::HostingPrivacyPosture::Hosted,
        data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
            key_ref: "account-host-key".into(),
        },
    };
    let vault = Vault::open(dir.path(), config).unwrap();
    let actor = scope_entity(19);
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &[0x80],
        )
        .unwrap();
    let old = ed_key(140);
    let new = ed_key(141);
    let key = authority_key_from_ed(&old);
    let mut genesis = genesis_entry(140, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    if let AuthorityOp::Genesis { device, .. } = &mut genesis.op {
        device.roles |= ROLE_CLOUD;
        device.tier = AuthorityTier::CloudCustodial;
    }
    genesis = sign_ed(genesis, &old);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&vault, &genesis);
    let bind = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            bind_op(&key, actor, "human", 1),
            key.clone(),
            2,
        ),
        &old,
    );
    store(&vault, &bind);
    assert!(
        vault
            .authenticate_owner(
                actor,
                &actor.to_hex(),
                false,
                crate::store::GateDecisionId::now()
            )
            .is_err()
    );
    let owner = vault
        .authenticate_owner(
            actor,
            &actor.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    vault
        .recover_cloud_account(
            &owner,
            device(
                authority_key_from_ed(&new),
                ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                AuthorityTier::CloudCustodial,
            ),
            key.clone(),
            |bytes| Ok(old.sign(bytes).to_bytes().to_vec()),
        )
        .unwrap();
    let fold = vault.authority_fold().unwrap();
    assert_eq!(fold.vault_id, Some(id));
    assert!(fold.roster[&key].revoked);
    assert!(!fold.roster[&authority_key_from_ed(&new)].revoked);
    assert!(fold.pending_widens.is_empty());
}
