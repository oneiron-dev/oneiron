use super::*;
use crate::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, DEFAULT_PENDING_WIDEN_DELAY_SECS,
    DeviceAuthority, ROLE_ADMIN, ROLE_OWNER, authority_entry_hash, authority_transcript,
    genesis_vault_id,
};
use ed25519_dalek::{Signer, SigningKey};

/// Real signed genesis + binding, and the next signed revocation for precise
/// transaction ordering. Shared only with the roster regression tests.
pub(crate) fn root_owner(vault: &Vault, owner: WriteActor, seed: u8) -> Result<AuthorityLogEntry> {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let sign = |mut entry: AuthorityLogEntry| -> Result<AuthorityLogEntry> {
        entry.signer.signature = signing
            .sign(&authority_transcript(&entry)?)
            .to_bytes()
            .to_vec();
        Ok(entry)
    };
    let genesis = sign(AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed; 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    })?;
    let bind = sign(AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(genesis_vault_id(&genesis)?),
        seq: 1,
        parent_hashes: vec![authority_entry_hash(&genesis)?],
        op: AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: owner.entity_ref(),
            actor_class: owner.actor_class().gate_actor_class().to_owned(),
            epoch: 1,
        },
        signer: genesis.signer.clone(),
        cosigns: Vec::new(),
        ts: 101,
    })?;
    let revoke = sign(AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: bind.vault_id,
        seq: 2,
        parent_hashes: vec![authority_entry_hash(&bind)?],
        op: AuthorityOp::RevokeActor {
            authority_key: key,
            epoch: 1,
        },
        signer: bind.signer.clone(),
        cosigns: Vec::new(),
        ts: 102,
    })?;
    vault.put_authority_log_entries(&[
        (
            genesis,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        ),
        (
            bind,
            TimeRange {
                start: 101,
                end: 101,
            },
            101,
        ),
    ])?;
    Ok(revoke)
}

#[test]
fn unauthorized_reanchor_preserves_the_active_head_and_history() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x71), ENTITY_TYPE_AGENT_DEF);
    let first = seed(&vault, entity(0x72), ENTITY_TYPE_PERSON);
    let other = seed(&vault, entity(0x73), ENTITY_TYPE_ORG);
    let stranger = seed(&vault, entity(0x74), ENTITY_TYPE_PERSON);
    let machine = seed(&vault, entity(0x75), crate::registry::ENTITY_TYPE_MACHINE);
    let claim = anchor_actor_subject(&vault, actor, first, writer(), 100)?;
    let before = vault.get_claim(&claim)?;
    let count = vault.claims_for_subject(&actor)?.len();
    for untrusted in [
        WriteActor::new(stranger, EdgeActorClass::Human),
        WriteActor::new(machine, EdgeActorClass::System),
        WriteActor::new(actor, EdgeActorClass::Agent),
        WriteActor::new(writer().entity_ref(), EdgeActorClass::System),
        WriteActor::new(actor, EdgeActorClass::Human),
        WriteActor::new(entity(0x76), EdgeActorClass::Human),
    ] {
        assert!(anchor_actor_subject(&vault, actor, other, untrusted, 101).is_err());
        assert_eq!(actor_subject_anchor(&vault, &actor, 103)?, Some(first));
        assert_eq!(vault.get_claim(&claim)?, before);
        assert_eq!(vault.claims_for_subject(&actor)?.len(), count);
    }
    // The same valid re-anchor still works for the bound human owner.
    anchor_actor_subject(&vault, actor, other, writer(), 102)?;
    assert_eq!(actor_subject_anchor(&vault, &actor, 103)?, Some(other));
    assert_ne!(vault.get_claim(&claim)?, before);
    Ok(())
}

#[test]
fn unauthorized_initial_anchor_and_non_actor_targets_are_rejected() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x77), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&vault, entity(0x78), ENTITY_TYPE_PERSON);
    let outsider = WriteActor::new(person, EdgeActorClass::Human);
    assert!(anchor_actor_subject(&vault, actor, person, outsider, 100).is_err());
    assert!(vault.claims_for_subject(&actor)?.is_empty());
    for kind in [ENTITY_TYPE_PLACE, ENTITY_TYPE_FACET, ENTITY_TYPE_ORG] {
        let target = seed(&vault, EntityId::now(), kind);
        let err = anchor_actor_subject(&vault, target, person, writer(), 100)
            .expect_err("only authority-bearing entities can act");
        assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
        assert!(vault.claims_for_subject(&target)?.is_empty());
    }
    Ok(())
}

#[test]
fn public_reanchor_observes_revocation_committed_after_preflight() -> Result<()> {
    // Do not use test_vault: this test owns the exact signed revocation.
    let (dir, vault) = unrooted_test_vault();
    seed(&vault, writer().entity_ref(), ENTITY_TYPE_PERSON);
    let revoke = root_owner(&vault, writer(), 0xE2)?;
    let actor = seed(&vault, entity(0x79), ENTITY_TYPE_AGENT_DEF);
    let first = seed(&vault, entity(0x7A), ENTITY_TYPE_PERSON);
    let other = seed(&vault, entity(0x7B), ENTITY_TYPE_PERSON);
    let claim = anchor_actor_subject(&vault, actor, first, writer(), 100)?;
    let before = vault.get_claim(&claim)?;
    let mut revocation_txn = vault.store.env.write_txn()?;
    vault.put_authority_log_entries_in_txn(
        &mut revocation_txn,
        &[(
            revoke,
            TimeRange {
                start: 102,
                end: 102,
            },
            102,
        )],
    )?;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let result = std::thread::scope(|scope| -> Result<EntityId> {
        let worker = scope.spawn(|| -> Result<EntityId> {
            let txn = vault.store.env.read_txn()?;
            vault.verify_owner_write_actor_in_txn(&txn, &writer())?;
            drop(txn);
            ready_tx.send(()).expect("notify preflight");
            // This write cannot acquire LMDB's lock until revocation commits.
            anchor_actor_subject(&vault, actor, other, writer(), 103)
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("preflight completed");
        revocation_txn.commit()?;
        worker.join().expect("anchor worker")
    });
    assert_eq!(
        result.expect_err("revoked owner").kind(),
        ErrorKind::ActorLacksClaimAuthority
    );
    assert_eq!(vault.get_claim(&claim)?, before);
    assert_eq!(actor_subject_anchor(&vault, &actor, 103)?, Some(first));
    assert_eq!(vault.claims_for_subject(&actor)?.len(), 1);
    drop(vault);
    drop(dir);
    Ok(())
}

#[test]
fn unrooted_anchor_uses_canonical_human_owner_semantics() -> Result<()> {
    let (_dir, vault) = unrooted_test_vault();
    seed(&vault, writer().entity_ref(), ENTITY_TYPE_PERSON);
    let actor = seed(&vault, entity(0x7C), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&vault, entity(0x7D), ENTITY_TYPE_PERSON);
    let machine = seed(&vault, entity(0x7E), crate::registry::ENTITY_TYPE_MACHINE);
    let err = anchor_actor_subject(
        &vault,
        actor,
        person,
        WriteActor::new(machine, EdgeActorClass::System),
        100,
    )
    .expect_err("System is not an owner capability");
    assert_eq!(err.kind(), ErrorKind::ActorLacksClaimAuthority);
    anchor_actor_subject(&vault, actor, person, writer(), 101)?;
    assert_eq!(actor_subject_anchor(&vault, &actor, 103)?, Some(person));
    Ok(())
}
