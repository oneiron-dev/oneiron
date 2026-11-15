use super::*;
use crate::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, DeviceAuthority, HostSlipIssuer, ROLE_ADMIN,
    ROLE_OWNER, authority_entry_hash, authority_transcript, genesis_vault_id,
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
            recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
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

/// The signed regrant of `owner`'s binding after [`root_owner`]'s `revoke`:
/// the same key binds it again at the next epoch.
pub(crate) fn regrant_after(
    revoke: &AuthorityLogEntry,
    owner: WriteActor,
    seed: u8,
) -> Result<AuthorityLogEntry> {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let mut regrant = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: revoke.vault_id,
        seq: 3,
        parent_hashes: vec![authority_entry_hash(revoke)?],
        op: AuthorityOp::BindActor {
            authority_key: AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
            actor_ref: owner.entity_ref(),
            actor_class: owner.actor_class().gate_actor_class().to_owned(),
            epoch: 2,
        },
        signer: revoke.signer.clone(),
        cosigns: Vec::new(),
        ts: 103,
    };
    regrant.signer.signature = signing
        .sign(&authority_transcript(&regrant)?)
        .to_bytes()
        .to_vec();
    Ok(regrant)
}

/// `op` signed by the [`root_owner`] key `seed`, as entry `seq` after
/// `parent` in the vault `vault_id`, cosigned by each enrolled device key in
/// `cosigners` (a roster of two keys or more needs a peer cosign).
pub(crate) fn sign_child(
    vault_id: Option<crate::authority::AuthorityVaultId>,
    parent: crate::authority::AuthorityEntryHash,
    seq: u64,
    op: AuthorityOp,
    seed: u8,
    cosigners: &[u8],
) -> Result<AuthorityLogEntry> {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let cosigning: Vec<SigningKey> = cosigners
        .iter()
        .map(|cosigner| SigningKey::from_bytes(&[*cosigner; 32]))
        .collect();
    let mut cosigns: Vec<AuthoritySignature> = cosigning
        .iter()
        .map(|cosigner| {
            let key = AuthorityKey::Ed25519(cosigner.verifying_key().to_bytes());
            AuthoritySignature {
                suite: key.suite(),
                public_key: key,
                signature: vec![0; 64],
            }
        })
        .collect();
    cosigns.sort_by(|left, right| left.public_key.cmp(&right.public_key));
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: vec![parent],
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: Vec::new(),
        },
        cosigns,
        ts: 100 + seq,
    };
    let transcript = authority_transcript(&entry)?;
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    for cosign in &mut entry.cosigns {
        let cosigner = cosigning
            .iter()
            .find(|cosigner| {
                AuthorityKey::Ed25519(cosigner.verifying_key().to_bytes()) == cosign.public_key
            })
            .expect("each cosign has its key");
        cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    Ok(entry)
}

/// The host secret the signed-birth fixture `seed` names. Each seed is its
/// own host identity, so births under different seeds never share a root.
fn host_secret_for_seed(seed: u8) -> Vec<u8> {
    format!("signed-birth-test-host-{seed:02x}").into_bytes()
}

/// The host issuer that roots (or rooted) a vault for the signed-birth
/// fixture `seed`: rebuilt from the seed's secret, as the same secret
/// rebuilds the same issuer.
pub(crate) fn host_issuer_for_seed(seed: u8) -> Result<HostSlipIssuer> {
    HostSlipIssuer::from_secret(&host_secret_for_seed(seed))
}

/// The authority-log signing key of [`host_issuer_for_seed`]: the same
/// `oneiron/host-authority-signing/v2` derivation the issuer holds, so the
/// depth birth and edits the fixture signs verify under the host key the
/// fold binds to the owner.
pub(crate) fn host_signing_for_seed(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&blake3::derive_key(
        "oneiron/host-authority-signing/v2",
        &host_secret_for_seed(seed),
    ))
}

/// Roots `vault` under the host `seed` names and returns the writer the
/// signed-birth tests birth and edit as: the vault's embedded owner, the
/// only live owner of a personal vault, which the root binds as `human` in
/// the same transaction. No rebind follows: the host key holds one live
/// binding, and a fresh person is no vault owner, so the owner stays bound.
pub(crate) fn root_host_owner(vault: &Vault, seed: u8) -> Result<WriteActor> {
    let issuer = host_issuer_for_seed(seed)?;
    vault.ensure_host_root_slip(&issuer)?;
    host_owner_writer(vault)
}

/// The writer [`root_host_owner`] returns, for a replica that takes the
/// origin's authority history by import instead of rooting itself: the
/// embedded owner staged locally, bound by the imported host genesis.
pub(crate) fn host_owner_writer(vault: &Vault) -> Result<WriteActor> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|_| crate::Error::InvariantViolation("embedded owner"))?;
    Ok(WriteActor::new(owner, crate::edge::EdgeActorClass::Human))
}

/// A person-authorized project-depth edit signed with the host key
/// [`host_signing_for_seed`] derives, for the owner [`root_host_owner`]
/// bound: what `set_project_depth_signed_for_test` is under a host root.
pub(crate) fn set_project_depth_with_host(
    vault: &Vault,
    id: EntityId,
    depth: u64,
    writer: &WriteActor,
    now: u64,
    seed: u8,
) -> Result<()> {
    let signing = host_signing_for_seed(seed);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    vault.set_project_depth(id, depth, writer, now, key, |message| {
        Ok(signing.sign(message).to_bytes().to_vec())
    })
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
        ErrorKind::WriteConcurrentWithRevocation
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
    // With no authority root the owner is the vault's embedded owner alone
    // (H149): another Human PERSON is no owner capability either.
    let err = anchor_actor_subject(&vault, actor, person, writer(), 101)
        .expect_err("a PERSON who is not the vault's owner");
    assert_eq!(err.kind(), ErrorKind::ActorLacksClaimAuthority);
    let owner = WriteActor::new(
        vault
            .ensure_embedded_owner_actor()
            .map_err(|_| crate::Error::InvariantViolation("embedded owner"))?,
        EdgeActorClass::Human,
    );
    anchor_actor_subject(&vault, actor, person, owner, 101)?;
    assert_eq!(actor_subject_anchor(&vault, &actor, 103)?, Some(person));
    Ok(())
}
