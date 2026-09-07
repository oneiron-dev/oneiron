use super::*;
use crate::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
    authority_entry_hash, authority_transcript, genesis_vault_id,
};
use ed25519_dalek::{Signer, SigningKey};

fn sign(mut entry: AuthorityLogEntry, key: &SigningKey) -> Result<AuthorityLogEntry> {
    entry.signer.signature = key.sign(&authority_transcript(&entry)?).to_bytes().to_vec();
    Ok(entry)
}

fn bind_recipient(
    vault: &Vault,
    recipient: EntityId,
    class: &str,
) -> Result<(SigningKey, AuthorityLogEntry)> {
    let signing = SigningKey::from_bytes(&[0xA1; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let genesis = sign(
        AuthorityLogEntry {
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
                genesis_nonce: [0xA2; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
            },
            signer: AuthoritySignature {
                suite: key.suite(),
                public_key: key.clone(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: 100,
        },
        &signing,
    )?;
    let bind = sign(
        AuthorityLogEntry {
            vault_id: Some(genesis_vault_id(&genesis)?),
            seq: 1,
            parent_hashes: vec![authority_entry_hash(&genesis)?],
            op: AuthorityOp::BindActor {
                authority_key: key,
                actor_ref: recipient,
                actor_class: class.to_owned(),
                epoch: 1,
            },
            ts: 101,
            ..genesis.clone()
        },
        &signing,
    )?;
    vault.put_authority_log_entries(&[(genesis, time(1), 1), (bind.clone(), time(2), 2)])?;
    Ok((signing, bind))
}

// Change only the fixture's read actor selectors and receipt requirement.
fn read_actor(
    vault: &Vault,
    class: &str,
    actor_ref: Option<EntityId>,
    receipt_required: bool,
) -> Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    let mut value = {
        let txn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .entities
            .get(&txn, id.as_bytes())?
            .expect("policy");
        rmpv::decode::read_value(&mut &raw[ENTITY_METADATA_HEADER_LEN..]).expect("decode policy")
    };
    let Value::Map(entries) = &mut value else {
        panic!("policy map")
    };
    let (_, Value::Array(grants)) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("scoped_grants"))
        .expect("scoped grants")
    else {
        panic!("grant array")
    };
    let grant = grants
        .iter_mut()
        .find_map(|grant| {
            let Value::Map(fields) = grant else {
                return None;
            };
            fields
                .iter()
                .any(|(key, value)| {
                    key.as_str() == Some("effector") && value.as_str() == Some("core:read")
                })
                .then_some(fields)
        })
        .expect("read grant");
    grant.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            Some("actor_ref" | "actor_class" | "receipt_required")
        )
    });
    grant.push((Value::from("actor_class"), Value::from(class)));
    if let Some(actor_ref) = actor_ref {
        grant.push((Value::from("actor_ref"), Value::from(actor_ref.to_hex())));
    }
    grant.push((
        Value::from("receipt_required"),
        Value::Boolean(receipt_required),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).expect("encode policy");
    put_policy_manifest_bytes(vault, id, &bytes)
}

#[test]
fn class_scoped_reads_require_live_verified_recipient_class() -> Result<()> {
    let (_dir, vault, issuer, mut share) = fixture()?;
    share.world_refs = BTreeSet::from([entity(0x61)]);
    share.facet_refs = BTreeSet::from([entity(0x71)]);
    let id = entity(0x81);
    let candidate = entity(0x91);
    vault.create_share(&id, &issuer, &share)?;
    claim(
        &vault,
        candidate,
        Some(entity(0x61)),
        &[entity(0x71), entity(0x72)],
        false,
    )?;
    // The fixture's explicit-ref grant still works without any class binding.
    assert_eq!(visible(&vault, &id, &share, &[candidate])?, vec![candidate]);
    for actor_ref in [None, Some(share.recipient_ref)] {
        read_actor(&vault, "human", actor_ref, false)?;
        assert!(visible(&vault, &id, &share, &[candidate])?.is_empty());
    }
    let (signing, binding) = bind_recipient(&vault, share.recipient_ref, "human")?;
    let receipts = vault.receipts(ReceiptQuery::new(20))?;
    for actor_ref in [None, Some(share.recipient_ref)] {
        read_actor(&vault, "human", actor_ref, false)?;
        assert_eq!(visible(&vault, &id, &share, &[candidate])?, vec![candidate]);
    }
    assert!(
        vault
            .resolve_share_for_view(&id, &issuer.entity_ref(), None, &[candidate])?
            .is_none()
    );
    read_actor(&vault, "human", Some(issuer.entity_ref()), false)?;
    assert!(visible(&vault, &id, &share, &[candidate])?.is_empty());
    read_actor(&vault, "agent", Some(share.recipient_ref), false)?;
    assert!(visible(&vault, &id, &share, &[candidate])?.is_empty());

    // Class grants intersect the SAME world/facet maximum, including facet OR.
    for (world, facet, allowed) in [(0x61, 0x71, true), (0x61, 0x72, false), (0x62, 0x71, false)] {
        policy(
            &vault,
            &issuer,
            &share,
            true,
            Some(read_scope(entity(world), entity(facet))),
        )?;
        read_actor(&vault, "human", None, false)?;
        assert_eq!(
            !visible(&vault, &id, &share, &[candidate])?.is_empty(),
            allowed
        );
    }
    policy(&vault, &issuer, &share, true, None)?;
    read_actor(&vault, "human", None, true)?;
    assert!(visible(&vault, &id, &share, &[candidate])?.is_empty());
    read_actor(&vault, "human", None, false)?;
    assert_eq!(visible(&vault, &id, &share, &[candidate])?, vec![candidate]);
    assert_eq!(vault.receipts(ReceiptQuery::new(20))?, receipts);

    // The stored PERSON type remains unchanged while its verified class changes.
    let rebound = sign(
        AuthorityLogEntry {
            seq: 2,
            parent_hashes: vec![authority_entry_hash(&binding)?],
            op: AuthorityOp::RebindActor {
                authority_key: binding.signer.public_key.clone(),
                actor_ref: share.recipient_ref,
                actor_class: "agent".to_owned(),
                epoch: 2,
            },
            ts: 102,
            ..binding
        },
        &signing,
    )?;
    vault.put_authority_log_entry(&rebound, time(3), 3)?;
    assert!(visible(&vault, &id, &share, &[candidate])?.is_empty());
    read_actor(&vault, "agent", Some(share.recipient_ref), false)?;
    assert_eq!(visible(&vault, &id, &share, &[candidate])?, vec![candidate]);
    let revoked = sign(
        AuthorityLogEntry {
            seq: 3,
            parent_hashes: vec![authority_entry_hash(&rebound)?],
            op: AuthorityOp::RevokeActor {
                authority_key: rebound.signer.public_key.clone(),
                epoch: 2,
            },
            ts: 103,
            ..rebound
        },
        &signing,
    )?;
    vault.put_authority_log_entry(&revoked, time(4), 4)?;
    assert!(visible(&vault, &id, &share, &[candidate])?.is_empty());
    policy(&vault, &issuer, &share, true, None)?;
    assert_eq!(visible(&vault, &id, &share, &[candidate])?, vec![candidate]);
    Ok(())
}

#[test]
fn class_scoped_reads_refuse_missing_invalid_or_unverifiable_identity() -> Result<()> {
    let (_dir, vault, issuer, share) = fixture()?;
    let id = entity(0x81);
    let candidate = entity(0x91);
    vault.create_share(&id, &issuer, &share)?;
    claim(&vault, candidate, None, &[], false)?;
    read_actor(&vault, "human", None, false)?;
    let recipient_raw = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .entities
            .get(&txn, share.recipient_ref.as_bytes())?
            .expect("recipient")
            .to_vec()
    };

    // An arbitrary resident claim asserting a class is not a verified binding.
    let body = ClaimBody::new(
        "profile.actor_class",
        ClaimSubject::Entity(share.recipient_ref),
        Value::from("human"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let bytes = encode_claim_body(&body)?;
    vault.with_write_txn(|txn| {
        let raw = entity_record(ENTITY_TYPE_CLAIM, time(1), 1, &bytes);
        vault
            .store
            .entities
            .put(txn, entity(0x92).as_bytes(), &raw)?;
        Ok(())
    })?;
    assert!(visible(&vault, &id, &share, &[candidate])?.is_empty());
    let (_, binding) = bind_recipient(&vault, share.recipient_ref, "human")?;
    assert_eq!(visible(&vault, &id, &share, &[candidate])?, vec![candidate]);
    for raw in [
        vec![],
        vec![ENTITY_TYPE_PERSON],
        entity_record(ENTITY_TYPE_FACET, time(1), 1, b"human"),
        entity_record(crate::registry::ENTITY_TYPE_MACHINE, time(1), 1, b"human"),
    ] {
        vault.with_write_txn(|txn| {
            vault
                .store
                .entities
                .put(txn, share.recipient_ref.as_bytes(), &raw)?;
            Ok(())
        })?;
        assert!(
            vault
                .resolve_share_for_view(&id, &share.recipient_ref, None, &[candidate])?
                .is_none()
        );
    }
    vault.with_write_txn(|txn| {
        vault
            .store
            .entities
            .delete(txn, share.recipient_ref.as_bytes())?;
        Ok(())
    })?;
    assert!(
        vault
            .resolve_share_for_view(&id, &share.recipient_ref, None, &[candidate])?
            .is_none()
    );
    vault.with_write_txn(|txn| {
        vault
            .store
            .entities
            .put(txn, share.recipient_ref.as_bytes(), &recipient_raw)?;
        Ok(())
    })?;

    // A resident authority row with an unverifiable signature cannot supply class.
    let binding_id = crate::authority::authority_log_entity_id(&binding)?;
    let mut forged = binding;
    forged.signer.signature = vec![0; 64];
    let bytes = crate::authority::encode_authority_log_entry_body(&forged)?;
    vault.with_write_txn(|txn| {
        let raw = entity_record(
            crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
            time(2),
            2,
            &bytes,
        );
        vault.store.entities.put(txn, binding_id.as_bytes(), &raw)?;
        Ok(())
    })?;
    assert!(
        vault
            .resolve_share_for_view(&id, &share.recipient_ref, None, &[candidate])
            .is_err()
    );
    Ok(())
}
