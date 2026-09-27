//! Signed MACHINE claims bind an enrolled software key to exact bytes and vault.
use super::support::{authority_key_from_ed, ed_key};
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::EdgeActorClass;
use crate::write_envelope::{
    ClaimCandidate, MachineWriteSignature, WriteActor, WriteEnvelope, WriteProvenance,
};
use crate::{Vault, VaultConfig};

#[test]
fn machine_enrollment_and_signed_claim_verify_at_all_write_doors() {
    let dir = tempfile::tempdir().unwrap();
    let clock = crate::ports::ManualClock::new(10_000);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).unwrap();
    let machine = EntityId::now();
    let at = TimeRange {
        start: 10_000,
        end: 10_000,
    };
    vault
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            10_000,
            b"machine",
        )
        .unwrap();
    let issuer = HostSlipIssuer::from_secret(b"machine host root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let signing = ed_key(226);
    assert!(
        vault
            .enroll_machine_identity(
                &issuer,
                machine,
                signing.verifying_key().to_bytes(),
                signing.verifying_key().to_bytes(),
                |_| Ok([0; 64]),
            )
            .is_err(),
        "the transport binding cannot reuse the authority public key"
    );
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [17; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .unwrap();
    let key = authority_key_from_ed(&signing);
    assert!(!vault.authority_fold().unwrap().pending_widens.is_empty());

    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("machine output")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "test.machine.signature",
        ClaimSubject::Entity(machine),
        Value::from("fact"),
        1.0,
    );
    let id = EntityId::now();
    let transcript = vault
        .machine_claim_transcript(&id, &candidate, &envelope)
        .unwrap();
    let proof = MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    };
    let signed = envelope.clone().with_machine_signature(proof);
    assert!(
        vault
            .batch()
            .claim_candidate(&id, candidate.clone(), &signed, at, 10_000)
            .commit()
            .is_err(),
        "a pending enrollment must not authorize"
    );
    assert!(vault.get(&id).unwrap().is_none());

    // The observation clock ignores wall-clock jumps. Advance its monotone
    // test floor, as in the authority readonly-fold delay fixtures.
    let matured = 10_000 + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    clock.set(matured);
    assert!(authority_observation_secs(&vault.store, matured, 0) >= matured);
    let fold = vault.authority_fold().unwrap();
    assert!(fold.actor_bindings.contains_key(&key), "{fold:?}");
    assert_eq!(fold.actor_bindings[&key].status, ActorBindingStatus::Active);
    assert_eq!(fold.roster[&key].tier, AuthorityTier::Software);
    assert_eq!(fold.roster[&key].roles, ROLE_AGENT);
    assert_eq!(fold.vault_id, Some(root.claims.vault_id));
    assert!(
        vault
            .batch()
            .claim_candidate(&id, candidate.clone(), &envelope, at, 10_000)
            .commit()
            .is_err(),
        "unsigned machine must not write"
    );
    assert!(vault.get(&id).unwrap().is_none());
    vault
        .batch()
        .claim_candidate(&id, candidate.clone(), &signed, at, 10_000)
        .commit()
        .unwrap();
    let stored = vault.get_claim(&id).unwrap().unwrap();
    assert_eq!(stored.value, Value::from("fact"));
    // The plain lifecycle door has no machine signer. It must not publish a
    // changed body carrying the old origin signature as if it were signed.
    assert!(vault.retract_claim(&id, matured).is_err());
    assert_eq!(
        vault.get_claim(&id).unwrap().unwrap().lifecycle,
        crate::claim::ClaimLifecycleStatus::Active
    );
    let body_bytes = crate::claim::encode_claim_body(&stored).unwrap();
    let other_id = EntityId::now();
    assert!(
        vault
            .batch()
            .put_replicated(
                &other_id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                10_000,
                &body_bytes
            )
            .commit()
            .is_err(),
        "signature cannot be moved to another id on replay"
    );
    let changed = ClaimCandidate::new(
        "test.machine.signature",
        ClaimSubject::Entity(machine),
        Value::from("tampered"),
        1.0,
    );
    assert!(
        vault
            .batch()
            .claim_candidate(&EntityId::now(), changed, &signed, at, 10_000)
            .commit()
            .is_err()
    );
    // A peer may send the signed claim before the binding arrives. Admit the
    // origin-signed bytes but withhold the unbound author at the read fold.
    let stranger = ed_key(227);
    let unbound_id = EntityId::now();
    let unbound_transcript = vault
        .machine_claim_transcript(&unbound_id, &candidate, &envelope)
        .unwrap();
    let unbound = envelope
        .clone()
        .with_machine_signature(MachineWriteSignature {
            public_key: stranger.verifying_key().to_bytes(),
            signature: stranger.sign(&unbound_transcript).to_bytes(),
        });
    let unbound_body = candidate.clone().into_claim_body(
        &unbound,
        crate::claim::default_facet_in(&vault.store, &vault.store.env.read_txn().unwrap()).unwrap(),
    );
    let unbound_bytes = crate::claim::encode_claim_body(&unbound_body).unwrap();
    vault
        .batch()
        .put_replicated(
            &unbound_id,
            crate::registry::ENTITY_TYPE_CLAIM,
            at,
            10_000,
            &unbound_bytes,
        )
        .commit()
        .unwrap();
    assert_eq!(
        vault.claim_write_disposition(&unbound_id).unwrap(),
        Some(CausalWriteDisposition::Quarantined)
    );

    // Relabeling a MACHINE writer as human is not a signed-identity bypass.
    let mut spoof = stored;
    if let Some(Value::Map(entries)) = &mut spoof.evidence {
        for (key, value) in entries {
            if key.as_str() == Some("actor_class") {
                *value = Value::from(EdgeActorClass::Human as u8);
            }
        }
    }
    let spoof_id = EntityId::now();
    let spoof_transcript =
        machine_claim_transcript(&root.claims.vault_id, &spoof_id, &spoof).unwrap();
    if let Some(Value::Map(entries)) = &mut spoof.evidence {
        for (key, value) in entries {
            if key.as_str() == Some("machine_signature") {
                *value = Value::Array(vec![
                    Value::Binary(signing.verifying_key().to_bytes().to_vec()),
                    Value::Binary(signing.sign(&spoof_transcript).to_bytes().to_vec()),
                ]);
            }
        }
    }
    assert!(
        vault
            .batch()
            .put_replicated(
                &spoof_id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                10_000,
                &crate::claim::encode_claim_body(&spoof).unwrap()
            )
            .commit()
            .is_err()
    );

    // A revoked binding withdraws this software key's future write authority.
    let mut revoke = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            4,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::RevokeActor {
                authority_key: key.clone(),
                epoch: 1,
            },
            matured,
        )
        .unwrap();
    revoke.cosigns.push(AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    });
    revoke.cosigns[0].signature = signing
        .sign(&authority_transcript(&revoke).unwrap())
        .to_bytes()
        .to_vec();
    issuer.resign_entry(&mut revoke).unwrap();
    vault
        .put_authority_log_entry(
            &revoke,
            TimeRange {
                start: matured,
                end: matured,
            },
            matured,
        )
        .unwrap();
    let revoked_id = EntityId::now();
    let revoked_transcript = vault
        .machine_claim_transcript(&revoked_id, &candidate, &envelope)
        .unwrap();
    let revoked = envelope.with_machine_signature(MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&revoked_transcript).to_bytes(),
    });
    assert!(
        vault
            .batch()
            .claim_candidate(&revoked_id, candidate, &revoked, at, 10_000)
            .commit()
            .is_err()
    );
    assert!(vault.get(&revoked_id).unwrap().is_none());

    let other_dir = tempfile::tempdir().unwrap();
    let other = Vault::open(other_dir.path(), VaultConfig::device()).unwrap();
    other
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            10_000,
            b"machine",
        )
        .unwrap();
    let other_issuer = HostSlipIssuer::from_secret(b"other vault root").unwrap();
    other.ensure_host_root_slip(&other_issuer).unwrap();
    assert!(
        other
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                10_000,
                &body_bytes
            )
            .commit()
            .is_err(),
        "vault-bound proof cannot be replayed in another vault"
    );
}

#[test]
fn unsigned_machine_claim_stays_quarantined_when_actor_arrives_after_replay() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let issuer = HostSlipIssuer::from_secret(b"late machine actor root").unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    let machine = EntityId::now();
    let subject = EntityId::now();
    let claim_id = EntityId::now();
    let at = TimeRange { start: 10, end: 10 };
    vault
        .put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            at,
            10,
            b"subject",
        )
        .unwrap();
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("peer asserted machine")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "test.machine.late_actor",
        ClaimSubject::Entity(subject),
        Value::from("unsigned"),
        1.0,
    );
    let facet =
        crate::claim::default_facet_in(&vault.store, &vault.store.env.read_txn().unwrap()).unwrap();
    let bytes =
        crate::claim::encode_claim_body(&candidate.into_claim_body(&envelope, facet)).unwrap();
    vault
        .batch()
        .put_replicated(
            &claim_id,
            crate::registry::ENTITY_TYPE_CLAIM,
            at,
            10,
            &bytes,
        )
        .commit()
        .unwrap();
    assert_eq!(
        vault.claim_write_disposition(&claim_id).unwrap(),
        Some(CausalWriteDisposition::Quarantined)
    );
    vault
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            10,
            b"late machine",
        )
        .unwrap();
    assert_eq!(
        vault.claim_write_disposition(&claim_id).unwrap(),
        Some(CausalWriteDisposition::Quarantined)
    );
}
