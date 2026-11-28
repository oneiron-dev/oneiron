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

    // A host-landed software enrollment takes effect at once: the device-key
    // widen delay is dead (identity.md, "Device-key widen ceremony").
    let later = 10_001;
    clock.set(later);
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
    let birth = vault.resolved_machine_claim(id).unwrap();
    assert_eq!(
        birth.signed_origin.lifecycle,
        crate::claim::ClaimLifecycleStatus::Active
    );
    vault
        .retract_claim(&id, later)
        .expect("host-authorized transition");
    let resolved = vault.resolved_machine_claim(id).unwrap();
    assert_eq!(
        resolved.current.lifecycle,
        crate::claim::ClaimLifecycleStatus::Retracted
    );
    assert_eq!(
        resolved.signed_origin.lifecycle,
        crate::claim::ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault.get_claim(&id).unwrap().unwrap().lifecycle,
        crate::claim::ClaimLifecycleStatus::Retracted
    );
    let body_bytes = crate::claim::encode_claim_body(&stored).unwrap();
    assert!(
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                10_000,
                None,
                &body_bytes,
            )
            .commit()
            .is_err(),
        "old valid birth cannot undo a terminal event"
    );
    assert_eq!(
        vault.get_claim(&id).unwrap().unwrap().lifecycle,
        crate::claim::ClaimLifecycleStatus::Retracted
    );
    let mut laundered = stored.clone();
    laundered.evidence = None;
    laundered.value = Value::from("attacker ordinary claim");
    laundered.approval = ClaimApprovalStatus::Approved;
    assert!(
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                10_000,
                None,
                &crate::claim::encode_claim_body(&laundered).unwrap(),
            )
            .commit()
            .is_err(),
        "known MACHINE target id cannot become ordinary claim"
    );
    assert_eq!(
        vault.get_claim(&id).unwrap().unwrap().lifecycle,
        crate::claim::ClaimLifecycleStatus::Retracted
    );
    // Fresh replica receives only signed authority rows and scoped controls.
    // Its CRDT row can still be the old birth: the authenticated handoff
    // selects the terminal projection, not the LWW snapshot.
    let replica_dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(replica_dir.path(), VaultConfig::device()).unwrap();
    replica
        .import_signed_authority_history(
            &vault.export_signed_authority_history().unwrap(),
            &CarriedOverlays::new(),
        )
        .unwrap();
    replica
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            10_000,
            b"machine",
        )
        .unwrap();
    let local_txn = vault.store.env.read_txn().unwrap();
    let controls =
        crate::claim::history_store::machine_history_ids_for_target(&vault.store, &local_txn, id)
            .unwrap();
    let handoff =
        crate::claim::history_projection::trusted_machine_handoff(&vault.store, &local_txn, id)
            .unwrap();
    let history_rows =
        crate::claim::history_projection::machine_history_rows(&vault.store, &local_txn, id)
            .unwrap();
    drop(local_txn);
    let scope = handoff.scope.clone();
    let expected_signer = issuer.public_key();
    let pin = crate::claim::ClaimHistoryHandoffPin {
        vault_id: &root.claims.vault_id,
        genesis_hash: &root.claims.vault_id,
        expected_signer: &expected_signer,
        scope: &scope,
        previous_handoff_hash: handoff.previous_handoff_hash,
        previous_heads: history_rows.previous_heads(),
        challenge: &handoff.challenge,
    };
    assert!(
        replica
            .authority_fold()
            .unwrap()
            .valid_entries
            .contains(&handoff.authority_head)
    );
    replica
        .pin_machine_history_handoff_pending(id, &handoff, &pin, &issuer)
        .unwrap();
    replica
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            at,
            10_000,
            None,
            &body_bytes,
        )
        .commit()
        .unwrap();
    replica
        .batch()
        .edge(&id, crate::edge::EdgeKind::ClaimOf, &machine, 1.0)
        .commit()
        .unwrap();
    assert!(
        replica.resolved_machine_claim(id).is_err(),
        "no peer assertion of empty history"
    );
    let mut rows = controls
        .into_iter()
        .map(|event_id| {
            let raw = vault.get_raw(&event_id).unwrap().unwrap();
            let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
            let body = crate::claim::decode_claim_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                true,
            )
            .unwrap();
            (event_id, header, body, raw)
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|(_, _, body, _)| match body.predicate.as_str() {
        "machine.birth" => 0,
        "machine.transition" => 1,
        _ => 2,
    });
    for (event_id, header, _, raw) in rows {
        replica
            .batch()
            .put_replicated(
                &event_id,
                crate::registry::ENTITY_TYPE_CLAIM,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                None,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .commit()
            .unwrap();
    }
    replica
        .adopt_machine_history_handoff(id, &handoff, &pin)
        .unwrap();
    assert_eq!(
        replica.get_claim(&id).unwrap().unwrap().lifecycle,
        crate::claim::ClaimLifecycleStatus::Retracted
    );
    assert_eq!(
        replica
            .resolved_machine_claim(id)
            .unwrap()
            .signed_origin
            .lifecycle,
        crate::claim::ClaimLifecycleStatus::Active
    );

    let other_id = EntityId::now();
    assert!(
        vault
            .batch()
            .put_replicated(
                &other_id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                10_000,
                None,
                &body_bytes,
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
    let unbound_body = candidate
        .clone()
        .into_claim_body(
            &unbound,
            crate::claim::default_facet_in(&vault.store, &vault.store.env.read_txn().unwrap())
                .unwrap(),
        )
        .unwrap();
    let unbound_bytes = crate::claim::encode_claim_body(&unbound_body).unwrap();
    vault
        .batch()
        .put_replicated(
            &unbound_id,
            crate::registry::ENTITY_TYPE_CLAIM,
            at,
            10_000,
            None,
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
                None,
                &crate::claim::encode_claim_body(&spoof).unwrap(),
            )
            .commit()
            .is_err()
    );

    // A revoked binding withdraws this software key's future write authority.
    let mut revoke = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            fold.append_sequences[&issuer.public_key()] + 1,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::RevokeActor {
                authority_key: key.clone(),
                epoch: 1,
            },
            later,
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
                start: later,
                end: later,
            },
            later,
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
                None,
                &body_bytes,
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
        crate::claim::encode_claim_body(&candidate.into_claim_body(&envelope, facet).unwrap())
            .unwrap();
    vault
        .batch()
        .put_replicated(
            &claim_id,
            crate::registry::ENTITY_TYPE_CLAIM,
            at,
            10,
            None,
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

#[test]
fn machine_without_genesis_never_writes_unsigned_or_bogus_claims() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let machine = EntityId::now();
    let id = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            1,
            b"machine",
        )
        .unwrap();
    let unsigned = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("bootstrap attempt")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "test.machine.bootstrap",
        ClaimSubject::Entity(machine),
        Value::from("no root"),
        1.0,
    );
    let bogus = unsigned
        .clone()
        .with_machine_signature(MachineWriteSignature {
            public_key: ed_key(220).verifying_key().to_bytes(),
            signature: [0; 64],
        });
    for envelope in [&unsigned, &bogus] {
        assert!(
            vault
                .batch()
                .claim_candidate(&id, candidate.clone(), envelope, at, 1)
                .commit()
                .is_err()
        );
        assert!(vault.get(&id).unwrap().is_none());
    }
    let issuer = HostSlipIssuer::from_secret(b"bootstrap after refused machine write").unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    assert!(
        vault
            .batch()
            .claim_candidate(&id, candidate.clone(), &unsigned, at, 1)
            .commit()
            .is_err()
    );
    assert!(
        vault
            .batch()
            .claim_candidate(&id, candidate, &bogus, at, 1)
            .commit()
            .is_err()
    );
    assert!(vault.get(&id).unwrap().is_none());
}

#[test]
fn owner_approval_and_machine_supersession_follow_signed_history() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let at = TimeRange { start: 10, end: 10 };
    let machine = EntityId::now();
    vault
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            10,
            b"machine",
        )
        .unwrap();
    let issuer = HostSlipIssuer::from_secret(b"history-approval-root").unwrap();
    // The self-hosted root binds the vault's owner (H149).
    vault.ensure_host_root_slip(&issuer).unwrap();
    let owner = crate::vault::embedded_owner_actor_id().unwrap();
    let signing = ed_key(228);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [29; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .unwrap();
    let later = vault.now_recorded_at() + 1;
    let mut manifest = crate::gate::default_policy_manifest().unwrap();
    let Value::Map(mut fields) =
        rmpv::decode::read_value(&mut std::io::Cursor::new(manifest.as_slice())).unwrap()
    else {
        panic!("policy")
    };
    for (key, value) in &mut fields {
        if key.as_str() == Some("actor_ceilings") {
            let Value::Array(rows) = value else {
                panic!("ceilings")
            };
            rows.push(Value::Map(vec![
                (Value::from("actor_class"), Value::from("system")),
                (Value::from("actor_ref"), Value::from(machine.to_hex())),
                (Value::from("ceiling"), Value::from("auto")),
            ]));
        }
    }
    manifest.clear();
    rmpv::encode::write_value(&mut manifest, &Value::Map(fields)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &manifest,
    )
    .unwrap();
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("machine fact")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "profile.color",
        ClaimSubject::Entity(machine),
        Value::from("blue"),
        1.0,
    );
    let id = EntityId::now();
    let transcript = vault
        .machine_claim_transcript(&id, &candidate, &envelope)
        .unwrap();
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    });
    vault
        .batch()
        .claim_candidate(&id, candidate, &signed, at, 10)
        .commit()
        .unwrap();
    let reviewed = vault.get_claim(&id).unwrap().unwrap();
    assert_eq!(reviewed.approval, ClaimApprovalStatus::Proposed);
    let unauthorized = WriteActor::new(machine, EdgeActorClass::System);
    assert!(vault.approve_machine_claim_as(id, unauthorized).is_err());
    let before = vault.resolved_machine_claim(id).unwrap().handoff_digest;
    assert_eq!(
        vault.resolved_machine_claim(id).unwrap().handoff_digest,
        before
    );
    vault
        .approve_machine_claim_as(id, WriteActor::new(owner, EdgeActorClass::Human))
        .unwrap();
    assert_eq!(
        vault.get_claim(&id).unwrap().unwrap().approval,
        ClaimApprovalStatus::Approved
    );
    assert_ne!(
        vault.resolved_machine_claim(id).unwrap().handoff_digest,
        before
    );
    let original = crate::claim::encode_claim_body(&reviewed).unwrap();
    assert!(
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                10,
                None,
                &original
            )
            .commit()
            .is_err(),
        "stale valid Proposed birth cannot roll back owner approval"
    );

    let auto_envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("machine revision")).unwrap(),
        ClaimApprovalStatus::Auto,
    );
    let mut ids = Vec::new();
    for value in ["old", "new"] {
        let next_id = EntityId::now();
        let next = ClaimCandidate::new(
            "profile.color",
            ClaimSubject::Entity(machine),
            Value::from(value),
            1.0,
        );
        let transcript = vault
            .machine_claim_transcript(&next_id, &next, &auto_envelope)
            .unwrap();
        let signed = auto_envelope
            .clone()
            .with_machine_signature(MachineWriteSignature {
                public_key: signing.verifying_key().to_bytes(),
                signature: signing.sign(&transcript).to_bytes(),
            });
        vault
            .batch()
            .claim_candidate(&next_id, next, &signed, at, 10)
            .commit()
            .unwrap();
        ids.push(next_id);
    }
    vault.supersede_claim(&ids[1], &ids[0], later).unwrap();
    assert_eq!(
        vault.get_claim(&ids[0]).unwrap().unwrap().lifecycle,
        crate::claim::ClaimLifecycleStatus::Superseded
    );
    let old_birth = vault.resolved_machine_claim(ids[0]).unwrap().signed_origin;
    assert!(
        vault
            .batch()
            .put_replicated(
                &ids[0],
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                10,
                None,
                &crate::claim::encode_claim_body(&old_birth).unwrap(),
            )
            .commit()
            .is_err()
    );
}

#[test]
fn successor_root_carries_exact_machine_history_and_refuses_retired_backdating() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let issuer = HostSlipIssuer::from_secret(b"old machine history root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let machine = EntityId::now();
    let id = EntityId::now();
    let at = TimeRange { start: 10, end: 10 };
    vault
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            10,
            b"machine",
        )
        .unwrap();
    let machine_key = ed_key(229);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            machine_key.verifying_key().to_bytes(),
            [13; 32],
            |transcript| Ok(machine_key.sign(transcript).to_bytes()),
        )
        .unwrap();
    let later = vault.now_recorded_at() + 1;
    let pre_rotation = vault.authority_fold().unwrap();
    assert_eq!(
        pre_rotation.actor_bindings[&authority_key_from_ed(&machine_key)].status,
        ActorBindingStatus::Active
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("before rotation")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "profile.color",
        ClaimSubject::Entity(machine),
        Value::from("blue"),
        1.0,
    );
    let transcript = vault
        .machine_claim_transcript(&id, &candidate, &envelope)
        .unwrap();
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: machine_key.verifying_key().to_bytes(),
        signature: machine_key.sign(&transcript).to_bytes(),
    });
    vault
        .batch()
        .claim_candidate(&id, candidate, &signed, at, 10)
        .commit()
        .unwrap();
    vault.retract_claim(&id, later).unwrap();
    let prior_handoff = vault.resolved_machine_claim(id).unwrap().handoff_digest;
    let successor = HostSlipIssuer::from_secret(b"successor machine history root").unwrap();
    let fold = vault.authority_fold().unwrap();
    let mut re_root = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            fold.append_sequences[&issuer.public_key()] + 1,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::ReRoot {
                new_device: DeviceAuthority {
                    key: successor.public_key(),
                    transport_key_binding: [14; 32],
                    attestation: AuthorityAttestation {
                        kind: "SoftwareArgon2id".into(),
                        evidence: Vec::new(),
                    },
                    tier: AuthorityTier::Software,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                },
            },
            later,
        )
        .unwrap();
    let machine_authority_key = authority_key_from_ed(&machine_key);
    re_root.cosigns.push(AuthoritySignature {
        suite: machine_authority_key.suite(),
        public_key: machine_authority_key,
        signature: vec![0; 64],
    });
    let transcript = authority_transcript(&re_root).unwrap();
    re_root.cosigns[0].signature = machine_key.sign(&transcript).to_bytes().to_vec();
    re_root.signer.signature = issuer.sign_claim_handoff(&transcript).to_vec();
    vault.apply_signed_re_root(&re_root).unwrap();
    let new_hash = vault
        .carry_machine_history_after_re_root(id, &successor, [15; 32])
        .unwrap();
    assert_ne!(new_hash, prior_handoff);
    let txn = vault.store.env.read_txn().unwrap();
    let rows =
        crate::claim::history_projection::machine_history_rows(&vault.store, &txn, id).unwrap();
    let packet =
        crate::claim::history_projection::trusted_machine_handoff(&vault.store, &txn, id).unwrap();
    let after = vault.authority_fold_readonly_in_txn(&txn).unwrap();
    assert!(after.valid_entries.contains(&packet.authority_head));
    assert!(packet.transitions.is_empty());
    assert_eq!(packet.previous_handoff_hash, Some(prior_handoff));
    assert_eq!(rows.events.len(), rows.transitions.len());
    assert_eq!(rows.events.len(), 1);
    assert!(
        after
            .roster
            .get(&packet.signer)
            .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
    );
    let check =
        crate::claim::history_projection::resolved_machine_history(&vault.store, &txn, &after, id);
    assert!(check.is_ok(), "re-root history verdict: {check:?}");
    drop(txn);
    let resolution = vault.resolved_machine_claim(id).unwrap();
    assert_eq!(
        resolution.current.lifecycle,
        crate::claim::ClaimLifecycleStatus::Retracted
    );
    assert_eq!(
        resolution.signed_origin.lifecycle,
        crate::claim::ClaimLifecycleStatus::Active
    );
    assert_eq!(resolution.handoff_digest, new_hash);
    assert_eq!(resolution.claim_id, id);
    assert_eq!(
        root.claims.vault_id,
        vault.authority_fold().unwrap().vault_id.unwrap()
    );
}

#[test]
fn orphan_peer_transition_is_quarantined_before_it_can_poison_a_target() {
    use crate::claim::transition::{
        ClaimTransitionKind, SignedClaimTransitionEvent, TransitionDelta,
        encode_machine_claim_transition_event, machine_claim_transition_event_id,
        machine_claim_transition_transcript,
    };
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let issuer = HostSlipIssuer::from_secret(b"orphan transition root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let machine = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            1,
            b"machine",
        )
        .unwrap();
    let mut orphan = SignedClaimTransitionEvent {
        vault_id: root.claims.vault_id,
        target: machine,
        birth_digest: [7; 32],
        predecessors: Vec::new(),
        authority_head: [8; 32],
        actor: machine,
        actor_class: EdgeActorClass::System,
        host_public_key: ed_key(230).verifying_key().to_bytes(),
        kind: ClaimTransitionKind::Retract,
        delta: TransitionDelta::ValidTo(2),
        signature: [0; 64],
    };
    orphan.signature = ed_key(230)
        .sign(&machine_claim_transition_transcript(&orphan).unwrap())
        .to_bytes();
    let id = machine_claim_transition_event_id(&orphan).unwrap();
    let record = crate::claim::history_store::machine_history_claim(
        crate::claim::history_store::MachineHistoryKind::Transition,
        machine,
        &ClaimCandidate::new(
            "profile.color",
            ClaimSubject::Entity(machine),
            Value::from("blue"),
            1.0,
        )
        .into_claim_body(
            &WriteEnvelope::new(
                WriteActor::new(machine, EdgeActorClass::System),
                ClaimSource::Observed,
                WriteProvenance::new(Value::from("fixture")).unwrap(),
                ClaimApprovalStatus::Proposed,
            ),
            crate::claim::substrate_facet_id(machine).unwrap(),
        )
        .unwrap(),
        encode_machine_claim_transition_event(&orphan).unwrap(),
    )
    .unwrap();
    let body = crate::claim::encode_claim_body(&record).unwrap();
    let result = vault
        .batch()
        .put_replicated(&id, crate::registry::ENTITY_TYPE_CLAIM, at, 1, None, &body)
        .commit();
    assert!(matches!(
        result,
        Err(crate::Error::Claim(
            crate::error::ClaimError::RemoteMachineHistoryPending
        ))
    ));
    assert!(vault.get(&id).unwrap().is_none());
    let txn = vault.store.env.read_txn().unwrap();
    assert!(
        crate::claim::history_store::machine_history_ids_for_target(&vault.store, &txn, machine)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn scoped_birth_control_follows_restrictive_current_demotion() {
    use crate::claim::{ClaimDemotionAction, ClaimDemotionRung};
    use crate::federation::{Scope, Sensitivity, SensitivityCeiling};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let issuer = HostSlipIssuer::from_secret(b"machine-demotion-scope-root").unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    let machine = EntityId::now();
    let id = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            1,
            b"machine",
        )
        .unwrap();
    let signing = ed_key(231);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [19; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .unwrap();
    let later = vault.now_recorded_at() + 1;
    let candidate = ClaimCandidate::new(
        "profile.color",
        ClaimSubject::Entity(machine),
        Value::from("public birth text"),
        1.0,
    )
    .with_scope(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("scoped")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let transcript = vault
        .machine_claim_transcript(&id, &candidate, &envelope)
        .unwrap();
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    });
    vault
        .batch()
        .claim_candidate(&id, candidate, &signed, at, 1)
        .commit()
        .unwrap();
    let before = vault.resolved_machine_claim(id).unwrap();
    let birth_id = EntityId::from_bytes(before.birth_digest[..16].try_into().unwrap()).unwrap();
    let raw = vault.get_raw(&birth_id).unwrap().unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let before_scope =
        crate::federation::record_scope::scope_for_blob(&vault.store, &txn, birth_id, &raw)
            .unwrap()
            .unwrap();
    assert_eq!(
        before_scope.sensitivity,
        SensitivityCeiling::AtMost(Sensitivity::Public)
    );
    drop(txn);
    assert_eq!(
        vault
            .apply_claim_demotion(
                &id,
                ClaimDemotionAction::Decay {
                    new_claim_of_weight: 0.5
                },
                later
            )
            .unwrap()
            .rung,
        ClaimDemotionRung::Decayed
    );
    // A weakening is the Dreamer's act: it births the Dreamer's own successor,
    // signed by the Dreamer's retained signer, never the machine's.
    vault.provision_engine_machine_identities(&issuer).unwrap();
    let weakened = vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Weaken {
                new_confidence: 0.5,
            },
            later + 1,
        )
        .unwrap();
    assert_eq!(weakened.rung, ClaimDemotionRung::Weakened);
    let id = weakened.claim;
    let successor = vault.resolved_machine_claim(id).unwrap();
    let birth_id = EntityId::from_bytes(successor.birth_digest[..16].try_into().unwrap()).unwrap();
    let raw = vault.get_raw(&birth_id).unwrap().unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let weakened_scope =
        crate::federation::record_scope::scope_for_blob(&vault.store, &txn, birth_id, &raw)
            .unwrap()
            .unwrap();
    assert_eq!(weakened_scope.sensitivity, before_scope.sensitivity);
    drop(txn);
    assert_eq!(
        vault
            .apply_claim_demotion(&id, ClaimDemotionAction::MarkStale, later + 2)
            .unwrap()
            .rung,
        ClaimDemotionRung::Stale
    );
    let txn = vault.store.env.read_txn().unwrap();
    let after_scope =
        crate::federation::record_scope::scope_for_blob(&vault.store, &txn, birth_id, &raw)
            .unwrap()
            .unwrap();
    assert_eq!(
        after_scope.sensitivity,
        SensitivityCeiling::AtMost(Sensitivity::Restricted)
    );
    drop(txn);
    let mut public = Scope::top();
    public.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Public);
    assert!(
        !vault
            .export_records_in_scope(&public, &Scope::top(), &Scope::top())
            .unwrap()
            .iter()
            .any(|row| row.id == birth_id)
    );
}

/// A vault whose MACHINE holds signed Proposed claims the default policy
/// parks for the owner (actor ceiling): held claims with ordinary tray rows.
struct HeldMachineClaims {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    machine: EntityId,
    signing: SigningKey,
}

impl HeldMachineClaims {
    fn open(secret: &[u8], key_seed: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        let issuer = HostSlipIssuer::from_secret(secret).unwrap();
        vault.ensure_host_root_slip(&issuer).unwrap();
        let machine = EntityId::now();
        vault
            .put_entity(
                &machine,
                crate::registry::ENTITY_TYPE_MACHINE,
                TimeRange { start: 1, end: 1 },
                1,
                b"machine",
            )
            .unwrap();
        let signing = ed_key(key_seed);
        vault
            .enroll_machine_identity(
                &issuer,
                machine,
                signing.verifying_key().to_bytes(),
                [key_seed; 32],
                |transcript| Ok(signing.sign(transcript).to_bytes()),
            )
            .unwrap();
        Self {
            _dir: dir,
            vault,
            issuer,
            machine,
            signing,
        }
    }

    /// The MACHINE's signed Proposed `profile.color` claim `value`, parked
    /// for the owner.
    fn propose(&self, value: &str) -> EntityId {
        let id = EntityId::now();
        let candidate = ClaimCandidate::new(
            "profile.color",
            ClaimSubject::Entity(self.machine),
            Value::from(value),
            1.0,
        )
        .with_scope(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from("public"),
        )]));
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.machine, EdgeActorClass::System),
            ClaimSource::Observed,
            WriteProvenance::new(Value::from("held")).unwrap(),
            ClaimApprovalStatus::Proposed,
        );
        let transcript = self
            .vault
            .machine_claim_transcript(&id, &candidate, &envelope)
            .unwrap();
        let signed = envelope.with_machine_signature(MachineWriteSignature {
            public_key: self.signing.verifying_key().to_bytes(),
            signature: self.signing.sign(&transcript).to_bytes(),
        });
        self.vault
            .batch()
            .claim_candidate(&id, candidate, &signed, TimeRange { start: 1, end: 1 }, 1)
            .commit()
            .unwrap();
        assert!(
            self.tray_row(&id).is_some(),
            "the default policy parks the MACHINE's proposal for the owner"
        );
        id
    }

    fn tray_row(&self, id: &EntityId) -> Option<crate::store::PendingGateConsentRecord> {
        let txn = self.vault.store.env.read_txn().unwrap();
        self.vault
            .store
            .pending_gate_consent_in_txn(&txn, id)
            .unwrap()
    }

    fn approve_as_owner(&self, id: EntityId) -> crate::Result<()> {
        let owner = crate::vault::embedded_owner_actor_id().unwrap();
        self.vault
            .approve_machine_claim_as(id, WriteActor::new(owner, EdgeActorClass::Human))
    }

    fn claim(&self, id: &EntityId) -> crate::claim::ClaimBody {
        self.vault.get_claim(id).unwrap().unwrap()
    }

    /// The pending decision the tray row of `id` names.
    fn asked(&self, id: &EntityId) -> crate::store::GateDecisionRecord {
        let row = self.tray_row(id).expect("the claim is asked");
        let txn = self.vault.store.env.read_txn().unwrap();
        self.vault
            .store
            .gate_decision_in_txn(&txn, row.decision_id)
            .unwrap()
            .expect("the asked decision is recorded")
    }

    /// Parks the held row of `id` again on a pending decision whose receipt
    /// also carries `reason`, the token a checker hold records for the owner.
    fn hold_with_checker_reason(&self, id: &EntityId, reason: &str) {
        let row = self.tray_row(id).expect("the claim is asked");
        let asked = self.asked(id);
        let mut wtxn = self.vault.store.env.write_txn().unwrap();
        let mut receipt = crate::store::GateReceipt::with_reasons(
            crate::store::gate_reason::GateReceiptOutcome::Pending,
            "claim",
            row.reason_codes.clone(),
            crate::store::ReceiptActor::Verbatim {
                class: asked.actor_class.clone(),
                actor_ref: asked.actor_ref.clone(),
            },
            row.diff_handle.clone(),
            crate::store::PolicyBasis::frontier(row.read_frontier_hash),
        );
        receipt.about = Some(*id);
        receipt.receipt_reasons = asked
            .receipt_reasons
            .iter()
            .cloned()
            .chain([reason.to_owned()])
            .collect();
        let decision = self
            .vault
            .store
            .record_gate_receipt_in_txn(&mut wtxn, receipt)
            .unwrap();
        self.vault
            .store
            .put_pending_gate_consent_in_txn(
                &mut wtxn,
                &crate::store::PendingGateConsentRecord {
                    decision_id: decision.decision_id,
                    created_at: decision.created_at,
                    ..row
                },
            )
            .unwrap();
        wtxn.commit().unwrap();
    }

    /// As [`Self::hold_with_checker_reason`], for a write a runner's attempt
    /// `attempt` made as an agent on a Normal predicate: the asked receipt
    /// also carries the loop link to that attempt and the drift tripwire's
    /// normal-baseline token, as the claim write door records them.
    fn hold_from_runner_attempt(&self, id: &EntityId, reason: &str, attempt: [u8; 16]) {
        self.hold_with_checker_reason(id, reason);
        let row = self.tray_row(id).expect("the claim is asked");
        let asked = self.asked(id);
        let mut wtxn = self.vault.store.env.write_txn().unwrap();
        let mut receipt = crate::store::GateReceipt::with_reasons(
            crate::store::gate_reason::GateReceiptOutcome::Pending,
            "claim",
            row.reason_codes.clone(),
            crate::store::ReceiptActor::Verbatim {
                class: asked.actor_class.clone(),
                actor_ref: asked.actor_ref.clone(),
            },
            row.diff_handle.clone(),
            crate::store::PolicyBasis::frontier(row.read_frontier_hash),
        );
        receipt.about = Some(*id);
        receipt.receipt_reasons = asked
            .receipt_reasons
            .iter()
            .cloned()
            .chain([crate::self_heal::tripwires::normal_baseline_token(
                &self.claim(id).predicate,
            )])
            .collect();
        receipt.context = crate::store::GateDecisionContext::linked(
            crate::store::GateLoopLink {
                family: crate::store::GateLoopFamily::Action,
                source: crate::store::GateLoopSource::Runner,
                run: Some("held-claim-restate-run".to_owned()),
                attempt: Some(attempt),
                origin: crate::store::GateLoopOrigin::SelfDecision,
                basis: None,
            },
            [],
        );
        let decision = self
            .vault
            .store
            .record_gate_receipt_in_txn(&mut wtxn, receipt)
            .unwrap();
        self.vault
            .store
            .put_pending_gate_consent_in_txn(
                &mut wtxn,
                &crate::store::PendingGateConsentRecord {
                    decision_id: decision.decision_id,
                    created_at: decision.created_at,
                    ..row
                },
            )
            .unwrap();
        wtxn.commit().unwrap();
    }
}

// S17-1 = A (Engine 19 Nov 20:31): a decay rewrites the held claim in place,
// and the owner's question follows the body it now stores.
#[test]
fn owner_approval_after_a_decay_settles_the_held_claim() {
    use crate::claim::ClaimDemotionAction;
    let held = HeldMachineClaims::open(b"held-claim-decay-root", 232);
    let id = held.propose("decayed proposal");
    let later = held.vault.now_recorded_at() + 1;
    held.vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.5,
            },
            later,
        )
        .unwrap();
    assert!(
        held.tray_row(&id).is_some(),
        "the decayed claim is still asked"
    );
    held.approve_as_owner(id).unwrap();
    assert_eq!(held.claim(&id).approval, ClaimApprovalStatus::Approved);
    assert!(held.tray_row(&id).is_none());
}

// S17-1 = A: the Dreamer's weakening supersedes a held claim; the old row
// goes silently and the owner answers the weakened successor instead.
#[test]
fn dreamer_weakening_of_a_held_claim_moves_the_owner_question_to_its_successor() {
    use crate::claim::{ClaimDemotionAction, ClaimDemotionRung, ClaimLifecycleStatus};
    let held = HeldMachineClaims::open(b"held-claim-weaken-root", 233);
    let id = held.propose("weakened proposal");
    let opener = held.asked(&id);
    let later = held.vault.now_recorded_at() + 1;
    held.vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.5,
            },
            later,
        )
        .unwrap();
    held.vault
        .provision_engine_machine_identities(&held.issuer)
        .unwrap();
    let weakened = held
        .vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Weaken {
                new_confidence: 0.5,
            },
            later + 1,
        )
        .unwrap();
    assert_eq!(weakened.rung, ClaimDemotionRung::Weakened);
    let successor = weakened.claim;
    assert_eq!(held.claim(&id).lifecycle, ClaimLifecycleStatus::Superseded);
    assert!(
        held.tray_row(&id).is_none(),
        "the superseded claim keeps no question"
    );
    let row = held
        .tray_row(&successor)
        .expect("the owner is asked about the weakened successor");
    assert_eq!(row.predicate.as_deref(), Some("profile.color"));
    let restated = held.asked(&successor);
    assert_eq!(
        (restated.actor_class.as_str(), restated.actor_ref.as_deref()),
        (opener.actor_class.as_str(), opener.actor_ref.as_deref()),
        "the successor's question names the writer the owner was asked about"
    );
    assert_eq!(
        held.claim(&successor).approval,
        ClaimApprovalStatus::Proposed
    );
    held.approve_as_owner(successor).unwrap();
    assert_eq!(
        held.claim(&successor).approval,
        ClaimApprovalStatus::Approved
    );
    assert!(held.tray_row(&successor).is_none());
}

// S17-1 = A: a plain supersession of a held claim closes its row silently;
// the owner keeps one answerable item, the superseding proposal's own.
#[test]
fn plain_supersession_of_a_held_claim_leaves_one_answerable_item() {
    use crate::claim::ClaimLifecycleStatus;
    let held = HeldMachineClaims::open(b"held-claim-supersede-root", 234);
    let old = held.propose("first proposal");
    let new = held.propose("second proposal");
    let later = held.vault.now_recorded_at() + 1;
    held.vault.supersede_claim(&new, &old, later).unwrap();
    assert_eq!(held.claim(&old).lifecycle, ClaimLifecycleStatus::Superseded);
    assert!(
        held.tray_row(&old).is_none(),
        "the closed claim keeps no question"
    );
    assert!(held.tray_row(&new).is_some());
    held.approve_as_owner(new).unwrap();
    assert_eq!(held.claim(&new).approval, ClaimApprovalStatus::Approved);
    assert!(held.tray_row(&new).is_none());
}

// S17-1 = A, review round 1: a restated question is the same question. Its
// receipt names the writer the asked decision named (the bundle settle door
// reads it as the opener) and keeps the checker's explanation the owner reads.
#[test]
fn a_restated_owner_question_keeps_its_writer_and_checker_reasons() {
    use crate::claim::ClaimDemotionAction;
    let held = HeldMachineClaims::open(b"held-claim-restate-root", 235);
    let id = held.propose("checked proposal");
    held.hold_with_checker_reason(&id, "checker_hedged_low_confidence");
    let before = held.asked(&id);
    assert!(
        before.actor_ref.is_some(),
        "the MACHINE's held write names its writer"
    );
    let later = held.vault.now_recorded_at() + 1;
    held.vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.5,
            },
            later,
        )
        .unwrap();
    let after = held.asked(&id);
    assert_ne!(
        after.decision_id, before.decision_id,
        "the decay restates the question"
    );
    assert_eq!(
        (after.actor_class.as_str(), after.actor_ref.as_deref()),
        (before.actor_class.as_str(), before.actor_ref.as_deref()),
        "the restated question names the asked writer"
    );
    assert!(
        after
            .receipt_reasons
            .iter()
            .any(|reason| reason == "checker_hedged_low_confidence"),
        "the checker's explanation survives: {:?}",
        after.receipt_reasons
    );
    // Review round 2: every asked reason but the drift tripwire's token for
    // the agent's own write (a restatement is no new write).
    let asked_reasons: Vec<String> = before
        .receipt_reasons
        .iter()
        .filter(|reason| crate::self_heal::tripwires::normal_baseline_predicate(reason).is_none())
        .cloned()
        .collect();
    assert_eq!(after.receipt_reasons, asked_reasons);
}

// S17-1 = A, review round 2: the restated question answers the asked decision
// inside its loop, so a job-filtered receipt read still finds the runner's
// attempt (and so does the owner's answer, which carries the restated links),
// and it is no second write by the agent: the drift tripwire's normal-baseline
// token stays on the asked receipt only, while the checker's reason moves on.
#[test]
fn a_restated_owner_question_keeps_its_loop_attempt_and_is_no_new_agent_write() {
    use crate::claim::ClaimDemotionAction;
    let held = HeldMachineClaims::open(b"held-claim-restate-loop-root", 236);
    let id = held.propose("looped proposal");
    let attempt = [0x4a; 16];
    held.hold_from_runner_attempt(&id, "checker_hedged_low_confidence", attempt);
    let before = held.asked(&id);
    let baseline = crate::self_heal::tripwires::normal_baseline_token(&held.claim(&id).predicate);
    assert!(before.receipt_reasons.contains(&baseline));
    let job_ref = crate::store::gate_receipt::gate_decision_receipt(&before).job_ref;
    assert!(job_ref.is_some(), "the asked write names its attempt");
    let later = held.vault.now_recorded_at() + 1;
    held.vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.5,
            },
            later,
        )
        .unwrap();
    let after = held.asked(&id);
    assert_ne!(
        after.decision_id, before.decision_id,
        "the decay restates the question"
    );
    assert_eq!(
        after.context.links,
        crate::store::GateDecisionContext::answering(&before).links,
        "the restated question keeps the asked loop links, based on the asked decision"
    );
    assert_eq!(
        crate::store::gate_receipt::gate_decision_receipt(&after).job_ref,
        job_ref,
        "a job-filtered receipt read finds the restated question"
    );
    assert!(
        !after.receipt_reasons.contains(&baseline),
        "a restatement is no new agent write: {:?}",
        after.receipt_reasons
    );
    assert!(
        after
            .receipt_reasons
            .iter()
            .any(|reason| reason == "checker_hedged_low_confidence"),
        "the checker's explanation survives: {:?}",
        after.receipt_reasons
    );
}

#[test]
fn signing_and_materialization_share_birth_facet_across_default_change() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let issuer = HostSlipIssuer::from_secret(b"machine-facet-root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let owner = crate::vault::embedded_owner_actor_id().unwrap();
    let parent = *vault
        .authority_fold()
        .unwrap()
        .append_heads
        .iter()
        .next_back()
        .unwrap();
    let owner_bind = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            2,
            vec![parent],
            AuthorityOp::BindActor {
                authority_key: issuer.public_key(),
                actor_ref: owner,
                actor_class: "human".into(),
                epoch: 1,
            },
            2,
        )
        .unwrap();
    let at = TimeRange { start: 10, end: 10 };
    vault.put_authority_log_entry(&owner_bind, at, 10).unwrap();
    let machine = EntityId::now();
    vault
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            10,
            b"machine",
        )
        .unwrap();
    let signing = ed_key(232);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [33; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .unwrap();
    let mask = EntityId::now();
    let replacement_mask = EntityId::now();
    let explicit_mask = EntityId::now();
    for facet in [mask, replacement_mask, explicit_mask] {
        vault
            .put_entity(&facet, crate::registry::ENTITY_TYPE_FACET, at, 10, b"mask")
            .unwrap();
    }
    let owner_actor = WriteActor::new(owner, EdgeActorClass::Human);
    vault.set_default_facet(mask, owner_actor).unwrap();
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("facet author")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "profile.color",
        ClaimSubject::Entity(machine),
        Value::from("blue"),
        1.0,
    );
    let id = EntityId::now();
    let transcript = vault
        .machine_claim_transcript(&id, &candidate, &envelope)
        .unwrap();
    let signed = envelope
        .clone()
        .with_machine_signature(MachineWriteSignature {
            public_key: signing.verifying_key().to_bytes(),
            signature: signing.sign(&transcript).to_bytes(),
        });
    vault
        .batch()
        .claim_candidate(&id, candidate.clone(), &signed, at, 10)
        .commit()
        .unwrap();
    assert_eq!(vault.get_claim(&id).unwrap().unwrap().scope_facet, mask);
    vault
        .set_default_facet(replacement_mask, owner_actor)
        .unwrap();
    assert_eq!(
        vault
            .machine_claim_transcript(&id, &candidate, &envelope)
            .unwrap(),
        transcript,
        "an existing claim keeps its first facet when the default changes"
    );
    let explicit = candidate.with_scope(Value::Map(vec![(
        Value::from("facet"),
        Value::Binary(explicit_mask.as_bytes().to_vec()),
    )]));
    let explicit_id = EntityId::now();
    let explicit_transcript = vault
        .machine_claim_transcript(&explicit_id, &explicit, &envelope)
        .unwrap();
    let signed_explicit = envelope
        .clone()
        .with_machine_signature(MachineWriteSignature {
            public_key: signing.verifying_key().to_bytes(),
            signature: signing.sign(&explicit_transcript).to_bytes(),
        });
    vault
        .batch()
        .claim_candidate(&explicit_id, explicit.clone(), &signed_explicit, at, 10)
        .commit()
        .unwrap();
    assert_eq!(
        vault.get_claim(&explicit_id).unwrap().unwrap().scope_facet,
        explicit_mask
    );
    vault.set_default_facet(mask, owner_actor).unwrap();
    assert_eq!(
        vault
            .machine_claim_transcript(&explicit_id, &explicit, &envelope)
            .unwrap(),
        explicit_transcript,
        "explicit nondefault facet survives another default change"
    );
}

/// A same-id successor closes the signed history with a `SupersedeClose` in
/// its author's name and then owns the live row. Another actor's row cannot
/// replace it, and a local erasure takes the signed history with the claim.
#[test]
fn same_id_successor_supersedes_signed_history_and_erasure_takes_it() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    // The engine's projector signs with its host-held key and holds the
    // default manifest's auto grant, so its birth needs no consent.
    crate::test_util::provision_engine_machines(&vault);
    let at = TimeRange { start: 10, end: 10 };
    let mut signed = crate::commitment_schedule::commitment_projection_envelope().unwrap();
    let machine = signed.actor().entity_ref();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    crate::test_util::bind_test_owner(&vault, owner);
    let stranger = EntityId::now();
    vault
        .put_entity(
            &stranger,
            crate::registry::ENTITY_TYPE_PERSON,
            at,
            10,
            b"stranger",
        )
        .unwrap();
    let candidate = |value: &str| {
        ClaimCandidate::new(
            "profile.color",
            ClaimSubject::Entity(machine),
            Value::from(value),
            1.0,
        )
    };
    let by = |actor| {
        WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("person")).unwrap(),
            ClaimApprovalStatus::Auto,
        )
    };

    let id = EntityId::now();
    {
        let txn = vault.store.env.read_txn().unwrap();
        vault
            .sign_retained_machine_claim_in_txn(&txn, &id, &candidate("blue"), &mut signed)
            .unwrap();
    }
    assert!(signed.machine_signature().is_some());
    vault
        .batch()
        .claim_candidate(&id, candidate("blue"), &signed, at, 10)
        .commit()
        .unwrap();

    vault
        .batch()
        .claim_candidate(&id, candidate("green"), &by(owner), at, 20)
        .commit()
        .unwrap();
    let resolved = vault.resolved_machine_claim(id).unwrap();
    assert_eq!(
        resolved.current.lifecycle,
        crate::claim::ClaimLifecycleStatus::Superseded
    );
    assert_eq!(resolved.signed_origin.value, Value::from("blue"));
    let live = vault.get_claim(&id).unwrap().unwrap();
    assert_eq!(live.value, Value::from("green"));
    assert_eq!(crate::memory::claim_author(&live), Some(owner));

    assert!(
        vault
            .batch()
            .claim_candidate(&id, candidate("red"), &by(stranger), at, 30)
            .commit()
            .is_err(),
        "only the actor that superseded the signed history owns its row"
    );
    assert_eq!(
        vault.get_claim(&id).unwrap().unwrap().value,
        Value::from("green")
    );

    vault.batch().delete(&id).commit().unwrap();
    assert!(vault.get_claim(&id).unwrap().is_none());
    let txn = vault.store.env.read_txn().unwrap();
    assert!(
        crate::claim::history_store::machine_history_ids_for_target(&vault.store, &txn, id)
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(&txn, &crate::claim::history_projection::pin_key(id))
            .unwrap()
            .is_none()
    );
}
