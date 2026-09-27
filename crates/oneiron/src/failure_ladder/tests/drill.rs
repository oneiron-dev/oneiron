//! Retrospective owner drill-in binds the caller, group, trace and receipt.
use super::*;
use crate::attempt_queue::{ManifestEntry, ManifestKind};
use crate::error::{Error, GateError};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::GateDecisionId;

fn embedded_owner(vault: &Vault) -> Result<crate::consent::AuthenticatedOwner> {
    let id = vault.ensure_embedded_owner_actor().expect("seed owner");
    vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
}

/// The public runner's valid custom-dispatch envelope without the higher-level
/// dispatcher skill-index stamp. This exercises a genuinely empty manifest.
fn bare_custom_dispatch(vault: &Vault, agent: EntityId, now: u64) -> Result<AttemptRecord> {
    use crate::agent_dispatch::{
        AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, encode_agent_dispatch_input,
    };

    let definition = vault
        .get_agent_definition(&agent)?
        .ok_or(Error::EntityNotFound)?;
    let input = AgentDispatchInput::frozen(AgentDispatchTarget::Custom(agent), definition);
    let EnqueueDreamerAttemptOutcome::Enqueued(status) =
        DreamerRunnerStore::new(vault).enqueue(EnqueueDreamerAttempt {
            attempt_type: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
            input: encode_agent_dispatch_input(&input)?,
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(RUN_ID.to_owned()),
            now,
        })?
    else {
        panic!("expected a fresh custom dispatch");
    };
    claim(vault, status.attempt.id, now)
}

fn person(vault: &Vault, seed: u8) -> Result<crate::consent::AuthenticatedOwner> {
    let id = test_id(seed);
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
}

#[test]
fn owner_drills_from_group_to_own_traces_and_receipts_without_consent_while_non_owner_is_denied()
-> Result<()> {
    let (_dir, vault) = open_vault();
    let (_other_dir, other) = open_vault();
    let owner_id = vault.ensure_embedded_owner_actor().expect("seed owner");
    let other_owner_id = other.ensure_embedded_owner_actor().expect("seed owner");
    assert_eq!(owner_id, other_owner_id);
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let non_owner = person(&vault, 0xb4)?;
    // A proof from another vault, even for the same owner actor id, cannot
    // cross the vault boundary.
    let foreign_owner = other.authenticate_owner(
        other_owner_id,
        &other_owner_id.to_hex(),
        true,
        GateDecisionId::now(),
    )?;
    let agent = put_scope_agent(&vault, 0xb5, "custom.trace")?;
    let leased = leased_dispatch(&vault, agent, 10)?;
    AttemptQueue::new(&vault).append_manifest_entry(
        leased.id,
        ManifestEntry::new(ManifestKind::Skill, "skill.trace", "1", 11),
    )?;
    // A Skill entry is receipt-bearing only with its executor (#1132).
    AttemptQueue::new(&vault).set_executor_model(
        leased.id,
        LEASE_OWNER,
        leased.attempt_count,
        "fixture/model@1",
    )?;
    let FailureLadderOutcome::Human(surface) = FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, indeterminate(), 20),
        policy_with(agent, 3, FailureEscalationMode::Human),
    )?
    else {
        panic!("expected surfaced failure");
    };
    assert_eq!(surface.failed_attempt.id, leased.id);
    let class = FailureSignalClass::TaskFailure;
    vault.record_custom_agent_failure(leased.id, class)?;
    let group = vault.custom_agent_failure_groups()?.remove(0);
    assert_eq!(group.class, class);
    assert_eq!(group.member_refs, vec![leased.id]);
    let drill = vault.drill_custom_agent_failure(&owner, group.class, group.member_refs[0])?;
    assert_eq!(drill.trace.id, leased.id);
    assert_eq!(drill.trace.state, AttemptState::Failed);
    assert_eq!(drill.trace.run_id.as_deref(), Some(RUN_ID));
    assert_eq!(
        drill.receipt_refs,
        vec![crate::receipt::attempt_pack_receipt_id(&leased.id)]
    );
    assert!(
        crate::receipt::attempt_pack_receipt(&vault, &drill.receipt_refs[0])?.is_some(),
        "drill must not invent a dangling receipt ref"
    );
    assert!(
        vault
            .drill_custom_agent_failure(&owner, FailureSignalClass::MemoryMiss, leased.id,)
            .is_err(),
        "a caller cannot use a class from a different group"
    );
    assert!(
        other
            .drill_custom_agent_failure(&foreign_owner, class, leased.id)
            .is_err(),
        "the attempt lives only in the first vault"
    );
    assert!(matches!(
        vault.drill_custom_agent_failure(&foreign_owner, class, leased.id),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    // An authenticated human in this vault is not automatically its owner.
    assert!(matches!(
        vault.drill_custom_agent_failure(&non_owner, class, leased.id),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    Ok(())
}

/// One signed authority root, a non-bootstrap human binding, and its signed
/// revocation. The same stored failure is read before and after the revoke.
fn bind_owner_with_revocation(
    vault: &Vault,
    actor: EntityId,
) -> Result<crate::authority::AuthorityLogEntry> {
    use crate::authority::{
        AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityKey, AuthorityLogEntry,
        AuthorityOp, AuthoritySignature, AuthorityTier, DeviceAuthority, GenesisRecoveryStep,
        ROLE_ADMIN, ROLE_OWNER,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&[0x76; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let sign = |mut entry: AuthorityLogEntry| {
        entry.signer.signature = signing
            .sign(&crate::authority::authority_transcript(&entry).expect("transcript"))
            .to_bytes()
            .to_vec();
        entry
    };
    let entry = |seq, vault_id, parents, op| AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parents,
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100 + seq,
    };
    let genesis = sign(entry(
        0,
        None,
        Vec::new(),
        AuthorityOp::Genesis {
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
            genesis_nonce: [0x86; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
    ));
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let genesis_hash = crate::authority::authority_entry_hash(&genesis)?;
    let bind = sign(entry(
        1,
        Some(vault_id),
        vec![genesis_hash],
        AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: actor,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
    ));
    let bind_hash = crate::authority::authority_entry_hash(&bind)?;
    vault.put_authority_log_entries(&[
        (genesis, TimeRange { start: 1, end: 1 }, 1),
        (bind, TimeRange { start: 2, end: 2 }, 2),
    ])?;
    Ok(sign(entry(
        2,
        Some(vault_id),
        vec![bind_hash],
        AuthorityOp::RevokeActor {
            authority_key: key.clone(),
            epoch: 1,
        },
    )))
}

#[test]
fn authority_bound_owner_drills_but_unbound_and_revoked_humans_cannot() -> Result<()> {
    let (_dir, vault) = open_vault();
    let owner = person(&vault, 0xb6)?;
    let unbound = person(&vault, 0xb7)?;
    let agent = put_scope_agent(&vault, 0xb8, "custom.authority")?;
    let leased = leased_dispatch(&vault, agent, 10)?;
    FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, indeterminate(), 20),
        policy_with(agent, 3, FailureEscalationMode::Human),
    )?;
    let class = FailureSignalClass::TaskFailure;
    vault.record_custom_agent_failure(leased.id, class)?;
    // No authority root means a non-bootstrap PERSON cannot claim this read.
    assert!(matches!(
        vault.drill_custom_agent_failure(&owner, class, leased.id),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    let revoke = bind_owner_with_revocation(&vault, owner.actor())?;
    let drill = vault.drill_custom_agent_failure(&owner, class, leased.id)?;
    assert_eq!(drill.trace.id, leased.id);
    assert_eq!(
        drill.receipt_refs,
        vec![crate::receipt::attempt_pack_receipt_id(&leased.id)]
    );
    assert!(matches!(
        vault.drill_custom_agent_failure(&unbound, class, leased.id),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    vault.put_authority_log_entries(&[(revoke, TimeRange { start: 3, end: 3 }, 3)])?;
    assert!(matches!(
        vault.drill_custom_agent_failure(&owner, class, leased.id),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    Ok(())
}

#[test]
fn deleted_agent_definition_keeps_retained_failure_member_drillable() -> Result<()> {
    let (_dir, vault) = open_vault();
    let owner_id = vault.ensure_embedded_owner_actor().expect("seed owner");
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let agent = put_scope_agent(&vault, 0xb9, "custom.historical")?;
    let leased = leased_dispatch(&vault, agent, 10)?;
    AttemptQueue::new(&vault).append_manifest_entry(
        leased.id,
        ManifestEntry::new(ManifestKind::Skill, "skill.historical", "1", 11),
    )?;
    // A Skill entry is receipt-bearing only with its executor (#1132).
    AttemptQueue::new(&vault).set_executor_model(
        leased.id,
        LEASE_OWNER,
        leased.attempt_count,
        "fixture/model@1",
    )?;
    FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, indeterminate(), 20),
        policy_with(agent, 3, FailureEscalationMode::Human),
    )?;
    let class = FailureSignalClass::TaskFailure;
    vault.record_custom_agent_failure(leased.id, class)?;
    assert!(vault.delete_entity(&agent)?);
    let group = vault.custom_agent_failure_groups()?.remove(0);
    assert_eq!(group.member_refs, vec![leased.id]);
    let drill = vault.drill_custom_agent_failure(&owner, group.class, group.member_refs[0])?;
    assert_eq!(drill.trace.id, leased.id);
    assert_eq!(
        drill.receipt_refs,
        vec![crate::receipt::attempt_pack_receipt_id(&leased.id)]
    );
    Ok(())
}

#[test]
fn manifest_bearing_retry_source_stays_drillable_with_its_terminal_receipt() -> Result<()> {
    let (_dir, vault) = open_vault();
    let owner = embedded_owner(&vault)?;
    let agent = put_scope_agent(&vault, 0xba, "custom.retry")?;
    let leased = leased_dispatch(&vault, agent, 10)?;
    AttemptQueue::new(&vault).append_manifest_entry(
        leased.id,
        ManifestEntry::new(ManifestKind::Skill, "skill.retry", "1", 11),
    )?;
    // A Skill entry is receipt-bearing only with its executor (#1132).
    AttemptQueue::new(&vault).set_executor_model(
        leased.id,
        LEASE_OWNER,
        leased.attempt_count,
        "fixture/model@1",
    )?;
    let FailureLadderOutcome::Retried {
        source_attempt_id, ..
    } = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&leased, transient(), 20), auto_policy(agent))?
    else {
        panic!("expected retry source");
    };
    assert_eq!(source_attempt_id, leased.id);
    let class = FailureSignalClass::TaskFailure;
    vault.record_custom_agent_failure(source_attempt_id, class)?;
    let group = vault.custom_agent_failure_groups()?.remove(0);
    assert_eq!(group.member_refs, vec![source_attempt_id]);
    let drill = vault.drill_custom_agent_failure(&owner, group.class, source_attempt_id)?;
    assert_eq!(drill.trace.state, AttemptState::Failed);
    assert_eq!(
        drill.receipt_refs,
        vec![crate::receipt::attempt_pack_receipt_id(&source_attempt_id)]
    );
    Ok(())
}

#[test]
fn manifest_bearing_queued_cancellation_stays_drillable_with_its_receipt() -> Result<()> {
    use crate::attempt_queue::{AttemptInterventionKind, InterveneAttempt};

    let (_dir, vault) = open_vault();
    let owner = embedded_owner(&vault)?;
    let agent = put_scope_agent(&vault, 0xbb, "custom.cancel")?;
    let queued = dispatch_attempt(&vault, agent, 10)?;
    let queue = AttemptQueue::new(&vault);
    queue.append_manifest_entry(
        queued.id,
        // Queued attempts carry only the dispatcher stamp; a Skill entry needs
        // a live lease and an executor (#1132).
        ManifestEntry::new(ManifestKind::SkillIndex, "skill.cancel", "1", 11),
    )?;
    let cancelled = queue.intervene(InterveneAttempt {
        id: queued.id,
        kind: AttemptInterventionKind::Cancel,
        actor: "vault-owner".to_owned(),
        note: None,
        now: 12,
    })?;
    assert_eq!(cancelled.record.state, AttemptState::Cancelled);
    let class = FailureSignalClass::LatencyAbandon;
    vault.record_custom_agent_failure(queued.id, class)?;
    let group = vault.custom_agent_failure_groups()?.remove(0);
    assert_eq!(group.member_refs, vec![queued.id]);
    let drill = vault.drill_custom_agent_failure(&owner, group.class, queued.id)?;
    assert_eq!(drill.trace.state, AttemptState::Cancelled);
    assert_eq!(
        drill.receipt_refs,
        vec![crate::receipt::attempt_pack_receipt_id(&queued.id)]
    );
    Ok(())
}

#[test]
fn skillless_actor_bound_failure_discovers_its_stored_receipt() -> Result<()> {
    let (_dir, vault) = open_vault();
    let owner = embedded_owner(&vault)?;
    let agent = put_scope_agent(&vault, 0xbc, "custom.skillless")?;
    let leased = bare_custom_dispatch(&vault, agent, 10)?;
    assert!(leased.manifest().is_empty());
    vault.bind_actor_attempt(leased.id, &agent)?;
    FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, indeterminate(), 20),
        policy_with(agent, 3, FailureEscalationMode::Human),
    )?;
    let class = FailureSignalClass::TaskFailure;
    vault.record_custom_agent_failure(leased.id, class)?;
    let group = vault.custom_agent_failure_groups()?.remove(0);
    let drill = vault.drill_custom_agent_failure(&owner, group.class, group.member_refs[0])?;
    assert!(drill.trace.manifest().is_empty());
    let receipt_id = crate::receipt::attempt_pack_receipt_id(&leased.id);
    assert_eq!(drill.receipt_refs, vec![receipt_id.clone()]);
    assert!(crate::receipt::attempt_pack_receipt(&vault, &receipt_id)?.is_some());
    Ok(())
}
