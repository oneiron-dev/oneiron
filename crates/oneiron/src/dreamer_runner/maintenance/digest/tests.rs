use super::*;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{ClaimBody, ClaimCandidate, ClaimSubject, TimeRange, WriteEnvelope, WriteProvenance};
use rmpv::Value;
fn propose(vault: &Vault, id: u8) -> Result<EntityId> {
    propose_named(vault, id, "dreamer.proactivity.follow_up")
}
fn propose_named(vault: &Vault, id: u8, predicate: &str) -> Result<EntityId> {
    let actor = vault.dreamer_authority()?;
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("surface"),
            Value::from("dreamer"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    );
    let id = entity(id);
    vault
        .batch()
        .claim_candidate(
            &id,
            ClaimCandidate::new(
                predicate,
                ClaimSubject::Entity(actor.entity_ref()),
                Value::from("pending action"),
                0.7,
            ),
            &envelope,
            TimeRange { start: 1, end: 1 },
            1,
        )
        .commit()?;
    Ok(id)
}
#[test]
fn three_proposals_one_digest_urgent_breakthrough_and_row_timing() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x12);
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let row = ProactivityCadence {
        period_secs: 100,
        group_by_facet: true,
        urgent_breakthrough: true,
    };
    vault.set_proactivity_cadence(&owner, &row)?;
    let presentation = ProactivityPresentation {
        group_aliases: BTreeMap::from([("dreamer.proactivity".into(), "Forward".into())]),
        group_template: "{group}:\n".into(),
        item_template: "* {summary} ({ref})\n".into(),
        voice_style: "quiet".into(),
        urgent_groups: vec!["dreamer.proactivity".into()],
    };
    vault.set_proactivity_presentation(&owner, &presentation)?;
    assert_eq!(vault.next_proactivity_digest_at()?, None);
    for id in [0x21, 0x22, 0x23] {
        propose(&vault, id)?;
    }
    assert_eq!(vault.next_proactivity_digest_at()?, Some(0));
    let digest = vault.proactivity_digest(&owner, 100, None)?.unwrap();
    assert_eq!(digest.voice_style, "quiet");
    assert!(
        digest
            .rendered
            .starts_with("Forward:\n* dreamer.proactivity.follow_up:")
    );
    assert_eq!(digest.groups.len(), 1);
    assert_eq!(digest.groups.values().map(Vec::len).sum::<usize>(), 3);
    assert!(!digest.urgent);
    assert_eq!(
        vault.read_proactivity_digest(digest.id)?,
        Some(digest.clone())
    );
    assert_eq!(vault.latest_proactivity_digest()?, Some(digest));
    propose(&vault, 0x24)?;
    assert_eq!(vault.next_proactivity_digest_at()?, Some(200));
    assert!(vault.proactivity_digest(&owner, 101, None)?.is_none());
    let intent_id = entity(0x31);
    let mut intent = ClaimBody::new(
        "profile.intent",
        ClaimSubject::Entity(owner_id),
        Value::from("time-sensitive follow-up"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    intent.source = Some(ClaimSource::UserStated);
    vault.put_claim(&intent_id, &intent, TimeRange { start: 1, end: 1 }, 1)?;
    let urgent = UrgentDigestWake {
        intent_ref: intent_id,
        needed_before: 150,
        waiting_harms_intent: true,
    };
    vault.put_entity(
        &entity(0x32),
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"other owner",
    )?;
    for change in 0..4 {
        let mut unrelated = intent.clone();
        match change {
            0 => unrelated.predicate = "profile.hobby".into(),
            1 => unrelated.subject = ClaimSubject::Entity(entity(0x32)),
            2 => unrelated.source = Some(ClaimSource::Generated),
            _ => unrelated.value = Value::Nil,
        }
        vault.put_claim(&intent_id, &unrelated, TimeRange { start: 1, end: 1 }, 1)?;
        assert!(
            vault
                .proactivity_digest(&owner, 102, Some(&urgent))?
                .is_none()
        );
    }
    vault.put_claim(&intent_id, &intent, TimeRange { start: 1, end: 1 }, 1)?;
    let breakthrough = vault
        .proactivity_digest(&owner, 102, Some(&urgent))?
        .unwrap();
    assert!(breakthrough.urgent);
    assert_eq!(breakthrough.groups.values().map(Vec::len).sum::<usize>(), 1);
    propose(&vault, 0x25)?;
    assert!(vault.proactivity_digest(&owner, 107, None)?.is_none());
    assert_eq!(vault.next_proactivity_digest_at()?, Some(200));
    vault.set_proactivity_cadence(
        &owner,
        &ProactivityCadence {
            period_secs: 5,
            ..row
        },
    )?;
    assert_eq!(vault.next_proactivity_digest_at()?, Some(105));
    let retimed = vault.proactivity_digest(&owner, 107, None)?.unwrap();
    assert!(!retimed.urgent);
    assert_eq!(retimed.groups.values().map(Vec::len).sum::<usize>(), 1);
    Ok(())
}

#[test]
fn policy_row_rejects_invalid_templates_and_disables_unpicked_breakthrough() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x51);
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let mut row = ProactivityPresentation {
        group_aliases: BTreeMap::new(),
        group_template: "{group}\n".into(),
        item_template: "{summary} [{ref}]\n".into(),
        voice_style: "neutral".into(),
        urgent_groups: vec![],
    };
    row.item_template = "no reference".into();
    assert!(vault.set_proactivity_presentation(&owner, &row).is_err());
    row.item_template = "{summary} [{ref}]\n".into();
    vault.set_proactivity_presentation(&owner, &row)?;
    vault.set_proactivity_cadence(
        &owner,
        &ProactivityCadence {
            period_secs: 100,
            group_by_facet: true,
            urgent_breakthrough: true,
        },
    )?;
    propose(&vault, 0x52)?;
    vault.proactivity_digest(&owner, 100, None)?.unwrap();
    propose(&vault, 0x53)?;
    let intent_id = entity(0x54);
    let mut intent = ClaimBody::new(
        "profile.intent",
        ClaimSubject::Entity(owner_id),
        Value::from("urgent"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    intent.source = Some(ClaimSource::UserStated);
    vault.put_claim(&intent_id, &intent, TimeRange { start: 1, end: 1 }, 1)?;
    let wake = UrgentDigestWake {
        intent_ref: intent_id,
        needed_before: 150,
        waiting_harms_intent: true,
    };
    assert!(
        vault
            .proactivity_digest(&owner, 101, Some(&wake))?
            .is_none()
    );
    assert_eq!(vault.next_proactivity_digest_at()?, Some(200));
    Ok(())
}

#[test]
fn repeated_urgent_groups_do_not_postpone_the_ordinary_group() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x61);
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.set_proactivity_cadence(
        &owner,
        &ProactivityCadence {
            period_secs: 100,
            group_by_facet: true,
            urgent_breakthrough: true,
        },
    )?;
    propose(&vault, 0x62)?;
    vault.proactivity_digest(&owner, 100, None)?.unwrap();
    propose_named(&vault, 0x63, "dreamer.ordinary.follow_up")?;
    let intent_id = entity(0x64);
    let mut intent = ClaimBody::new(
        "profile.intent",
        ClaimSubject::Entity(owner_id),
        Value::from("prompt response"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    intent.source = Some(ClaimSource::UserStated);
    vault.put_claim(&intent_id, &intent, TimeRange { start: 1, end: 1 }, 1)?;
    let urgent = UrgentDigestWake {
        intent_ref: intent_id,
        needed_before: 199,
        waiting_harms_intent: true,
    };
    for (seed, now) in [(0x65, 190), (0x66, 195)] {
        propose(&vault, seed)?;
        let digest = vault
            .proactivity_digest(&owner, now, Some(&urgent))?
            .unwrap();
        assert!(digest.urgent);
        assert!(digest.groups.contains_key("dreamer.proactivity"));
        assert!(!digest.groups.contains_key("dreamer.ordinary"));
        assert_eq!(vault.next_proactivity_digest_at()?, Some(200));
    }
    let regular = vault.proactivity_digest(&owner, 200, None)?.unwrap();
    assert!(!regular.urgent);
    assert_eq!(regular.groups["dreamer.ordinary"].len(), 1);
    Ok(())
}

#[test]
fn agent_memory_request_requires_exact_owner_confirmation_before_policy_changes() -> Result<()> {
    use crate::code_run::{
        GatedActorWrite, SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfMemoryPutClaimCall,
        SelfMemoryWriteResult,
    };
    use crate::{EdgeActorClass, WriteActor};
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x75);
    let agent_id = entity(0x76);
    for id in [owner_id, agent_id] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    propose(&vault, 0x77)?;
    vault.proactivity_digest(&owner, 100, None)?.unwrap();
    propose(&vault, 0x78)?;
    assert_eq!(vault.next_proactivity_digest_at()?, Some(100 + 86_400));
    let request = ProactivityPolicyRequest {
        cadence: ProactivityCadence {
            period_secs: 5,
            group_by_facet: true,
            urgent_breakthrough: false,
        },
        presentation: ProactivityPresentation {
            group_aliases: BTreeMap::from([("dreamer.proactivity".into(), "Next".into())]),
            group_template: "{group}\n".into(),
            item_template: "{summary} [{ref}]\n".into(),
            voice_style: "gentle".into(),
            urgent_groups: vec![],
        },
    };
    let claim_ref = entity(0x79);
    let dispatcher = GatedActorWrite::new(
        &vault,
        WriteActor::new(agent_id, EdgeActorClass::Agent),
        "policy-chat-request",
    )?;
    let result = dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        claim_ref,
        ClaimCandidate::new(
            PROACTIVITY_POLICY_REQUEST_PREDICATE,
            ClaimSubject::Entity(owner_id),
            Value::from(request.claim_value()?),
            0.9,
        ),
        TimeRange {
            start: 101,
            end: 101,
        },
        101,
    )))?;
    assert_eq!(
        result,
        SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: claim_ref })
    );
    // The agent's gated claim is just a request. Neither metadata row moved.
    assert_eq!(vault.next_proactivity_digest_at()?, Some(100 + 86_400));
    let proposal = vault.proactivity_policy_proposal(&owner, claim_ref)?;
    assert_eq!(proposal.request, request);
    assert!(
        vault
            .confirm_proactivity_policy_proposal(&owner, claim_ref, [0; 32])
            .is_err()
    );
    assert!(
        vault
            .authenticate_owner(
                owner_id,
                &owner_id.to_hex(),
                false,
                crate::store::GateDecisionId::now()
            )
            .is_err()
    );
    let other = vault.authenticate_owner(
        agent_id,
        &agent_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    assert!(
        vault
            .confirm_proactivity_policy_proposal(&other, claim_ref, proposal.revision)
            .is_err()
    );
    assert_eq!(vault.next_proactivity_digest_at()?, Some(100 + 86_400));
    vault.confirm_proactivity_policy_proposal(&owner, claim_ref, proposal.revision)?;
    assert!(
        vault
            .confirm_proactivity_policy_proposal(&owner, claim_ref, proposal.revision)
            .is_err()
    );
    assert_eq!(vault.next_proactivity_digest_at()?, Some(105));
    let digest = vault.proactivity_digest(&owner, 105, None)?.unwrap();
    assert_eq!(digest.voice_style, "gentle");
    assert!(digest.rendered.starts_with("Next\n"));
    Ok(())
}
