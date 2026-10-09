use super::*;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{ClaimCandidate, ClaimSubject, TimeRange, WriteEnvelope, WriteProvenance};
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
    let candidate = ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(actor.entity_ref()),
        Value::from("pending action"),
        0.7,
    );
    let envelope = crate::test_util::sign_machine_candidate(vault, &id, &candidate, &envelope);
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, TimeRange { start: 1, end: 1 }, 1)
        .commit()?;
    Ok(id)
}

#[test]
fn agent_memory_request_requires_exact_owner_confirmation_before_policy_changes() -> Result<()> {
    use crate::code_run::{
        GatedActorWrite, SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfMemoryPutClaimCall,
        SelfMemoryWriteResult,
    };
    use crate::{EdgeActorClass, WriteActor};
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    crate::test_util::provision_engine_machines(&vault);
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

#[test]
fn calibration_asks_batch_under_minutes_and_only_human_picks_label() -> Result<()> {
    use crate::skill_optimize::{
        ask_judge_disagreement, ask_judge_uncertainty, judge_label_anchor, record_judge_pick,
        set_judge_digest_minutes,
    };
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    crate::test_util::provision_engine_machines(&vault);
    let person = entity(0x61);
    let other = entity(0x62);
    let skill = entity(0x63);
    for id in [person, other] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )?;
    }
    let skill_record = crate::skill::SkillRecord::new(
        "oneiron.skill.calibration",
        "Judge calibration instructions.",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        crate::skill::SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.5,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("test"))]),
    );
    vault.put_skill_record(&skill, &skill_record, TimeRange { start: 1, end: 1 }, 1)?;
    let owner = vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let other_owner = vault.authenticate_owner(
        other,
        &other.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let first = ask_judge_disagreement(
        &vault,
        skill,
        person,
        "campaign-1",
        "case-1",
        "old answer",
        "new answer",
    )?;
    let second = ask_judge_uncertainty(
        &vault,
        skill,
        person,
        "campaign-1",
        "case-2",
        "choice A",
        "choice B",
    )?;
    assert_ne!(first.id, second.id);
    assert_eq!(
        ask_judge_disagreement(
            &vault,
            skill,
            person,
            "campaign-1",
            "case-1",
            "old answer",
            "new answer"
        )?,
        first
    );
    assert!(judge_label_anchor(&vault, skill, "campaign-1")?.is_empty());
    assert!(record_judge_pick(&vault, &owner, first.id, false, 3).is_err());
    assert!(vault.proactivity_digest(&owner, 10, None)?.is_none());
    set_judge_digest_minutes(&vault, &owner, 1)?;
    let digest = vault.proactivity_digest(&owner, 11, None)?.unwrap();
    assert_eq!(digest.judge_asks.len(), 1);
    assert_eq!(
        vault.read_proactivity_digest(digest.id)?,
        Some(digest.clone())
    );
    let delivered = digest.judge_asks[0].id;
    assert!(record_judge_pick(&vault, &other_owner, delivered, false, 12).is_err());
    let picked = record_judge_pick(&vault, &owner, delivered, false, 12)?;
    assert_eq!(
        record_judge_pick(&vault, &owner, delivered, false, 13)?,
        picked
    );
    assert!(record_judge_pick(&vault, &owner, delivered, true, 14).is_err());
    assert_eq!(
        judge_label_anchor(&vault, skill, "campaign-1")?,
        vec![picked]
    );
    vault.set_proactivity_cadence(
        &owner,
        &ProactivityCadence {
            period_secs: 1,
            group_by_facet: false,
            urgent_breakthrough: false,
        },
    )?;
    assert!(vault.proactivity_digest(&owner, 12, None)?.is_none());
    set_judge_digest_minutes(&vault, &owner, 1)?;
    let later = vault.proactivity_digest(&owner, 13, None)?.unwrap();
    assert_eq!(later.judge_asks.len(), 1);
    assert_ne!(later.judge_asks[0].id, delivered);
    assert!(vault.proactivity_digest(&owner, 14, None)?.is_none());
    record_judge_pick(&vault, &owner, later.judge_asks[0].id, true, 15)?;
    assert_eq!(judge_label_anchor(&vault, skill, "campaign-1")?.len(), 2);
    Ok(())
}

fn calibration_fixture(vault: &Vault, skill: EntityId, people: &[EntityId]) -> Result<()> {
    for person in people {
        vault.put_entity(
            person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )?;
    }
    vault.put_skill_record(
        &skill,
        &crate::skill::SkillRecord::new(
            "oneiron.skill.calibration",
            "Calibration.",
            "1.0.0",
            ClaimApprovalStatus::Approved,
            crate::skill::SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            0.5,
            false,
            true,
            Vec::new(),
            Value::Map(vec![(Value::from("source"), Value::from("test"))]),
        ),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    Ok(())
}

fn calibration_owner(
    vault: &Vault,
    person: EntityId,
) -> Result<crate::consent::AuthenticatedOwner> {
    vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )
}

#[test]
fn deleted_or_archived_owner_cannot_pick_or_refund_a_delivered_ask() -> Result<()> {
    use crate::skill_optimize::{
        ask_judge_uncertainty, judge_label_anchor, record_judge_pick, set_judge_digest_minutes,
    };
    for archived in [false, true] {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        crate::test_util::provision_engine_machines(&vault);
        let person = entity(0x66);
        let skill = entity(0x67);
        calibration_fixture(&vault, skill, &[person])?;
        let owner = calibration_owner(&vault, person)?;
        let ask = ask_judge_uncertainty(&vault, skill, person, "run", "case", "yes", "no")?;
        set_judge_digest_minutes(&vault, &owner, 3)?;
        assert_eq!(
            vault
                .proactivity_digest(&owner, 10, None)?
                .unwrap()
                .judge_asks
                .len(),
            1
        );
        let key = [
            b"settings:skill_optimize:judge_minutes:v1:".as_slice(),
            person.as_bytes(),
        ]
        .concat();
        let before = {
            let txn = vault.store.env.read_txn()?;
            vault.store.vault_meta.get(&txn, &key)?.unwrap().to_vec()
        };
        if archived {
            vault.with_write_txn(|txn| {
                let marker = crate::deletion::TombstoneValueV2 {
                    reason: crate::deletion::TombstoneReason::ArchivedByCleanup,
                    deleted_at: 20,
                    request_id: [0x79; 16],
                };
                vault.store.sync_state.put(
                    txn,
                    &format!("ac:{}", person.to_hex()),
                    &marker.encode(),
                )?;
                Ok(())
            })?;
        } else {
            vault.delete_entity_with_reason(&person, crate::deletion::DeleteReason::UserDelete)?;
        }
        assert_eq!(
            record_judge_pick(&vault, &owner, ask.id, false, 20)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::ConsentOwnerNotAuthenticated
        );
        assert_eq!(
            set_judge_digest_minutes(&vault, &owner, 100)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::ConsentOwnerNotAuthenticated
        );
        let txn = vault.store.env.read_txn()?;
        assert_eq!(
            vault.store.vault_meta.get(&txn, &key)?.unwrap().as_ref(),
            before
        );
        drop(txn);
        assert!(judge_label_anchor(&vault, skill, "run")?.is_empty());
    }
    Ok(())
}
