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
    )?;
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

#[test]
fn calibration_asks_batch_under_minutes_and_only_human_picks_label() -> Result<()> {
    use crate::skill_optimize::{
        ask_judge_disagreement, ask_judge_uncertainty, judge_label_anchor, record_judge_pick,
        set_judge_digest_minutes,
    };
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
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

#[test]
fn every_funded_recipient_has_an_independent_digest_cadence() -> Result<()> {
    use crate::skill_optimize::{ask_judge_uncertainty, set_judge_digest_minutes};
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (a, b, skill) = (entity(0x68), entity(0x69), entity(0x70));
    calibration_fixture(&vault, skill, &[a, b])?;
    let (owner_a, owner_b) = (calibration_owner(&vault, a)?, calibration_owner(&vault, b)?);
    set_judge_digest_minutes(&vault, &owner_a, 2)?;
    set_judge_digest_minutes(&vault, &owner_b, 2)?;
    vault.set_proactivity_cadence(
        &owner_a,
        &ProactivityCadence {
            period_secs: 10,
            group_by_facet: false,
            urgent_breakthrough: false,
        },
    )?;
    for n in 0..2 {
        let at = 10 + n * 10;
        let evidence = format!("case-{n}");
        let ask_a = ask_judge_uncertainty(&vault, skill, a, "run", &evidence, "yes", "no")?;
        let ask_b = ask_judge_uncertainty(&vault, skill, b, "run", &evidence, "yes", "no")?;
        if n > 0 {
            // Each recipient's own mark holds its pending ask until the boundary.
            assert!(vault.proactivity_digest(&owner_a, at - 5, None)?.is_none());
            assert!(vault.proactivity_digest(&owner_b, at - 5, None)?.is_none());
        }
        let first = vault.proactivity_digest(&owner_a, at, None)?.unwrap();
        let second = vault.proactivity_digest(&owner_b, at, None)?.unwrap();
        assert_eq!(first.recipient, Some(a));
        assert_eq!(second.recipient, Some(b));
        let ids = |digest: &ProactivityDigest| {
            digest
                .judge_asks
                .iter()
                .map(|ask| ask.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&first), vec![ask_a.id]);
        assert_eq!(ids(&second), vec![ask_b.id]);
        assert_ne!(first.id, second.id);
        assert_eq!(vault.read_proactivity_digest(first.id)?, Some(first));
        assert_eq!(vault.read_proactivity_digest(second.id)?, Some(second));
    }
    assert!(vault.proactivity_digest(&owner_a, 30, None)?.is_none());
    assert!(vault.proactivity_digest(&owner_b, 30, None)?.is_none());
    Ok(())
}

fn set_calibration_manifest(vault: &Vault, cost: u32, limit: u32) -> Result<()> {
    let mut cursor = std::io::Cursor::new(crate::gate::default_policy_manifest());
    let Value::Map(ref mut entries) = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| crate::Error::InvalidConfig("test manifest".into()))?
    else {
        unreachable!()
    };
    for (key, value) in entries.iter_mut() {
        if key.as_str() == Some(crate::skill_optimize::policy::MANIFEST_KEY) {
            *value = Value::Map(vec![
                (Value::from("ask_minutes"), Value::from(cost)),
                (Value::from("max_context_bytes"), Value::from(limit)),
            ]);
        }
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries.clone()))
        .map_err(|_| crate::Error::InvalidConfig("test manifest".into()))?;
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

#[test]
fn manifest_cost_and_context_limit_narrow_questions_and_debits() -> Result<()> {
    use crate::skill_optimize::{ask_judge_uncertainty, set_judge_digest_minutes};
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (person, skill) = (entity(0x72), entity(0x73));
    calibration_fixture(&vault, skill, &[person])?;
    let owner = calibration_owner(&vault, person)?;
    set_calibration_manifest(&vault, 2, 16)?;
    assert!(
        ask_judge_uncertainty(
            &vault,
            skill,
            person,
            "run",
            "case",
            "long-answer-over-16",
            "no"
        )
        .is_err()
    );
    let first = ask_judge_uncertainty(&vault, skill, person, "run", "case-a", "yes", "no")?;
    let second = ask_judge_uncertainty(&vault, skill, person, "run", "case-b", "yes", "no")?;
    set_judge_digest_minutes(&vault, &owner, 3)?;
    let digest = vault.proactivity_digest(&owner, 10, None)?.unwrap();
    assert_eq!(digest.judge_asks.len(), 1);
    assert!([first.id, second.id].contains(&digest.judge_asks[0].id));
    vault.set_proactivity_cadence(
        &owner,
        &ProactivityCadence {
            period_secs: 1,
            group_by_facet: false,
            urgent_breakthrough: false,
        },
    )?;
    assert!(vault.proactivity_digest(&owner, 11, None)?.is_none());
    set_calibration_manifest(&vault, 3, 8)?;
    assert!(
        ask_judge_uncertainty(&vault, skill, person, "campaign-long", "case", "yes", "no").is_err()
    );
    set_judge_digest_minutes(&vault, &owner, 3)?;
    let later = vault.proactivity_digest(&owner, 12, None)?.unwrap();
    assert_eq!(later.judge_asks.len(), 1);
    assert_ne!(later.judge_asks[0].id, digest.judge_asks[0].id);
    assert!(vault.proactivity_digest(&owner, 13, None)?.is_none());
    Ok(())
}

#[test]
fn timer_digest_has_no_recipient_and_leaves_judge_asks_pending() -> Result<()> {
    use crate::skill_optimize::{ask_judge_uncertainty, set_judge_digest_minutes};
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (person, skill) = (entity(0x74), entity(0x77));
    calibration_fixture(&vault, skill, &[person])?;
    let owner = calibration_owner(&vault, person)?;
    let ask = ask_judge_uncertainty(&vault, skill, person, "run", "case", "yes", "no")?;
    set_judge_digest_minutes(&vault, &owner, 1)?;
    propose(&vault, 0x78)?;
    let timer = vault.assemble_proactivity_digest(None, 10, None)?.unwrap();
    assert_eq!(timer.recipient, None);
    assert!(timer.judge_asks.is_empty());
    assert_eq!(timer.groups.values().map(Vec::len).sum::<usize>(), 1);
    assert_eq!(
        vault.read_proactivity_digest(timer.id)?,
        Some(timer.clone())
    );
    let own = vault.proactivity_digest(&owner, 10, None)?.unwrap();
    assert_eq!(own.recipient, Some(person));
    assert!(own.groups.is_empty());
    assert_eq!(own.judge_asks.len(), 1);
    assert_eq!(own.judge_asks[0].id, ask.id);
    assert_eq!(vault.latest_proactivity_digest()?, Some(timer));
    Ok(())
}
