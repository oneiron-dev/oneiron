use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
};
use crate::edge::EdgeActorClass;
use crate::llm::decision::questions::{
    OutcomeBinding, OutcomeSource, calibration_pairs, project_bound_outcomes, read_question,
};
use crate::{EntityId, TimeRange, Vault, VaultConfig};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn spec(vault: &Vault, holder: EntityId) -> TaskAskSpec {
    TaskAskSpec {
        intent_key: "bound-ask".into(),
        ..crate::task_verb::TaskAskSpec::shorthand(
            Some(TaskAskTarget::Responder(TaskAssignee::Human {
                actor_ref: holder,
            })),
            crate::task_verb::TaskAskQuestion {
                reference: super::tests::support::consult_turn(vault, 0xFE),
                revision: 1,
                options: Default::default(),
                context_refs: Vec::new(),
                label: None,
                outcome_binding: Some(OutcomeBinding {
                    source: OutcomeSource::Claim {
                        predicate: "outcome.earned".into(),
                    },
                    horizon: 60,
                    mapping: [("won".into(), true), ("lost".into(), false)].into(),
                    noise_weight: 0.8,
                    linked_by: None,
                }),
            },
            Some(u64::MAX),
            crate::task_verb::TaskAskDefault::AskMe,
        )
    }
}

fn settled(vault: &Vault, owner: EntityId, handle: TaskAskHandle) -> TaskAskResult {
    let TaskAskStatus::Settled(result) = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask_status(handle)
        .unwrap()
    else {
        panic!("settled ask")
    };
    *result
}

fn answered_at(vault: &Vault, owner: EntityId, handle: TaskAskHandle) -> u64 {
    read_question(vault, owner, handle.group_ref, None)
        .unwrap()
        .unwrap()
        .created_at
}

fn actors(vault: &Vault, principal: EntityId, ids: &[EntityId]) -> Result<()> {
    super::tests::support::permit_outcome_fixture_predicates(vault, principal)?;
    let now = crate::unix_seconds_now();
    for id in ids {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"actor",
        )?;
    }
    Ok(())
}

fn fact(unit: EntityId) -> ClaimBody {
    ClaimBody::new(
        "outcome.earned",
        ClaimSubject::Entity(unit),
        rmpv::Value::from("won"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap()
}

#[test]
fn outcome_horizon_field_mutation_privacy_and_reopen_are_rechecked() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = EntityId::now();
    let holder = EntityId::now();
    let stranger = EntityId::now();
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    actors(&vault, owner, &[owner, holder, stranger])?;
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let receipt = facade.tasks_ask(&spec(&vault, holder))?;
    let answer = vault
        .memory(holder, EdgeActorClass::Human)
        .tasks_answer(&receipt.handle, &TaskAskWord::new(holder))?;
    let task = receipt.handle.group_ref;
    let answer_id = settled(&vault, owner, receipt.handle)
        .settlement
        .outcome_answer_ref
        .expect("answer claim");
    let fact_id = EntityId::now();
    let body = fact(holder);
    let at = answered_at(&vault, owner, receipt.handle) + 60;
    let occurred = TimeRange { start: at, end: at };
    // Before the answer and one second past the horizon cannot label it.
    for time in [
        answered_at(&vault, owner, receipt.handle) - 1,
        answered_at(&vault, owner, receipt.handle) + 61,
    ] {
        vault.put_claim(
            &EntityId::now(),
            &body,
            TimeRange {
                start: time,
                end: time,
            },
            time,
        )?;
    }
    assert!(facade.tasks_ask_outcomes(&receipt.handle)?.is_empty());
    vault.put_claim(&fact_id, &body, occurred, at)?;
    let expected = facade.tasks_ask_outcomes(&receipt.handle)?;
    assert_eq!(expected.len(), 1);
    assert_eq!(expected[0].outcome.answer, answer_id);
    assert!(
        vault
            .memory(stranger, EdgeActorClass::Human)
            .tasks_ask_outcomes(&receipt.handle)
            .is_err()
    );
    assert!(calibration_pairs(&vault, stranger, task)?.is_empty());
    assert!(read_question(&vault, stranger, task, None)?.is_none());

    // A label is immutable. Neither a different value nor different routing
    // fields may make the same fact id silently relabel another observation.
    let mut changed = body.clone();
    changed.value = rmpv::Value::from("lost");
    vault.put_claim(&fact_id, &changed, occurred, at + 1)?;
    assert!(facade.tasks_ask_outcomes(&receipt.handle)?.is_empty());
    changed = body.clone();
    changed.subject = ClaimSubject::Entity(stranger);
    vault.put_claim(&fact_id, &changed, occurred, at + 2)?;
    assert!(facade.tasks_ask_outcomes(&receipt.handle)?.is_empty());
    changed = body.clone();
    changed.predicate = "outcome.changed".into();
    vault.put_claim(&fact_id, &changed, occurred, at + 3)?;
    assert!(facade.tasks_ask_outcomes(&receipt.handle)?.is_empty());
    vault.put_claim(
        &fact_id,
        &body,
        TimeRange {
            start: at + 1,
            end: at + 1,
        },
        at + 4,
    )?;
    assert!(facade.tasks_ask_outcomes(&receipt.handle)?.is_empty());
    changed = body.clone();
    changed.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("typed_question_principal"),
        rmpv::Value::from(stranger.to_hex()),
    )]));
    vault.put_claim(&fact_id, &changed, occurred, at + 5)?;
    assert!(facade.tasks_ask_outcomes(&receipt.handle)?.is_empty());
    // The same boundary also applies at arrival, before any label exists.
    let private_fact = EntityId::now();
    vault.put_claim(&private_fact, &changed, occurred, at + 5)?;
    assert_eq!(project_bound_outcomes(&vault, owner, task)?, 0);
    changed = body.clone();
    changed.approval = ClaimApprovalStatus::Rejected;
    vault.put_claim(&fact_id, &changed, occurred, at + 6)?;
    assert!(facade.tasks_ask_outcomes(&receipt.handle)?.is_empty());
    changed = body.clone();
    changed.lifecycle = ClaimLifecycleStatus::Retracted;
    vault.put_claim(&fact_id, &changed, occurred, at + 7)?;
    assert!(facade.tasks_ask_outcomes(&receipt.handle)?.is_empty());
    vault.put_claim(&fact_id, &body, occurred, at + 8)?;
    assert_eq!(facade.tasks_ask_outcomes(&receipt.handle)?, expected);

    // Approving the answer never widens its private-reader boundary.
    let mut prediction = vault.get_claim(&answer_id)?.expect("answer");
    prediction.approval = ClaimApprovalStatus::Approved;
    vault.put_claim(
        &answer_id,
        &prediction,
        TimeRange {
            start: answered_at(&vault, owner, receipt.handle),
            end: answered_at(&vault, owner, receipt.handle),
        },
        at + 9,
    )?;
    let crate::claim::ScopedReadResult {
        value,
        receipt: _receipt,
    } = vault
        .scoped_read(ScopedReadActorKey::new(owner.to_hex()).unwrap())
        .read(&[crate::claim::PointRead::id(answer_id)], None)?
        .single();
    assert!(value.is_some());
    let crate::claim::ScopedReadResult {
        value,
        receipt: _receipt,
    } = vault
        .scoped_read(ScopedReadActorKey::new(stranger.to_hex()).unwrap())
        .read(&[crate::claim::PointRead::id(answer_id)], None)?
        .single();
    assert!(value.is_none());
    assert_eq!(facade.tasks_ask_outcomes(&receipt.handle)?, expected);
    assert_eq!(
        facade.tasks_wait(receipt.handle, Some("reopen-step"))?,
        TaskAskWait::Ready(Box::new(settled(&vault, owner, receipt.handle)))
    );
    drop(vault);

    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    let facade = reopened.memory(owner, EdgeActorClass::Human);
    assert_eq!(facade.tasks_ask_outcomes(&receipt.handle)?, expected);
    assert_eq!(
        facade.tasks_wait(receipt.handle, Some("reopen-step"))?,
        TaskAskWait::Ready(Box::new(settled(&reopened, owner, receipt.handle)))
    );
    let before_late = settled(&reopened, owner, receipt.handle);
    let late = reopened
        .memory(holder, EdgeActorClass::Human)
        .tasks_answer(&receipt.handle, &TaskAskWord::new(stranger))?;
    assert_ne!(late.word_ref, answer.word_ref);
    assert_eq!(settled(&reopened, owner, receipt.handle), before_late);
    assert!(
        facade
            .tasks_ask_evidence(receipt.handle)?
            .iter()
            .any(|entry| entry.answer == late && entry.reason == TaskAskEvidenceReason::Late)
    );
    assert!(
        facade
            .tasks_ask(&spec(&reopened, holder))?
            .idempotent_replay
    );
    assert_eq!(project_bound_outcomes(&reopened, owner, task)?, 0);
    Ok(())
}

#[test]
fn bound_ask_first_answer_cas_has_one_version_claim_and_resolved_result() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let one = EntityId::now();
    let two = EntityId::now();
    actors(&vault, owner, &[owner, one, two])?;
    let mut ask = spec(&vault, one);
    let auth = vault.authenticate_owner(
        one,
        &one.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let class = crate::consent::ActionClass::new("review")?;
    let envelope = crate::consent::ActionEnvelope::new(["project:alpha".into()])?;
    let bound = crate::consent::GrantBound::action(
        crate::consent::ActorBound::new(two.to_hex())?,
        class.clone(),
        envelope.clone(),
    )?;
    vault.create_standing_grant(&auth, bound)?;
    ask.who = Some(TaskAskTarget::Authority(AskAuthorityScope {
        class,
        envelope,
    }));
    let handle = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask(&ask)?
        .handle;
    let answers = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            vault
                .memory(one, EdgeActorClass::Human)
                .tasks_answer(&handle, &TaskAskWord::new(one))
        });
        let b = scope.spawn(|| {
            vault
                .memory(two, EdgeActorClass::Human)
                .tasks_answer(&handle, &TaskAskWord::new(two))
        });
        [
            a.join().expect("first holder"),
            b.join().expect("second holder"),
        ]
    });
    let [first, second] = answers;
    let first = first?;
    let second = second?;
    assert_ne!(first.task_ref, second.task_ref);
    assert_eq!((first.result_ref, second.result_ref), (one, two));
    let result = settled(&vault, owner, handle);
    let TaskAskDecision::First(winner) = result.decision else {
        panic!("first human word")
    };
    assert!(result.settlement.outcome_answer_ref.is_some());
    let unit = winner.result_ref;
    let question = handle.group_ref;
    let record = read_question(&vault, owner, question, None)?.expect("question");
    assert_eq!(record.definition.question.version, 1);
    assert_eq!(record.definition.units, vec![unit]);
    let count = [one, two]
        .into_iter()
        .map(|id| vault.claims_for_subject(&id))
        .collect::<crate::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .map(|id| vault.get_claim(&id))
        .collect::<crate::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .filter(|claim| claim.predicate == "judgment.answer")
        .count();
    assert_eq!(count, 1);
    assert_eq!(
        vault
            .memory(owner, EdgeActorClass::Human)
            .tasks_wait(handle, Some("winner"))?,
        TaskAskWait::Ready(Box::new(settled(&vault, owner, handle)))
    );
    let at = answered_at(&vault, owner, handle) + 1;
    vault.put_claim(
        &EntityId::now(),
        &fact(unit),
        TimeRange { start: at, end: at },
        at,
    )?;
    let pairs = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask_outcomes(&handle)?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(
        pairs[0].outcome.answer,
        settled(&vault, owner, handle)
            .settlement
            .outcome_answer_ref
            .unwrap()
    );
    Ok(())
}

#[test]
fn invalid_binding_and_unreadable_result_do_not_bind_an_ask() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let holder = EntityId::now();
    actors(&vault, owner, &[owner, holder])?;
    let facade = vault.memory(owner, EdgeActorClass::Human);
    for source in [
        OutcomeSource::Claim {
            predicate: "judgment.answer".into(),
        },
        OutcomeSource::Event {
            predicate: "".into(),
        },
        OutcomeSource::Edge {
            relation: "unknown".into(),
        },
    ] {
        let mut ask = spec(&vault, holder);
        ask.what.outcome_binding.as_mut().unwrap().source = source;
        assert!(facade.tasks_ask(&ask).is_err());
    }
    let mut zero = spec(&vault, holder);
    zero.what.outcome_binding.as_mut().unwrap().horizon = 0;
    assert!(facade.tasks_ask(&zero).is_err());
    let private = EntityId::now();
    let now = crate::unix_seconds_now();
    let mut body = fact(holder);
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("typed_question_principal"),
        rmpv::Value::from(holder.to_hex()),
    )]));
    vault.put_claim(
        &private,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    for bound in [false, true] {
        let mut ask = spec(&vault, holder);
        ask.intent_key = format!("private-{bound}");
        if !bound {
            ask.what.outcome_binding = None;
        }
        let handle = facade.tasks_ask(&ask)?.handle;
        assert!(
            vault
                .memory(holder, EdgeActorClass::Human)
                .tasks_answer(&handle, &TaskAskWord::new(private))
                .is_err()
        );
        let task = handle.group_ref;
        assert!(read_question(&vault, owner, task, None)?.is_none());
        assert!(matches!(
            facade.tasks_wait(handle, Some("retry"))?,
            TaskAskWait::Pending { .. }
        ));
        // Rejection rolled back every piece. A readable answer still wins later.
        let answer = vault
            .memory(holder, EdgeActorClass::Human)
            .tasks_answer(&handle, &TaskAskWord::new(holder))?;
        assert_eq!(
            settled(&vault, owner, handle)
                .settlement
                .outcome_answer_ref
                .is_some(),
            bound
        );
        assert_eq!(answer.result_ref, holder);
        assert_eq!(
            facade.tasks_wait(handle, Some("retry"))?,
            TaskAskWait::Ready(Box::new(settled(&vault, owner, handle)))
        );
        if bound {
            let mut changed = ask;
            changed.what.outcome_binding.as_mut().unwrap().noise_weight = 0.4;
            assert!(facade.tasks_ask(&changed).is_err());
        }
    }
    Ok(())
}

#[test]
fn linked_event_replay_and_edge_stage_arrivals_use_the_same_projector() -> Result<()> {
    use crate::campaign::claims::{
        CrmStageValue, EvidenceBasis, StageEvidenceClass, StageKey, encode_crm_stage_value,
    };
    use crate::edge::EdgeKind;
    use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let unit = EntityId::now();
    let linked = EntityId::now();
    let campaign = EntityId::now();
    actors(&vault, owner, &[owner, unit, linked, campaign])?;
    vault
        .batch()
        .edge(&unit, EdgeKind::About, &linked, 1.0)
        .commit()?;
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let mut event = spec(&vault, unit);
    event.intent_key = "event-outcome".into();
    let binding = event.what.outcome_binding.as_mut().unwrap();
    binding.source = OutcomeSource::Event {
        predicate: "outcome.earned".into(),
    };
    binding.linked_by = Some("about".into());
    let handle = facade.tasks_ask(&event)?.handle;
    let answer = vault
        .memory(unit, EdgeActorClass::Human)
        .tasks_answer(&handle, &TaskAskWord::new(unit))?;
    assert_eq!(answer.result_ref, unit);
    let at = answered_at(&vault, owner, handle) + 1;
    let occurred = TimeRange { start: at, end: at };
    let body = fact(linked);
    let fact_id = EntityId::now();
    let rolled_back: crate::Result<()> = vault.with_write_txn(|txn| {
        vault.put_claim_in_txn(txn, &fact_id, &body, occurred, at)?;
        Err(crate::Error::ConcurrentWrite("fixture rollback"))
    });
    assert!(matches!(rolled_back, Err(crate::Error::ConcurrentWrite(_))));
    assert!(vault.get_claim(&fact_id)?.is_none());
    assert!(facade.tasks_ask_outcomes(&handle)?.is_empty());
    for _ in 0..2 {
        vault
            .batch()
            .put_replicated(
                &fact_id,
                crate::registry::ENTITY_TYPE_CLAIM,
                occurred,
                at,
                &crate::claim::encode_claim_body(&body)?,
            )
            .commit()?;
    }
    let pairs = facade.tasks_ask_outcomes(&handle)?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].outcome.fact, fact_id);
    assert!(vault.delete_edge(&unit, EdgeKind::About, &linked)?);
    assert!(facade.tasks_ask_outcomes(&handle)?.is_empty());

    // The preceding case removed this edge to prove link revocation. A real
    // edge must exist before a provenance claim can describe it.
    vault
        .batch()
        .edge(&unit, EdgeKind::About, &linked, 1.0)
        .commit()?;
    let mut edge = spec(&vault, unit);
    edge.intent_key = "edge-outcome".into();
    let binding = edge.what.outcome_binding.as_mut().unwrap();
    binding.source = OutcomeSource::Edge {
        relation: "about".into(),
    };
    binding.mapping = [("confirmed".into(), true)].into();
    let edge_handle = facade.tasks_ask(&edge)?.handle;
    let answer = vault
        .memory(unit, EdgeActorClass::Human)
        .tasks_answer(&edge_handle, &TaskAskWord::new(unit))?;
    assert_eq!(answer.result_ref, unit);
    let at = answered_at(&vault, owner, edge_handle) + 1;
    let edge_fact = EntityId::now();
    let mut provenance = EdgeProvenanceClaimBody::new(owner, 1.0, SupersessionStatus::Confirmed);
    provenance.valid_from = Some(at);
    vault.put_edge_provenance(
        &edge_fact,
        &EdgeRef::new(unit, EdgeKind::About, linked),
        &provenance,
        EdgeActorClass::Human,
        at,
    )?;
    let pairs = facade.tasks_ask_outcomes(&edge_handle)?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].outcome.fact, edge_fact);

    let mut stage = spec(&vault, unit);
    stage.intent_key = "stage-outcome".into();
    let binding = stage.what.outcome_binding.as_mut().unwrap();
    binding.source = OutcomeSource::Stage {
        campaign: campaign.to_hex(),
    };
    binding.mapping = [("earned".into(), true)].into();
    let stage_handle = facade.tasks_ask(&stage)?.handle;
    let answer = vault
        .memory(unit, EdgeActorClass::Human)
        .tasks_answer(&stage_handle, &TaskAskWord::new(unit))?;
    assert_eq!(answer.result_ref, unit);
    let at = answered_at(&vault, owner, stage_handle) + 1;
    let stage_fact = EntityId::now();
    let mut body = fact(unit);
    body.predicate = "crm.stage".into();
    body.value = encode_crm_stage_value(&CrmStageValue {
        campaign_ref: campaign,
        stage: StageKey("earned".into()),
        evidence_class: StageEvidenceClass::MeaningfulReply,
        evidence_refs: vec![unit],
        basis: EvidenceBasis::Machine,
        recorded_at: at,
    });
    vault.put_claim(&stage_fact, &body, TimeRange { start: at, end: at }, at)?;
    let pairs = facade.tasks_ask_outcomes(&stage_handle)?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].outcome.fact, stage_fact);
    Ok(())
}
