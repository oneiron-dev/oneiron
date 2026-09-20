//! Persistence, rerun idempotence, prior-head and topic partition laws.
use super::*;
use crate::dreamer_promotion::{DreamerRunContext, promote_consolidated_claims};

fn auto_policy(vault: &Vault) {
    let sources: serde_json::Map<String, serde_json::Value> = [
        "user_stated",
        "observed",
        "inferred",
        "imported",
        "tool_output",
        "generated",
    ]
    .into_iter()
    .map(|s| {
        (
            s.into(),
            serde_json::json!({"max_auto_sensitivity":3,"receipted":true,"warned":true}),
        )
    })
    .collect();
    let value = serde_json::json!({"schema_version":"1.1","pack_id":"conflict-test","pack_version":"1","min_engine_version":env!("CARGO_PKG_VERSION"),"defaults":{"criticality":"normal","sensitivity":"normal"},"rules":[],"actor_ceilings":[{"actor_class":"agent","ceiling":"auto"},{"actor_class":"human","ceiling":"auto"},{"actor_class":"first_party","ceiling":"auto"}],"source_trust":sources,"signature":{"alg":"ed25519","key_id":"test","sig":"test-signature"}});
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &rmp_serde::to_vec_named(&value).unwrap(),
    )
    .unwrap();
}
fn topic_candidate(subject: EntityId, topic: &str, answer: &str) -> PromotionCandidate {
    let mut c = candidate(subject, "preference.food", answer, None);
    c.candidate = c.candidate.with_scope(Value::Map(vec![(
        Value::from("topic_key"),
        Value::from(topic),
    )]));
    c
}
#[test]
fn changed_answers_share_topic_but_different_questions_do_not_conflict() -> Result<()> {
    let subject = EntityId::now();
    let candidates = vec![
        topic_candidate(subject, "coffee", "yes"),
        topic_candidate(subject, "coffee", "no"),
        topic_candidate(subject, "tea", "yes"),
        topic_candidate(subject, "tea", "no"),
    ];
    let conflicts = detect_conflicts(&candidates, &[])?;
    assert_eq!(conflicts.len(), 2);
    assert_eq!(conflicts[0].candidate_indexes.len(), 2);
    assert_ne!(conflicts[0].identity.topic, conflicts[1].identity.topic);
    Ok(())
}
#[test]
fn prior_head_disagreement_opens_one_persistent_marker_and_close_audit() -> Result<()> {
    let (_dir, vault) = open_vault();
    auto_policy(&vault);
    let actor = EntityId::now();
    let subject = EntityId::now();
    for id in [actor, subject] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    }
    let conversation = seed_session(&vault, 0xB2, 1);
    let turn = seed_turn(&vault, &conversation, "user", "no coffee", 2);
    let mut head = prior_head(
        subject,
        "preference.food",
        "yes",
        ClaimApprovalStatus::Approved,
        ClaimSource::UserStated,
    );
    head.body.scope = Some(Value::Map(vec![(
        Value::from("topic_key"),
        Value::from("coffee"),
    )]));
    vault.put_claim(&head.claim_id, &head.body, occurred(2), 2)?;
    let mut c = topic_candidate(subject, "coffee", "no");
    c.evidence_turn_refs = vec![turn];
    let priors = vec![PriorHead {
        claim_id: head.claim_id,
        body: vault.get_claim(&head.claim_id)?.unwrap(),
    }];
    let sets = detect_conflicts(&[c.clone()], &priors)?;
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].prior_head, Some(head.claim_id));
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, _, _) =
        admitted_attempt_fixture(&vault, &store, 0xB3, &[("user", "no coffee")])?;
    let run = DreamerRunContext {
        run_id: "conflict-test".into(),
        attempt_id: admitted.status.attempt.id,
        agent_actor: vault.dreamer_actor_for_attempt(admitted.status.attempt.id)?,
        now_ms: 10,
    };
    let marker =
        super::super::persistence::open_marker(&sets[0], &[&c], &priors, run.attempt_id, 10)?;
    let id = marker.claim_id;
    assert_eq!(id, conflict_open_marker_id(&sets[0], run.attempt_id));
    for _ in 0..2 {
        let outcome = promote_consolidated_claims(&vault, &run, vec![marker.clone()])?;
        assert_eq!(outcome.landed, vec![id], "{:?}", outcome.rejected);
    }
    assert_eq!(
        vault.get_claim(&id)?.unwrap().predicate,
        crate::claim::PREDICATE_CONFLICT_OPEN
    );
    assert_eq!(
        vault
            .claims_for_subject(&subject)?
            .into_iter()
            .filter(|id| vault.get_claim(id).unwrap().unwrap().predicate
                == crate::claim::PREDICATE_CONFLICT_OPEN)
            .count(),
        1
    );
    let closed =
        close_persistent_conflict(&vault, &run, id, Value::from("owner chose no"), vec![turn])?;
    assert_eq!(closed.landed.len(), 1, "{:?}", closed.rejected);
    assert_eq!(
        vault.get_claim(&closed.landed[0])?.unwrap().predicate,
        crate::claim::PREDICATE_CONFLICT_RESOLVED
    );
    assert_eq!(
        close_persistent_conflict(&vault, &run, id, Value::from("owner chose no"), vec![turn])?
            .landed,
        closed.landed
    );
    Ok(())
}

#[test]
fn extraction_keeps_same_answers_for_different_topics_distinct_on_replay() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, _) =
        admitted_attempt_fixture(&vault, &store, 0xB4, &[("user", "I like coffee and tea")])?;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let relationships = [EntityId::now(), EntityId::now()];
    let candidates: Vec<_> = relationships
        .into_iter()
        .flat_map(|rel| ["coffee", "tea"].into_iter().map(move |topic| (rel, topic)))
        .map(|(rel, topic)| {
            serde_json::json!({
                "subject": subject.to_hex(), "predicate": "preference.food",
                "value": "yes", "topic_key": topic, "rel": rel.to_hex(), "confidence": 0.9,
                "evidence_turn_refs": [turns[0].to_hex()]
            })
        })
        .collect();
    let backend = ScriptedBackend::new(vec![Ok(text_response(
        serde_json::json!({"candidates": candidates}).to_string(),
    ))]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut sink = CapturingSink::default();
    for _ in 0..2 {
        let mut executor = ConsolidationExecutor {
            backend: &backend,
            guard: &guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor: vault.dreamer_authority()?,
            model: crate::ModelId::new("test/model@r1").expect("fixture model"),
            sink: &mut sink,
            scope: None,
        };
        let mut ctx = WakeAttemptContext {
            vault: &vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms: 21_000,
        };
        assert!(matches!(
            block_on_ready(executor.execute(&admitted, &mut ctx))?,
            DreamerAttemptExecution::Completed { .. }
        ));
    }
    let ids: Vec<_> = sink
        .accepted
        .iter()
        .map(|candidate| candidate.claim_id)
        .collect();
    assert_eq!(ids.len(), 8);
    assert_eq!(
        ids[..4]
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    assert_ne!(
        ids[0], ids[1],
        "different questions cannot overwrite each other"
    );
    assert_eq!(
        &ids[..4],
        &ids[4..],
        "replay keeps both write-once identities"
    );
    Ok(())
}
