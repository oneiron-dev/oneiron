use super::*;

#[test]
fn prior_head_judge_routes_merge_accumulate_escalate_and_down() -> Result<()> {
    for resolution in ["merge", "accumulate", "escalate", "down"] {
        let (_dir, vault) = open_vault();
        let store = DreamerRunnerStore::new(&vault);
        let (admitted, turns, _) =
            admitted_attempt_fixture(&vault, &store, 0x2c, &[("user", "new name")])?;
        let actor = EntityId::now();
        let subject = EntityId::now();
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        let head = EntityId::now();
        let mut body = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            Value::from("Previous"),
            0.9,
            crate::ClaimApprovalStatus::Auto,
            crate::ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Approved;
        vault
            .batch()
            .put_replicated(
                &head,
                crate::registry::ENTITY_TYPE_CLAIM,
                occurred(1),
                1,
                &crate::claim::encode_claim_body(&body)?,
            )
            .commit()?;
        let judgment = if resolution == "down" {
            Err(crate::LlmError::Fatal(crate::FatalLlmError::InvalidRequest))
        } else {
            Ok(text_response(
                serde_json::json!({"resolution":resolution, "value":"Merged"}).to_string(),
            ))
        };
        let backend =
            ScriptedBackend::new(vec![Ok(extraction_response(&subject, &turns[0])), judgment]);
        let guard = crate::BudgetGuard::with_reserve_units(
            "wake",
            10_000,
            100,
            BudgetExhaustionPolicy::Suspend,
        );
        let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
        let mut sink = CapturingSink::default();
        let mut executor = ConsolidationExecutor {
            backend: &backend,
            guard: &guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor: WriteActor::new(actor, EdgeActorClass::Agent),
            model: crate::ModelId::new("test/model@r1").expect("model"),
            sink: &mut sink,
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
        let [result] = sink.accepted.as_slice() else {
            panic!("one judge result");
        };
        match resolution {
            "merge" => {
                assert_eq!(result.supersedes, Some(head));
                assert_eq!(result.candidate.predicate(), "profile.name");
            }
            "accumulate" => {
                assert_eq!(result.supersedes, None);
                assert_eq!(result.candidate.predicate(), "profile.name");
            }
            _ => {
                assert_eq!(result.supersedes, None);
                assert_eq!(
                    result.candidate.predicate(),
                    crate::claim::PREDICATE_CONFLICT_OPEN
                );
            }
        }
        assert_eq!(
            vault.get_claim(&head)?.expect("prior").lifecycle,
            crate::claim::ClaimLifecycleStatus::Active
        );
    }
    Ok(())
}

#[test]
fn manifest_single_value_skips_judge_only_at_sufficient_trust() -> Result<()> {
    for source in [ClaimSource::Inferred, ClaimSource::UserStated] {
        let (_dir, vault) = open_vault();
        let manifest_id = crate::gate::default_policy_manifest_id()?;
        let raw = vault.get_raw(&manifest_id)?.expect("manifest");
        let mut cursor = std::io::Cursor::new(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]);
        let Value::Map(mut rows) = rmpv::decode::read_value(&mut cursor).expect("manifest decode")
        else {
            panic!("manifest map");
        };
        rows.push((
            Value::from("single_valued_predicates"),
            Value::Array(vec![Value::from("profile.name")]),
        ));
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &Value::Map(rows)).expect("encode");
        crate::test_util::put_policy_manifest_bytes(&vault, manifest_id, &encoded)?;
        let store = DreamerRunnerStore::new(&vault);
        let (admitted, turns, _) =
            admitted_attempt_fixture(&vault, &store, 0x2d, &[("user", "new name")])?;
        let subject = EntityId::now();
        let actor = EntityId::now();
        let head = EntityId::now();
        for id in [subject, actor] {
            vault.put_entity(&id, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        }
        let mut body = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            Value::from("Old"),
            0.9,
            crate::ClaimApprovalStatus::Auto,
            crate::ClaimLifecycleStatus::Active,
        );
        body.source = Some(source);
        body.approval = ClaimApprovalStatus::Approved;
        vault
            .batch()
            .put_replicated(
                &head,
                crate::registry::ENTITY_TYPE_CLAIM,
                occurred(1),
                1,
                &crate::claim::encode_claim_body(&body)?,
            )
            .commit()?;
        let mut script = vec![Ok(extraction_response(&subject, &turns[0]))];
        if source == ClaimSource::UserStated {
            script.push(Ok(text_response(
                "{\"resolution\":\"escalate\"}".to_owned(),
            )));
        }
        let backend = ScriptedBackend::new(script);
        let guard = crate::BudgetGuard::with_reserve_units(
            "wake",
            10_000,
            100,
            BudgetExhaustionPolicy::Suspend,
        );
        let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
        let mut sink = CapturingSink::default();
        let mut executor = ConsolidationExecutor {
            backend: &backend,
            guard: &guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor: WriteActor::new(actor, EdgeActorClass::Agent),
            model: crate::ModelId::new("test/model@r1").expect("model"),
            sink: &mut sink,
        };
        let mut ctx = WakeAttemptContext {
            vault: &vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms: 21_000,
        };
        block_on_ready(executor.execute(&admitted, &mut ctx))?;
        let [result] = sink.accepted.as_slice() else {
            panic!("one result");
        };
        if source == ClaimSource::Inferred {
            assert_eq!(result.supersedes, Some(head));
        } else {
            assert_eq!(
                result.candidate.predicate(),
                crate::claim::PREDICATE_CONFLICT_OPEN
            );
        }
    }
    Ok(())
}
