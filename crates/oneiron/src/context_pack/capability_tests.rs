//! Actual retrieval split: turn discoveries cannot displace memory rows.
use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ScopedReadActorKey};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_SKILL, ENTITY_TYPE_TURN};
use crate::skill::{SkillLifecycle, SkillRecord, encode_skill_record};
use crate::{Result, TimeRange};

#[test]
fn capability_channel_keeps_memory_budget_and_revalidates_lifecycle() -> Result<()> {
    let mut config = crate::test_util::embedding_test_config();
    config.retrieval_telemetry_capture = true;
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    for index in 1..=9 {
        let id = crate::test_util::entity(index);
        let status = if index == 9 {
            ClaimApprovalStatus::Proposed
        } else {
            ClaimApprovalStatus::Approved
        };
        let mut skill = SkillRecord::new(
            format!("skill.channel.{index}"),
            "channel",
            "v1",
            status,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            vec![],
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from("fixture"),
            )]),
        );
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_SKILL,
                TimeRange { start: 1, end: 1 },
                1,
                &encode_skill_record(&skill)?,
            )
            .text(&id, &[("body", "channel")])
            .commit()?;
        skill.lifecycle_status = SkillLifecycle::Active;
        vault.update_skill_record(&id, &skill, TimeRange { start: 1, end: 1 }, 1)?;
        vault.batch().text(&id, &[("body", "channel")]).commit()?;
    }
    let agent_id = crate::test_util::entity(40);
    // Agent definitions remain discovery candidates even when not approved/active.
    let agent = AgentDefinition::new(
        "agent.channel",
        "channel",
        "v1",
        None,
        vec![],
        vec![],
        vec![],
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
        None,
        false,
        None,
    );
    vault
        .batch()
        .put(
            &agent_id,
            ENTITY_TYPE_AGENT_DEF,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_agent_definition(&agent)?,
        )
        .text(&agent_id, &[("body", "channel")])
        .commit()?;
    let memory = crate::test_util::entity(90);
    let bytes = rmp_serde::to_vec_named(&serde_json::json!({"text":"channel"})).unwrap();
    vault
        .batch()
        .put(
            &memory,
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            &bytes,
        )
        .text(&memory, &[("body", "channel")])
        .commit()?;
    let runs_before = vault.retrieval_runs(100)?.len();
    let mut pack = vault
        .context_pack()
        .search_text("channel", 1)
        .limit(1)
        .retrieval_budget(super::ContextPackRetrievalBudget::new(0, 1, 0, 0, 0, 0))
        .run()?;
    assert_eq!(
        pack.results.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![memory]
    );
    assert_eq!(vault.retrieval_runs(100)?.len(), runs_before + 1);
    assert_eq!(pack.stats.entities_hydrated, 1);
    assert_eq!(pack.stats.candidates_considered, 1);
    assert_eq!(
        pack.capabilities
            .iter()
            .filter(|hit| hit.entity_type == ENTITY_TYPE_SKILL)
            .count(),
        5
    );
    assert!(pack.capabilities.iter().any(|hit| hit.id == agent_id));
    assert!(
        !pack
            .capabilities
            .iter()
            .any(|hit| hit.id == crate::test_util::entity(9))
    );
    // A capability-only pack remains nonempty without overwriting memory
    // accounting. The stored run and the returned pack must agree on the
    // pre-filter memory population, independently of the five discoveries.
    let filtered_run = vault
        .context_pack()
        .search_text("channel", 20)
        .filter_types(&[ENTITY_TYPE_SKILL])
        .run_with_telemetry()?;
    let recorded = vault
        .retrieval_run(filtered_run.run_id.expect("recorded run"))?
        .expect("retrieval record");
    assert_eq!(recorded.total_in_scope, 1);
    let filtered = filtered_run.value;
    assert!(filtered.results.is_empty());
    assert_eq!(filtered.stats.candidates_considered, 1);
    assert_eq!(filtered.capabilities.len(), 5);
    assert!(
        filtered.empty.is_none(),
        "discoveries keep the pack nonempty"
    );
    // Reverse pressure: more high-ranked memory rows still cannot remove discovery.
    for seed in 100..130 {
        let id = crate::test_util::entity(seed);
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                &bytes,
            )
            .text(&id, &[("body", "channel channel channel")])
            .commit()?;
    }
    let crowded = vault
        .context_pack()
        .search_text("channel", 1)
        .limit(1)
        .retrieval_budget(super::ContextPackRetrievalBudget::new(0, 1, 0, 0, 0, 0))
        .run()?;
    assert_eq!(crowded.results.len(), 1);
    assert_eq!(
        crowded
            .capabilities
            .iter()
            .filter(|hit| hit.entity_type == ENTITY_TYPE_SKILL)
            .count(),
        5
    );
    assert!(crowded.capabilities.iter().any(|hit| hit.id == agent_id));
    let restricted = vault
        .context_pack()
        .search_text("channel", 1)
        .limit(1)
        .filter_types(&[ENTITY_TYPE_TURN])
        .run()?;
    assert_eq!(restricted.results.len(), 1);
    assert!(restricted.capabilities.is_empty());
    let retired = pack
        .capabilities
        .iter()
        .find(|hit| hit.entity_type == ENTITY_TYPE_SKILL)
        .unwrap()
        .id;
    crate::test_util::authorize_readers(&vault, &["viewer"]);
    let row = vault
        .scoped_read(ScopedReadActorKey::new("viewer").unwrap())
        .read(&[crate::claim::PointRead::id(retired)], None)?
        .single()
        .value
        .expect("readable skill");
    let mut skill = crate::skill::decode_skill_record(&row.body.expect("live body"))?;
    skill.lifecycle_status = SkillLifecycle::Superseded;
    vault.put_entity(
        &retired,
        ENTITY_TYPE_SKILL,
        TimeRange { start: 1, end: 1 },
        1,
        &encode_skill_record(&skill)?,
    )?;
    vault
        .scoped_read(ScopedReadActorKey::new("viewer").unwrap())
        .filter_context_pack(&mut pack)?;
    assert!(!pack.capabilities.iter().any(|hit| hit.id == retired));
    let session = crate::context_board::SessionReadSet::default();
    let skills = crate::context_board::SkillsSection::project(&pack.capabilities, &session);
    assert_eq!(skills.found.len(), 4);
    assert_eq!(skills.loaded, "loaded: ");
    let agents =
        crate::context_board::AgentsSection { rows: vec![] }.with_candidates(&pack.capabilities);
    assert_eq!(agents.rows.len(), 1);
    assert_eq!(agents.rows[0].lane, crate::context_board::AgentLane::Cand);
    Ok(())
}

/// The pack's skill channel ranks after semantic filtering, not by entity id or
/// the rebuildable confidence cache. The projected claim supplies the posterior.
#[test]
fn skill_discovery_blends_relevance_with_posterior_and_explores() -> Result<()> {
    use crate::claim::{ClaimBody, ClaimSubject};
    use crate::skill_reliability::PREDICATE_SKILL_RELIABILITY;

    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let mut skills = Vec::new();
    // All six have the same indexed text and therefore equal semantic relevance.
    // Skill 6 must enter the five-slot turn budget from outside the old semantic
    // top five; skills 2 and 6 have exactly equal posterior means.
    for (index, alpha, beta) in [
        (1, 1.0_f32, 3.0_f32),
        (2, 80.0, 80.0),
        (3, 1.0, 5.0),
        (4, 3.0, 1.0),
        (5, 1.0, 9.0),
        (6, 2.0, 2.0),
    ] {
        let id = crate::test_util::entity(index);
        let mut skill = SkillRecord::new(
            format!("skill.ucb.{index}"),
            "retrieval probe",
            "v1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            0.01, // deliberately stale cache; it must not govern selection
            false,
            true,
            vec![],
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from("ranking-fixture"),
            )]),
        );
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_SKILL,
                TimeRange { start: 1, end: 1 },
                1,
                &encode_skill_record(&skill)?,
            )
            .text(&id, &[("body", "channel")])
            .commit()?;
        skill.lifecycle_status = SkillLifecycle::Active;
        vault.update_skill_record(&id, &skill, TimeRange { start: 2, end: 2 }, 2)?;
        vault.batch().text(&id, &[("body", "channel")]).commit()?;
        let claim_id = crate::test_util::entity(index + 100);
        let mut posterior = ClaimBody::new(
            PREDICATE_SKILL_RELIABILITY,
            ClaimSubject::Entity(id),
            rmpv::Value::Map(vec![
                (rmpv::Value::from("alpha"), rmpv::Value::F32(alpha)),
                (rmpv::Value::from("beta"), rmpv::Value::F32(beta)),
            ]),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        ).unwrap();
        posterior.source = Some(ClaimSource::Observed);
        vault.with_write_txn(|txn| {
            vault.put_reserved_claim_in_txn(
                txn,
                &claim_id,
                &posterior,
                TimeRange { start: 3, end: 3 },
                3,
            )
        })?;
        skills.push(id);
    }
    let pack = vault.context_pack().search_text("channel", 20).run()?;
    assert_eq!(
        pack.capabilities
            .iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>(),
        vec![skills[3], skills[5], skills[1], skills[0], skills[2]],
        "posterior mean first, then UCB exploration for equal-mean arms"
    );
    Ok(())
}

#[test]
fn executor_pair_controls_production_pack_skill_ranking() -> Result<()> {
    use crate::claim::{ClaimBody, ClaimSubject};
    use crate::skill_reliability::PREDICATE_SKILL_RELIABILITY;
    let mut config = crate::test_util::embedding_test_config();
    config.retrieval_telemetry_capture = true;
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let mut ids = Vec::new();
    for index in 1..=2 {
        let id = crate::test_util::entity(index);
        let mut skill = SkillRecord::new(
            format!("skill.pair.{index}"),
            "pair ranking",
            "v1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            0.01,
            false,
            true,
            vec![],
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from("fixture"),
            )]),
        );
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_SKILL,
                TimeRange { start: 1, end: 1 },
                1,
                &encode_skill_record(&skill)?,
            )
            .text(&id, &[("body", "channel")])
            .commit()?;
        skill.lifecycle_status = SkillLifecycle::Active;
        vault.update_skill_record(&id, &skill, TimeRange { start: 2, end: 2 }, 2)?;
        vault.batch().text(&id, &[("body", "channel")]).commit()?;
        ids.push(id);
    }
    for (n, model, alpha, beta) in [
        (0, "old@1", 90.0, 10.0),
        (1, "old@1", 10.0, 90.0),
        (2, "new@2", 10.0, 90.0),
        (3, "new@2", 90.0, 10.0),
    ] {
        let id = ids[n % 2];
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_RELIABILITY,
            ClaimSubject::Entity(id),
            rmpv::Value::Map(vec![
                (rmpv::Value::from("alpha"), rmpv::Value::F32(alpha)),
                (rmpv::Value::from("beta"), rmpv::Value::F32(beta)),
                (rmpv::Value::from("executor"), rmpv::Value::from(model)),
            ]),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        ).unwrap();
        body.source = Some(ClaimSource::Observed);
        vault.with_write_txn(|txn| {
            vault.put_reserved_claim_in_txn(
                txn,
                &crate::test_util::entity(u8::try_from(n + 100).expect("small fixture")),
                &body,
                TimeRange { start: 3, end: 3 },
                3,
            )
        })?;
    }
    let rank = |model: &str| -> Result<Vec<crate::EntityId>> {
        Ok(vault
            .context_pack()
            .skill_executor(model)?
            .search_text("channel", 20)
            .run()?
            .capabilities
            .iter()
            .map(|hit| hit.id)
            .collect())
    };
    assert_eq!(rank("old@1")?, ids);
    assert_eq!(rank("new@2")?, vec![ids[1], ids[0]]);
    assert!(
        vault
            .context_pack()
            .skill_executor("missing-revision")
            .is_err()
    );
    let unmeasured = rank("new@3")?;
    assert_eq!(unmeasured.len(), 2);
    let captured = |model: Option<&str>| -> Result<_> {
        let mut builder = vault
            .context_pack()
            .search_text("private-query-sentinel", 20)
            .replay_query_ref("eval://pair-routing")
            .capture_retrieval_trace(true);
        if let Some(model) = model {
            builder = builder.skill_executor(model)?;
        }
        let run = builder.run_with_telemetry()?;
        let row = vault
            .retrieval_run(run.run_id.expect("recorded run"))?
            .expect("row");
        let inputs = row.replay_inputs.expect("captured replay inputs");
        assert!(!inputs.config.to_string().contains("private-query-sentinel"));
        Ok((inputs.config, row.trace.expect("trace").fork_hash))
    };
    let (old_config, old_hash) = captured(Some("old@1"))?;
    let (new_config, new_hash) = captured(Some("new@2"))?;
    let (unknown_config, unknown_hash) = captured(None)?;
    assert_eq!(old_config["skill_executor"], "old@1");
    assert_eq!(old_config["pack"]["assembly"]["skill_executor"], "old@1");
    assert_eq!(new_config["skill_executor"], "new@2");
    assert_eq!(new_config["pack"]["assembly"]["skill_executor"], "new@2");
    assert!(unknown_config["skill_executor"].is_null());
    assert!(unknown_config["pack"]["assembly"]["skill_executor"].is_null());
    assert_ne!(old_hash, new_hash);
    assert_ne!(old_hash, unknown_hash);
    assert_ne!(new_hash, unknown_hash);
    assert_eq!(old_hash, captured(Some("old@1"))?.1);
    Ok(())
}

/// Equal reliability cannot discard the strongest text match just because its
/// entity ID sorts after the other five skills in the semantic shortlist.
#[test]
fn skill_discovery_preserves_semantic_relevance_before_ucb() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let mut skills = Vec::new();
    for index in 1..=6 {
        let id = crate::test_util::entity(index);
        let mut skill = SkillRecord::new(
            format!("skill.semantic.{index}"),
            "semantic retrieval probe",
            "v1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            0.01,
            false,
            true,
            vec![],
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from("semantic-ranking-fixture"),
            )]),
        );
        let text = if index == 6 {
            "channel bonusword"
        } else {
            "channel"
        };
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_SKILL,
                TimeRange { start: 1, end: 1 },
                1,
                &encode_skill_record(&skill)?,
            )
            .text(&id, &[("body", text)])
            .commit()?;
        skill.lifecycle_status = SkillLifecycle::Active;
        vault.update_skill_record(&id, &skill, TimeRange { start: 2, end: 2 }, 2)?;
        vault.batch().text(&id, &[("body", text)]).commit()?;
        skills.push(id);
    }

    // All six have the same human-authored Beta(2,1) prior and timestamps.
    // Five match only "channel"; the highest-ID skill matches both tokens.
    let pack = vault
        .context_pack()
        .search_text("channel bonusword", 20)
        .run()?;
    let selected: Vec<_> = pack.capabilities.iter().map(|hit| hit.id).collect();
    assert_eq!(selected.len(), 5);
    assert_eq!(selected[0], skills[5], "the strongest match ranks first");
    assert!(
        !selected.contains(&skills[4]),
        "only the weakest tie loses a slot"
    );
    Ok(())
}

/// The skill bandit must not re-sort agent discoveries after the host reranker
/// has chosen their order, including when the text/vector union exceeds five.
#[test]
fn agent_discovery_retains_reranker_order_and_five_slot_choice() -> Result<()> {
    use std::sync::Mutex;

    use crate::rerank::{RerankCandidate, RerankOptions, Reranker};
    use crate::{EntityId, Vault};

    struct ReverseIdReranker {
        seen: Mutex<Vec<EntityId>>,
    }
    impl Reranker for ReverseIdReranker {
        fn id(&self) -> &str {
            "test/agent-reverse-id@v1"
        }

        fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
            *self.seen.lock().expect("candidate capture") =
                candidates.iter().map(|candidate| candidate.id).collect();
            Ok(candidates
                .iter()
                .map(|candidate| f32::from(candidate.id.as_bytes()[0]))
                .collect())
        }
    }

    fn put_agent(vault: &Vault, id: EntityId, vector: &[f32; 4]) -> Result<()> {
        let agent = AgentDefinition::new(
            format!("agent.rerank.{}", id.as_bytes()[0]),
            "channel",
            "v1",
            None,
            vec![],
            vec![],
            vec![],
            None,
            AgentScope::All,
            AgentCeiling::Proposed,
            None,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from("agent-rerank-fixture"),
            )]),
            None,
            false,
            None,
        );
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_AGENT_DEF,
                TimeRange { start: 1, end: 1 },
                1,
                &encode_agent_definition(&agent)?,
            )
            .text(&id, &[("body", "channel")])
            .vector(&id, vector)
            .commit()
    }

    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let reranker = ReverseIdReranker {
        seen: Mutex::new(Vec::new()),
    };
    let ids: Vec<_> = (1..=6).map(crate::test_util::entity).collect();
    put_agent(&vault, ids[0], &[-1.0, 0.0, 0.0, 0.0])?;
    put_agent(&vault, ids[1], &[1.0, 0.0, 0.0, 0.0])?;
    let query = || {
        vault
            .context_pack()
            .search_text("channel", 5)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 5)
            .rerank(&reranker, RerankOptions::default())
            .run()
    };
    let two = query()?;
    assert_eq!(
        two.capabilities
            .iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>(),
        vec![ids[1], ids[0]],
        "host choice survives the neutral blend's equal score ladder"
    );

    for id in &ids[2..] {
        put_agent(&vault, *id, &[1.0, 0.0, 0.0, 0.0])?;
    }
    let six = query()?;
    assert_eq!(reranker.seen.lock().expect("candidate capture").len(), 6);
    assert_eq!(
        six.capabilities
            .iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>(),
        vec![ids[5], ids[4], ids[3], ids[2], ids[1]],
        "the reranker's first five survive the independent agent budget"
    );
    Ok(())
}
