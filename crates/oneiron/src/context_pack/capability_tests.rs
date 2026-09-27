//! Actual retrieval split: turn discoveries cannot displace memory rows.
use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ScopedReadActorKey};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_SKILL, ENTITY_TYPE_TURN};
use crate::skill::{SkillLifecycle, SkillRecord, encode_skill_record};
use crate::{Result, TimeRange};

#[test]
fn capability_channel_keeps_memory_budget_and_revalidates_lifecycle() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
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
    let crate::claim::ScopedReadResult {
        value,
        receipt: _receipt,
    } = vault
        .scoped_read(ScopedReadActorKey::new("viewer").unwrap())
        .get_entity_parts_with_receipt(&retired, None)?;
    let mut skill = crate::skill::decode_skill_record(&value.unwrap().2)?;
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
        );
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
