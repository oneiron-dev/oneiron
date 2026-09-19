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
    // A kind filter is a post-fusion relevance decision, not a category or
    // authority predicate. Discoveries must not erase the memory accounting.
    let filtered = vault
        .context_pack()
        .search_text("channel", 20)
        .filter_types(&[ENTITY_TYPE_SKILL])
        .run()?;
    assert!(filtered.results.is_empty());
    assert_eq!(filtered.stats.candidates_considered, 1);
    assert_eq!(filtered.capabilities.len(), 5);
    assert_eq!(
        filtered.empty.as_ref().map(|empty| empty.reason),
        Some(super::EmptyReason::FilterMatchedNone)
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
    let mut skill = crate::skill::decode_skill_record(
        &vault
            .scoped_read(ScopedReadActorKey::new("viewer").unwrap())
            .get_entity_parts(&retired)?
            .unwrap()
            .2,
    )?;
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
