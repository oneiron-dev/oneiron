use super::*;
use crate::vault_cleanup::{CleanupKind, zero_live_members};

#[test]
fn production_executor_mints_only_explicit_evidenced_people_and_never_relabels() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, conversation) =
        admitted_attempt_fixture(&vault, &store, 0x2F, &[("user", "I met Casey and Morgan")])?;
    let actor = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;
    let person = EntityId::now();
    let ordinary = EntityId::now();
    vault.put_entity(
        &ordinary,
        ENTITY_TYPE_PERSON,
        occurred(1),
        1,
        b"owner person",
    )?;
    let unsupported = EntityId::now();
    let outside = EntityId::now();
    let tool_person = EntityId::now();
    let tool_turn = seed_turn(&vault, &conversation, "tool", "I met Morgan", 12);
    let foreign_turn = seed_turn(&vault, &conversation, "user", "I met Morgan", 13);
    let row = |id: EntityId, name: &str, evidence: EntityId| {
        serde_json::json!({
            "id": id.to_hex(), "name": name, "evidence_turn_refs": [evidence.to_hex()],
        })
    };
    let response = text_response(
        serde_json::json!({
            "candidates": [],
            "persons": [
                row(person, "Casey", turns[0]),
                row(ordinary, "Morgan", turns[0]),
                row(unsupported, "Unmentioned", turns[0]),
                row(outside, "Morgan", foreign_turn),
                row(tool_person, "Morgan", tool_turn)
            ]
        })
        .to_string(),
    );
    let backend = ScriptedBackend::new(vec![Ok(response)]);
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
        model: crate::ModelId::new("test/model@r1").expect("regression fixture"),
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
    assert_eq!(
        zero_live_members(&vault, &person)?,
        Some(CleanupKind::ClaimlessExtractionPerson)
    );
    assert_eq!(zero_live_members(&vault, &ordinary)?, None);
    assert_eq!(vault.get(&ordinary)?, Some(b"owner person".to_vec()));
    for id in [unsupported, outside, tool_person] {
        assert!(!vault.entity_exists(&id)?);
    }
    let original = vault.get_raw(&person)?;
    // Durable extraction replay retains the same id and exact mint revision.
    block_on_ready(executor.execute(&admitted, &mut ctx))?;
    assert_eq!(vault.get_raw(&person)?, original);
    assert_eq!(
        zero_live_members(&vault, &person)?,
        Some(CleanupKind::ClaimlessExtractionPerson)
    );
    Ok(())
}

#[test]
fn extraction_provenance_rechecks_role_and_liveness_even_for_working_set_ids() -> Result<()> {
    let (_dir, vault) = open_vault();
    let conversation = seed_session(&vault, 0x30, 1);
    let user = seed_turn(&vault, &conversation, "user", "I met Casey", 10);
    let tool = seed_turn(&vault, &conversation, "tool", "I met Morgan", 11);
    let deleted = seed_turn(&vault, &conversation, "user", "I met Jordan", 12);
    vault.delete_entity_with_reason(&deleted, crate::deletion::DeleteReason::UserDelete)?;
    let valid_person = EntityId::now();
    let tool_person = EntityId::now();
    let deleted_person = EntityId::now();
    let row = |id: EntityId, name: &str, turn: EntityId| {
        serde_json::json!({
            "id": id.to_hex(), "name": name, "evidence_turn_refs": [turn.to_hex()],
        })
    };
    let response = text_response(
        serde_json::json!({
            "candidates": [],
            "persons": [
                row(valid_person, "Casey", user),
                row(tool_person, "Morgan", tool),
                row(deleted_person, "Jordan", deleted)
            ]
        })
        .to_string(),
    );
    crate::dreamer_consolidation::extracted_people::mint_extracted_people(
        &vault,
        &response,
        &[user, tool, deleted],
        20,
    )?;
    assert_eq!(
        zero_live_members(&vault, &valid_person)?,
        Some(CleanupKind::ClaimlessExtractionPerson)
    );
    assert!(!vault.entity_exists(&tool_person)?);
    assert!(!vault.entity_exists(&deleted_person)?);
    Ok(())
}
