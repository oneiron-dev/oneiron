use super::*;
use crate::vault_cleanup::{CleanupKind, zero_live_members};

#[test]
fn production_executor_mints_only_explicit_evidenced_people_and_never_relabels() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, conversation) =
        admitted_attempt_fixture(&vault, &store, 0x2F, &[("user", "I met Casey and Morgan")])?;
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
        roles: Default::default(),
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("regression fixture"),
        sink: &mut sink,
        inference: test_inference_host(),
        scope: None,
        decisions: ConsolidationDecisions::shipped()?,
    };
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "wake",
        now_ms: 21_000,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
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
fn expired_mint_transaction_does_not_publish_extracted_people() -> Result<()> {
    let (_dir, vault) = open_vault();
    let conversation = seed_session(&vault, 0x72, 1);
    let turn = seed_turn(&vault, &conversation, "user", "I met Casey", 10);
    let sources = TestCallSources::new(&[(turn, "I met Casey")]);
    let persons = vec![
        crate::dreamer_consolidation::executor::extraction::ExtractedPerson {
            id: "new:P1".to_owned(),
            name: "Casey".to_owned(),
            evidence_turn_refs: vec!["T1".to_owned()],
        },
    ];
    let namespace = crate::dreamer_consolidation::extracted_people::MintNamespace::new(
        crate::AttemptId::now(),
        None,
        None,
        None,
        None,
    );
    let bindings =
        crate::dreamer_consolidation::extracted_people::bind_people(&persons, &sources, &namespace);
    let id = bindings.subject(1).expect("P1 binds");
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 180_001));
    assert!(
        crate::dreamer_consolidation::extracted_people::mint_extracted_people(
            &vault,
            &bindings,
            &[turn],
            &source_scope(&vault, &[turn])?,
            20,
            Some(&deadline),
            None,
        )
        .is_err()
    );
    assert!(!vault.entity_exists(&id)?);
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
    let sources = TestCallSources::new(&[
        (user, "I met Casey"),
        (tool, "I met Morgan"),
        (deleted, "I met Jordan"),
    ]);
    let persons = vec![
        crate::dreamer_consolidation::executor::extraction::ExtractedPerson {
            id: "new:P1".to_owned(),
            name: "Casey".to_owned(),
            evidence_turn_refs: vec!["T1".to_owned()],
        },
        crate::dreamer_consolidation::executor::extraction::ExtractedPerson {
            id: "new:P2".to_owned(),
            name: "Morgan".to_owned(),
            evidence_turn_refs: vec!["T2".to_owned()],
        },
        crate::dreamer_consolidation::executor::extraction::ExtractedPerson {
            id: "new:P3".to_owned(),
            name: "Jordan".to_owned(),
            evidence_turn_refs: vec!["T3".to_owned()],
        },
    ];
    let namespace = crate::dreamer_consolidation::extracted_people::MintNamespace::new(
        crate::AttemptId::now(),
        None,
        None,
        None,
        None,
    );
    let bindings =
        crate::dreamer_consolidation::extracted_people::bind_people(&persons, &sources, &namespace);
    let valid = bindings.subject(1).expect("P1 binds");
    let tool_id = bindings.subject(2).expect("P2 binds");
    let deleted_id = bindings.subject(3).expect("P3 binds");
    crate::dreamer_consolidation::extracted_people::mint_extracted_people(
        &vault,
        &bindings,
        &[user, tool, deleted],
        &source_scope(&vault, &[user, tool, deleted])?,
        20,
        None,
        None,
    )?;
    assert_eq!(
        zero_live_members(&vault, &valid)?,
        Some(CleanupKind::ClaimlessExtractionPerson)
    );
    assert!(!vault.entity_exists(&tool_id)?);
    assert!(!vault.entity_exists(&deleted_id)?);
    Ok(())
}

#[test]
fn extraction_requires_a_normalized_name_span_not_an_embedded_word() -> Result<()> {
    let (_dir, vault) = open_vault();
    let conversation = seed_session(&vault, 0x31, 1);
    let cases = [
        ("Ann", "Annual planning starts today.", false),
        ("ann", "The ANNUAL report is ready.", false),
        ("Lee", "I met Ashlee.", false),
        ("Ann", "I met Ann2 and Ann_team.", false),
        ("Ann", "I met team_Ann.", false),
        ("Ann", "I met Ann-Marie and O'Ann.", false),
        ("Ann", "I met ÉAnn and Ann\u{301}.", false),
        ("Ann", "Ann\u{200d}ual planning starts today.", false),
        ("Ann Lee", "I met Ann, Lee, and Casey.", false),
        ("---", "---", false),
        ("  ", "There is no name here.", false),
        ("Ann", "Ann", true),
        ("Ann", "Annual planning includes Ann.", true),
        ("Ann", "I met (ANN), today.", true),
        ("Ann", "I met Ａｎｎ.", true),
        ("  Ann   Lee  ", "I met ANN\tLEE.", true),
        ("José", "I met Jose\u{301}.", true),
        ("Ann-Marie", "I met Ann-Marie.", true),
    ];
    let mut working_set = Vec::new();
    let mut turn_texts = Vec::new();
    let mut persons = Vec::new();
    for (index, (name, text, _)) in cases.iter().enumerate() {
        let turn = seed_turn(&vault, &conversation, "user", *text, 10);
        working_set.push(turn);
        turn_texts.push((turn, *text));
        persons.push(
            crate::dreamer_consolidation::executor::extraction::ExtractedPerson {
                id: format!("new:P{}", index + 1),
                name: (*name).to_owned(),
                evidence_turn_refs: vec![format!("T{}", index + 1)],
            },
        );
    }
    let sources = TestCallSources::new(&turn_texts);
    let namespace = crate::dreamer_consolidation::extracted_people::MintNamespace::new(
        crate::AttemptId::now(),
        None,
        None,
        None,
        None,
    );
    let bindings =
        crate::dreamer_consolidation::extracted_people::bind_people(&persons, &sources, &namespace);
    crate::dreamer_consolidation::extracted_people::mint_extracted_people(
        &vault,
        &bindings,
        &working_set,
        &source_scope(&vault, &working_set)?,
        20,
        None,
        None,
    )?;
    for (index, (name, text, should_mint)) in cases.iter().enumerate() {
        let number = index + 1;
        match bindings.subject(number) {
            Ok(id) => {
                assert_eq!(
                    vault.entity_exists(&id)?,
                    *should_mint,
                    "name {name:?}, evidence {text:?}"
                );
                if *should_mint {
                    assert_eq!(
                        zero_live_members(&vault, &id)?,
                        Some(CleanupKind::ClaimlessExtractionPerson)
                    );
                }
            }
            Err(_) => {
                assert!(!should_mint, "name {name:?} bound no id but expected mint");
            }
        }
    }
    Ok(())
}

/// One extraction call's labels over the turns it showed, for person-mint
/// tests: each turn labelled `T<n>` in seeding order, showing its text.
struct TestCallSources {
    labels: crate::dreamer_consolidation::call_labels::CallLabelMap,
    texts: std::collections::BTreeMap<crate::EntityId, String>,
}

impl TestCallSources {
    fn new(turns: &[(crate::EntityId, &str)]) -> Self {
        let mut labels = crate::dreamer_consolidation::call_labels::CallLabelMap::default();
        let mut texts = std::collections::BTreeMap::new();
        for (turn, text) in turns {
            labels.assign(
                crate::dreamer_consolidation::call_labels::LabelKind::Turn,
                *turn,
            );
            texts.insert(*turn, (*text).to_owned());
        }
        Self { labels, texts }
    }
}

impl crate::dreamer_consolidation::call_labels::CallSources for TestCallSources {
    fn labels(&self) -> &crate::dreamer_consolidation::call_labels::CallLabelMap {
        &self.labels
    }

    fn shown(
        &self,
        id: crate::EntityId,
    ) -> Option<crate::dreamer_consolidation::call_labels::SourceShown<'_>> {
        self.texts.get(&id).map(
            |text| crate::dreamer_consolidation::call_labels::SourceShown {
                text: Some(text.as_str()),
                project: None,
            },
        )
    }
}

fn source_scope(vault: &Vault, ids: &[EntityId]) -> Result<crate::llm::Scope> {
    let mut scope = crate::llm::Scope::default();
    for id in ids {
        if let Some(body) = vault.get(id)? {
            scope
                .readable
                .insert(super::super::resources::document_version(*id, &body));
        }
    }
    Ok(scope)
}
