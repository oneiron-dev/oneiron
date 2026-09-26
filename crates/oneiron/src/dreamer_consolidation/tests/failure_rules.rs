//! A resident-authored policy changes what the real executor can publish on fatal fallback.
use super::*;

fn rows(subject: EntityId, turn: EntityId, eligible: bool) -> Vec<u8> {
    let mut rows = Vec::new();
    for stage in ["extraction", "conflict"] {
        for failure in ["retryable", "fatal", "budget"] {
            let (route, value) = match (stage, failure) {
                ("extraction", "fatal") => (
                    "declared_fallback",
                    Some(serde_json::json!({"people":[], "candidates":[{
                        "subject":subject.to_hex(), "predicate":"profile.name",
                        "value":"from declared fallback", "confidence":0.7,
                        "evidence_turn_refs":[turn.to_hex()]
                    }]})),
                ),
                ("conflict", "fatal") => (
                    "declared_fallback",
                    Some(serde_json::json!({"resolution":"escalate"})),
                ),
                (_, "retryable") => ("step_retry", None),
                _ => ("budget_trap", None),
            };
            rows.push(serde_json::json!({
                "stage":stage, "failure":failure, "route":route,
                "consolidation_eligible":failure == "fatal" && stage == "extraction" && eligible,
                "effector_eligible":false, "value":value
            }));
        }
    }
    serde_json::to_vec(&serde_json::json!({"version":1,"rows":rows})).expect("policy")
}

#[test]
fn resident_failure_rules_route_fatal_extraction_and_clamp_promotion() -> Result<()> {
    for eligible in [false, true] {
        let (_dir, vault) = open_vault();
        let store = DreamerRunnerStore::new(&vault);
        let (admitted, turns, _) = admitted_attempt_fixture(
            &vault,
            &store,
            if eligible { 0x63 } else { 0x64 },
            &[("user", "my name is Oleksii")],
        )?;
        let subject = EntityId::from_bytes([0x65; 16])?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        vault.set_dreamer_failure_rules(
            vault.dreamer_authority()?,
            &rows(subject, turns[0], eligible),
        )?;
        let backend = ScriptedBackend::new(vec![Err(crate::FatalLlmError::Auth.into())]);
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
            actor: vault.dreamer_authority()?,
            model: crate::ModelId::new("test/model@r1").expect("model"),
            sink: &mut sink,
            scope: None,
        };
        let execution = block_on_ready(executor.execute(
            &admitted,
            &mut WakeAttemptContext {
                vault: &vault,
                deadline: &deadline,
                budget_id: "wake",
                now_ms: 21_000,
            },
        ))?;
        assert!(matches!(
            execution,
            DreamerAttemptExecution::Completed { completed_units: 0 }
        ));
        assert_eq!(sink.accepted.len(), usize::from(eligible));
        if eligible {
            assert_eq!(sink.accepted[0].evidence_turn_refs, turns);
        }
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        assert_eq!(guard.read().reserved_units, 0);
    }
    Ok(())
}

#[test]
fn resident_failure_rules_reject_unauthorized_or_unsafe_rows() -> Result<()> {
    let (_dir, vault) = open_vault();
    let subject = EntityId::from_bytes([0x66; 16])?;
    let turn = EntityId::from_bytes([0x67; 16])?;
    let rules = rows(subject, turn, true);
    assert!(
        vault
            .set_dreamer_failure_rules(WriteActor::new(subject, EdgeActorClass::Human), &rules,)
            .is_err()
    );
    let mut value: serde_json::Value = serde_json::from_slice(&rules).expect("valid rules");
    value["rows"][1]["effector_eligible"] = true.into();
    assert!(
        vault
            .set_dreamer_failure_rules(
                vault.dreamer_authority()?,
                &serde_json::to_vec(&value).expect("valid json"),
            )
            .is_err()
    );
    value["rows"][1]["effector_eligible"] = false.into();
    value["rows"][1]["route"] = "step_retry".into();
    assert!(
        vault
            .set_dreamer_failure_rules(
                vault.dreamer_authority()?,
                &serde_json::to_vec(&value).expect("valid json"),
            )
            .is_err()
    );
    assert!(super::super::failure_rules::load(&vault)?.is_none());
    Ok(())
}
