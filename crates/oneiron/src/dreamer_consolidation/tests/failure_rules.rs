//! A resident-authored policy changes what the real executor can publish on fatal fallback.
use super::*;
use crate::code_run::{HostSelfDispatcher, SelfCall, SelfDispatcher, SelfMemoryPutClaimCall};

fn rows(subject: EntityId, turn: EntityId, eligible: bool) -> Vec<u8> {
    let mut rows = Vec::new();
    for stage in ["extraction", "conflict"] {
        for failure in ["retryable", "fatal", "budget"] {
            let (route, value) = match (stage, failure) {
                ("extraction", "fatal") => (
                    "declared_fallback",
                    Some(serde_json::json!({"persons":[{
                        "id": EntityId::from_bytes([0x68; 16]).expect("person").to_hex(),
                        "name":"Oleksii", "evidence_turn_refs":[turn.to_hex()]
                    }], "candidates":[{
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
        super::prior_heads::policy(&vault, vault.dreamer_authority()?.entity_ref(), true)?;
        let store = DreamerRunnerStore::new(&vault);
        let (admitted, turns, _) = admitted_attempt_fixture(
            &vault,
            &store,
            if eligible { 0x63 } else { 0x64 },
            &[("user", "my name is Oleksii")],
        )?;
        let subject = EntityId::from_bytes([0x65; 16])?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        let resident = EntityId::from_bytes([0x69; 16])?;
        vault.put_entity(&resident, ENTITY_TYPE_PERSON, occurred(1), 1, b"resident")?;
        let author = WriteActor::new(resident, EdgeActorClass::Agent);
        let authored: serde_json::Value =
            serde_json::from_slice(&rows(subject, turns[0], eligible))
                .expect("valid authored rows");
        let value = super::super::value_projection::json_to_rmpv(&authored);
        crate::dreamer_consolidation::prepare_authored_claim(
            crate::dreamer_consolidation::DREAMER_FAILURE_RULES_PREDICATE,
            &value,
        )
        .expect("authored rows accepted before dispatch");
        let claim_id = EntityId::from_bytes([0x6a; 16])?;
        let outcome = HostSelfDispatcher::new(&vault, author, "resident-chat-rule")?.dispatch(
            SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                claim_id,
                ClaimCandidate::new(
                    crate::dreamer_consolidation::DREAMER_FAILURE_RULES_PREDICATE,
                    ClaimSubject::Entity(resident),
                    value,
                    1.0,
                ),
                occurred(21),
                21,
            )),
        )?;
        assert!(matches!(
            outcome,
            crate::code_run::SelfDispatchOutcome::MemoryWrite(_)
        ));
        let record = vault.get_claim(&claim_id)?.expect("authored record");
        assert_eq!(record.source, Some(ClaimSource::Generated));
        assert!(crate::dreamer_consolidation::admitted_authored_claim(
            &vault, &claim_id, author
        )?);
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
        let person = EntityId::from_bytes([0x68; 16])?;
        let minted = vault.get_raw(&person)?;
        assert_eq!(
            minted.is_some(),
            eligible,
            "fallback PERSON follows eligibility"
        );
        if eligible {
            assert_eq!(sink.accepted[0].evidence_turn_refs, turns);
            let row = minted.expect("minted person");
            let mut body = &row[crate::batch::ENTITY_METADATA_HEADER_LEN..];
            let Value::Map(fields) =
                rmpv::decode::read_value(&mut body).expect("minted person body")
            else {
                panic!("person body map")
            };
            assert!(
                fields
                    .iter()
                    .any(|(key, value)| key.as_str() == Some("name")
                        && value.as_str() == Some("Oleksii"))
            );
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
    let resident = EntityId::from_bytes([0x69; 16])?;
    vault.put_entity(&resident, ENTITY_TYPE_PERSON, occurred(1), 1, b"resident")?;
    let author = WriteActor::new(resident, EdgeActorClass::Agent);
    assert!(
        vault
            .set_dreamer_failure_rules(WriteActor::new(subject, EdgeActorClass::Human), &rules,)
            .is_err()
    );
    let mut value: serde_json::Value = serde_json::from_slice(&rules).expect("valid rules");
    value["rows"][1]["effector_eligible"] = true.into();
    assert!(
        vault
            .set_dreamer_failure_rules(author, &serde_json::to_vec(&value).expect("valid json"),)
            .is_err()
    );
    value["rows"][1]["effector_eligible"] = false.into();
    value["rows"][1]["route"] = "step_retry".into();
    assert!(
        vault
            .set_dreamer_failure_rules(author, &serde_json::to_vec(&value).expect("valid json"),)
            .is_err()
    );
    value["rows"][1]["route"] = "declared_fallback".into();
    let extraction = value["rows"][1]["value"]
        .as_object_mut()
        .expect("fallback value");
    extraction.remove("persons");
    extraction.insert("people".into(), serde_json::json!([]));
    assert!(
        vault
            .set_dreamer_failure_rules(author, &serde_json::to_vec(&value).expect("json"))
            .is_err()
    );
    let forged = EntityId::from_bytes([0x6b; 16])?;
    let authored: serde_json::Value = serde_json::from_slice(&rules).expect("rules");
    assert!(
        HostSelfDispatcher::new(&vault, author, "resident-forgery")?
            .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                forged,
                ClaimCandidate::new(
                    crate::dreamer_consolidation::DREAMER_FAILURE_RULES_PREDICATE,
                    ClaimSubject::Entity(subject),
                    super::super::value_projection::json_to_rmpv(&authored),
                    1.0,
                ),
                occurred(1),
                1,
            )))
            .is_err()
    );
    assert!(vault.get_claim(&forged)?.is_none());
    // The system Dreamer executes partitions but cannot impersonate the
    // resident who authors this policy, even through the first-party call.
    let dreamer = vault.dreamer_authority()?;
    super::prior_heads::policy(&vault, dreamer.entity_ref(), true)?;
    let dreamer_claim = EntityId::from_bytes([0x6c; 16])?;
    assert!(
        HostSelfDispatcher::new(&vault, dreamer, "system-dreamer-rule")?
            .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                dreamer_claim,
                ClaimCandidate::new(
                    crate::dreamer_consolidation::DREAMER_FAILURE_RULES_PREDICATE,
                    ClaimSubject::Entity(dreamer.entity_ref()),
                    super::super::value_projection::json_to_rmpv(&authored),
                    1.0,
                ),
                occurred(1),
                1,
            )))
            .is_err()
    );
    assert!(!crate::dreamer_consolidation::admitted_authored_claim(
        &vault,
        &dreamer_claim,
        dreamer
    )?);
    assert!(super::super::failure_rules::load(&vault)?.is_none());
    Ok(())
}

#[test]
fn pending_resident_rule_claim_does_not_activate_policy() -> Result<()> {
    let (_dir, vault) = open_vault();
    let resident = EntityId::from_bytes([0x70; 16])?;
    let subject = EntityId::from_bytes([0x71; 16])?;
    let turn = EntityId::from_bytes([0x72; 16])?;
    vault.put_entity(&resident, ENTITY_TYPE_PERSON, occurred(1), 1, b"resident")?;
    let claim_id = EntityId::from_bytes([0x73; 16])?;
    let authored: serde_json::Value =
        serde_json::from_slice(&rows(subject, turn, true)).expect("valid rows");
    let result = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(resident, EdgeActorClass::Agent),
        "resident-pending-rule",
    )?
    .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        claim_id,
        ClaimCandidate::new(
            crate::dreamer_consolidation::DREAMER_FAILURE_RULES_PREDICATE,
            ClaimSubject::Entity(resident),
            super::super::value_projection::json_to_rmpv(&authored),
            1.0,
        ),
        occurred(1),
        1,
    )));
    assert!(result.is_err(), "a pending rule is not active");
    assert_eq!(
        vault
            .get_claim(&claim_id)?
            .expect("proposal remains")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(super::super::failure_rules::load(&vault)?.is_none());
    Ok(())
}
