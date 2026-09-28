//! A resident-authored policy changes what the real executor can publish on fatal fallback.
use super::*;
use crate::CallClass;
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
                        "evidence_refs":[{"source_id":turn.to_hex(),"byte_range":[0,1]}]
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

fn permits_only_decorated_extraction(request: &LlmRequest) -> bool {
    matches!(&request.envelope.class, CallClass::Durable { fallback }
        if fallback.config.as_ref()
            .and_then(|config| config.pointer("/rows/0/value/candidates/0/value"))
            .and_then(serde_json::Value::as_str) == Some("from declared fallback"))
}

fn set_manifest_failure_policy(
    vault: &Vault,
    consolidation_ceiling: bool,
    effector_ceiling: bool,
    precedence: &str,
) -> Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    let raw = vault.get_raw(&id)?.expect("fixture policy manifest");
    let mut data = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut data).expect("manifest map") else {
        panic!("manifest map")
    };
    entries.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            Some("dreamer_failure_rules" | "dreamer_failure_precedence")
        )
    });
    entries.push(("dreamer_failure_precedence".into(), precedence.into()));
    entries.push((
        "dreamer_failure_rules".into(),
        Value::Array(vec![Value::Map(vec![
            ("failure".into(), "fatal".into()),
            ("route".into(), "fallback".into()),
            (
                "consolidation_eligible".into(),
                consolidation_ceiling.into(),
            ),
            ("effector_eligible".into(), effector_ceiling.into()),
            ("default_consolidation_eligible".into(), false.into()),
            ("default_effector_eligible".into(), false.into()),
        ])]),
    ));
    crate::test_util::put_policy_manifest_bytes(
        vault,
        id,
        &super::super::support::encode_value(&Value::Map(entries))?,
    )
}

fn deny_manifest_consolidation(vault: &Vault) -> Result<()> {
    set_manifest_failure_policy(vault, false, false, "holder_override_capped_at_vault")
}

struct RevokeBeforePromotion<'a> {
    inner: crate::dreamer_promotion::PromotionWriterSink<'a>,
    author: WriteActor,
    revoked: Vec<u8>,
    kind: &'static str,
}

impl ConsolidationSink for RevokeBeforePromotion<'_> {
    fn accept(&mut self, _: Vec<PromotionCandidate>) -> Result<()> {
        panic!("sealed scoped write required")
    }

    fn accept_scoped(&mut self, write: ScopedConsolidationWrite) -> Result<()> {
        match self.kind {
            "manifest" => deny_manifest_consolidation(self.inner.vault)?,
            "stage" => self
                .inner
                .vault
                .set_dreamer_failure_rules(self.author, &self.revoked)?,
            _ => unreachable!(),
        }
        self.inner.accept_scoped(write)
    }
}

fn execute_with_sink(
    vault: &Vault,
    admitted: &crate::dreamer_runner::DreamerAdmittedAttempt,
    backend: &ScriptedBackend,
    guard: &crate::BudgetGuard,
    deadline: &WakePassDeadline,
    sink: &mut dyn ConsolidationSink,
) -> Result<DreamerAttemptExecution> {
    let mut executor = ConsolidationExecutor {
        backend,
        guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink,
        inference: crate::llm::HostInferenceContext {
            extraction_egress: Some(&permits_only_decorated_extraction),
            ..test_inference_host()
        },
        scope: None,
    };
    block_on_ready(executor.execute(
        admitted,
        &mut WakeAttemptContext {
            vault,
            deadline,
            budget_id: "wake",
            now_ms: 21_000,
            prepared_wake: None,
            prepared_attempt: None,
        },
    ))
}

#[test]
fn resident_failure_rules_route_fatal_extraction_and_clamp_promotion() -> Result<()> {
    for (
        eligible,
        on_record_session,
        manifest_denies,
        revoke_before_mint,
        revoke_before_promotion,
        stage_effector,
    ) in [
        (false, false, false, None, None, false),
        (true, false, false, None, None, false),
        (false, true, false, None, None, false),
        (true, true, false, None, None, false),
        (true, false, true, None, None, false),
        (true, false, false, Some("manifest"), None, false),
        (true, false, false, Some("stage"), None, false),
        (true, false, false, None, Some("manifest"), false),
        (true, false, false, None, Some("stage"), false),
        (true, false, false, None, None, true),
    ] {
        let (_dir, vault) = open_vault();
        super::prior_heads::policy(&vault, vault.dreamer_authority()?.entity_ref(), true)?;
        set_manifest_failure_policy(&vault, true, true, "holder_override_capped_at_vault")?;
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
        let definition = crate::agent_def::AgentDefinition::new(
            "oneiron.agent.resident",
            "Resident rule author",
            "1",
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            crate::agent_def::AgentScope::All,
            crate::agent_def::AgentCeiling::Auto,
            None,
            ClaimApprovalStatus::Approved,
            crate::ClaimLifecycleStatus::Active,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            Value::Map(vec![("definedVia".into(), "test".into())]),
            None,
            true,
            None,
        );
        vault.put_agent_definition(&resident, &definition, occurred(1), 1)?;
        assert_eq!(
            vault.get_entity_type(&resident)?,
            Some(crate::registry::ENTITY_TYPE_AGENT_DEF)
        );
        let author = WriteActor::new(resident, EdgeActorClass::Agent);
        let mut authored: serde_json::Value =
            serde_json::from_slice(&rows(subject, turns[0], eligible))
                .expect("valid authored rows");
        if revoke_before_promotion.is_some() {
            authored["rows"][1]["value"]["persons"] = serde_json::json!([]);
        }
        authored["rows"][1]["effector_eligible"] = stage_effector.into();
        let value = super::super::value_projection::json_to_rmpv(&authored);
        crate::dreamer_consolidation::prepare_authored_claim(
            crate::dreamer_consolidation::DREAMER_FAILURE_RULES_PREDICATE,
            &value,
        )
        .expect("authored rows accepted before dispatch");
        let claim_id = EntityId::from_bytes([0x6a; 16])?;
        let call = SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            claim_id,
            ClaimCandidate::new(
                crate::dreamer_consolidation::DREAMER_FAILURE_RULES_PREDICATE,
                ClaimSubject::Entity(resident),
                value,
                1.0,
            ),
            occurred(21),
            21,
        ));
        let outcome = if on_record_session {
            let session = vault.off_record_session_vault().enter(
                "resident-rule-session",
                crate::off_record::OffRecordBackendClass::Local,
            )?;
            session.flip_on_record()?;
            HostSelfDispatcher::for_off_record_session(&session, author, "resident-chat-rule")?
                .dispatch(call)?
        } else {
            HostSelfDispatcher::new(&vault, author, "resident-chat-rule")?.dispatch(call)?
        };
        assert!(matches!(
            outcome,
            crate::code_run::SelfDispatchOutcome::MemoryWrite(_)
        ));
        let record = vault.get_claim(&claim_id)?.expect("authored record");
        assert_eq!(record.source, Some(ClaimSource::Generated));
        assert!(crate::dreamer_consolidation::admitted_authored_claim(
            &vault, &claim_id, author
        )?);
        if manifest_denies {
            deny_manifest_consolidation(&vault)?;
        }
        match revoke_before_mint {
            Some("manifest") => vault
                .test_hooks()
                .install_before_dreamer_person_mint(|vault| {
                    deny_manifest_consolidation(vault).expect("revoke before mint");
                }),
            Some("stage") => {
                let disallowed = rows(subject, turns[0], false);
                vault
                    .test_hooks()
                    .install_before_dreamer_person_mint(move |vault| {
                        vault
                            .set_dreamer_failure_rules(author, &disallowed)
                            .expect("revoke stage rule before mint");
                    });
            }
            None => {}
            _ => unreachable!(),
        }
        let backend = ScriptedBackend::new(vec![Err(crate::FatalLlmError::Auth.into())]);
        let guard = crate::BudgetGuard::with_reserve_units(
            "wake",
            10_000,
            100,
            BudgetExhaustionPolicy::Suspend,
        );
        let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
        let mut sink = CapturingSink::default();
        let execution = if let Some(kind) = revoke_before_promotion {
            let run = crate::dreamer_promotion::DreamerRunContext {
                run_id: admitted
                    .status
                    .attempt
                    .run_id
                    .clone()
                    .unwrap_or_else(|| "run-1".into()),
                attempt_id: admitted.status.attempt.id,
                agent_actor: vault.dreamer_authority()?,
                now_ms: 21_000,
            };
            let mut writer = RevokeBeforePromotion {
                inner: crate::dreamer_promotion::PromotionWriterSink::new(&vault, run),
                author,
                revoked: rows(subject, turns[0], false),
                kind,
            };
            let result =
                execute_with_sink(&vault, &admitted, &backend, &guard, &deadline, &mut writer);
            assert!(result.is_err(), "revocation before promotion must refuse");
            assert!(writer.inner.outcome.landed.is_empty());
            assert!(!writer.inner.outcome.rejected.is_empty());
            assert!(vault.get_raw(&EntityId::from_bytes([0x68; 16])?)?.is_none());
            for id in vault.claims_for_subject(&subject)? {
                assert_ne!(
                    vault.get_claim(&id)?.expect("stored claim").predicate,
                    "profile.name"
                );
            }
            assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
            continue;
        } else {
            execute_with_sink(&vault, &admitted, &backend, &guard, &deadline, &mut sink)
        };
        if revoke_before_mint.is_some() {
            assert!(execution.is_err(), "revocation before mint must refuse");
            assert!(sink.accepted.is_empty());
            assert!(vault.get_raw(&EntityId::from_bytes([0x68; 16])?)?.is_none());
            assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
            continue;
        }
        assert!(matches!(
            execution?,
            DreamerAttemptExecution::Completed { completed_units: 0 }
        ));
        // Even a separate manifest effector permit cannot widen the resident
        // consolidation stage row (whose only valid effector bit is false).
        let txn = vault.store.env.read_txn()?;
        let fallback = crate::LlmResponse {
            message: crate::LlmMessage {
                role: crate::LlmMessageRole::Assistant,
                content: vec![crate::ContentPart::Text {
                    text: "fallback".into(),
                }],
            },
            usage: crate::LlmUsage::zero(),
            finish_reason: crate::FinishReason::Other {
                name: "fallback:json_rules_v1".into(),
            },
        };
        assert_eq!(
            super::super::step_effector_eligible_in_txn(&vault, &txn, "extraction", &fallback,)?,
            Some(stage_effector),
        );
        let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
        assert_eq!(
            policy
                .dreamer_failure_decision(crate::llm::DreamerFailureClass::Fatal)
                .effector_with_stage(Some(stage_effector)),
            stage_effector && !manifest_denies,
        );
        drop(txn);
        let accepted = eligible && !manifest_denies;
        assert_eq!(sink.accepted.len(), usize::from(accepted));
        let person = EntityId::from_bytes([0x68; 16])?;
        let minted = vault.get_raw(&person)?;
        assert_eq!(
            minted.is_some(),
            accepted,
            "fallback PERSON follows eligibility"
        );
        if accepted {
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
    let authored = super::super::value_projection::json_to_rmpv(&value);
    assert!(
        super::super::failure_rules::prepare_authored_claim(
            super::super::failure_rules::PREDICATE,
            &authored,
        )?
        .is_some(),
        "authenticated Fatal stage true is valid policy data"
    );
    assert!(
        vault
            .set_dreamer_failure_rules(author, &serde_json::to_vec(&value).expect("valid json"),)
            .is_err(),
        "PERSON actor cannot author stage policy"
    );
    value["rows"][1]["effector_eligible"] = false.into();
    value["rows"][1]["route"] = "step_retry".into();
    assert!(
        super::super::failure_rules::prepare_authored_claim(
            super::super::failure_rules::PREDICATE,
            &super::super::value_projection::json_to_rmpv(&value),
        )
        .is_err()
    );
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
        super::super::failure_rules::prepare_authored_claim(
            super::super::failure_rules::PREDICATE,
            &super::super::value_projection::json_to_rmpv(&value),
        )
        .is_err()
    );
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
