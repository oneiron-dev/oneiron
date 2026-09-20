//! Real executor -> sealed sink -> durable evidence/provenance fixture.
use super::*;
use crate::dreamer_consolidation::resources::{BranchResources, document_version};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::llm::Scope;

struct Fixture {
    attempt: crate::dreamer_runner::DreamerAdmittedAttempt,
    turn: EntityId,
    subject: EntityId,
    head: EntityId,
    scope: Scope,
    run: DreamerRunContext,
}

fn policy(vault: &Vault, reader: EntityId, auto: bool) -> Result<()> {
    let row = Value::Map(vec![
        ("max_auto_sensitivity".into(), 3_u64.into()),
        ("receipted".into(), true.into()),
        ("warned".into(), true.into()),
    ]);
    let manifest = Value::Map(vec![
        ("schema_version".into(), "1.1".into()),
        ("pack_id".into(), "prior-head-test".into()),
        ("pack_version".into(), "v1".into()),
        (
            "min_engine_version".into(),
            env!("CARGO_PKG_VERSION").into(),
        ),
        (
            "defaults".into(),
            Value::Map(vec![
                ("criticality".into(), "normal".into()),
                ("sensitivity".into(), "normal".into()),
            ]),
        ),
        ("rules".into(), Value::Array(Vec::new())),
        (
            "actor_ceilings".into(),
            Value::Array(
                ["agent", "human", "first_party"]
                    .map(|actor| {
                        Value::Map(vec![
                            ("actor_class".into(), actor.into()),
                            (
                                "ceiling".into(),
                                if actor == "agent" && !auto {
                                    "proposed"
                                } else {
                                    "auto"
                                }
                                .into(),
                            ),
                        ])
                    })
                    .to_vec(),
            ),
        ),
        (
            "source_trust".into(),
            Value::Map(
                [
                    ClaimSource::Generated,
                    ClaimSource::UserStated,
                    ClaimSource::Observed,
                    ClaimSource::Inferred,
                    ClaimSource::Imported,
                    ClaimSource::ToolOutput,
                ]
                .map(|source| (source.as_str().into(), row.clone()))
                .to_vec(),
            ),
        ),
        (
            "scoped_grants".into(),
            Value::Array(vec![Value::Map(vec![
                ("actor_ref".into(), reader.to_hex().into()),
                ("effector".into(), "core:read".into()),
                ("receipt_required".into(), false.into()),
            ])]),
        ),
        (
            "signature".into(),
            Value::Map(vec![
                ("alg".into(), "ed25519".into()),
                ("key_id".into(), "prior-test".into()),
                ("sig".into(), "prior-test-signature".into()),
            ]),
        ),
    ]);
    let bytes = super::super::support::encode_value(&manifest)?;
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

fn fixture(vault: &Vault) -> Result<Fixture> {
    let actor = vault.dreamer_authority()?;
    policy(vault, actor.entity_ref(), true)?;
    let store = DreamerRunnerStore::new(vault);
    let (attempt, turns, _) =
        admitted_attempt_fixture(vault, &store, 0x58, &[("user", "my name is Oleksii")])?;
    let subject = EntityId::now();
    let owner = EntityId::now();
    for id in [subject, owner] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    }
    let head = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new("owner statement".into())?,
        ClaimApprovalStatus::Approved,
    );
    vault
        .batch()
        .claim_candidate(
            &head,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(subject),
                "Oleksii".into(),
                0.9,
            ),
            &envelope,
            occurred(2),
            2,
        )
        .commit()?;
    let (partition, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
    let branch = BranchResources::open(
        vault,
        actor,
        partition,
        &turns,
        attempt.status.attempt.id,
        None,
    )?;
    let mut scope = branch.scope().clone();
    let pin = document_version(head, &vault.get(&head)?.expect("head body"));
    scope.readable.insert(pin.clone());
    scope.writable.insert(pin);
    // Project semantics remain the exact source/head document slice.
    scope.project = Some(EntityId::now());
    scope
        .writable
        .remove(&super::super::gap::branch_gap_projection(
            &partition,
            branch.scope(),
        ));
    scope
        .writable
        .insert(super::super::gap::branch_gap_projection(&partition, &scope));
    let run = DreamerRunContext {
        run_id: attempt.status.attempt.run_id.clone().expect("queued run"),
        attempt_id: attempt.status.attempt.id,
        agent_actor: actor,
        now_ms: 21_000,
    };
    Ok(Fixture {
        attempt,
        turn: turns[0],
        subject,
        head,
        scope,
        run,
    })
}

fn execute(
    vault: &Vault,
    fx: &Fixture,
    backend: &dyn LlmBackend,
    sink: &mut dyn ConsolidationSink,
    scope: Scope,
) -> Result<DreamerAttemptExecution> {
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut executor = ConsolidationExecutor {
        backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: fx.run.agent_actor,
        model: crate::ModelId::new("test/model@r1").unwrap(),
        sink,
        scope: Some(scope),
    };
    block_on_ready(executor.execute(
        &fx.attempt,
        &mut WakeAttemptContext {
            vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms: 21_000,
        },
    ))
}

fn extract(fx: &Fixture, value: &str) -> crate::LlmResponse {
    text_response(
        serde_json::json!({"candidates": [{
            "subject": fx.subject.to_hex(), "predicate": "profile.name", "value": value,
            "evidence_turn_refs": [fx.turn.to_hex()], "confidence": 0.8,
        }]})
        .to_string(),
    )
}

fn names(vault: &Vault, subject: EntityId) -> Result<Vec<EntityId>> {
    vault
        .claims_for_subject(&subject)?
        .into_iter()
        .filter_map(|id| match vault.get_claim(&id) {
            Ok(Some(body)) if body.predicate == "profile.name" => Some(Ok(id)),
            Err(error) => Some(Err(error)),
            _ => None,
        })
        .collect()
}

#[test]
fn exact_persisted_head_attaches_evidence_without_judge_or_duplicate_and_survives_reopen()
-> Result<()> {
    let (dir, vault) = open_vault();
    let fx = fixture(&vault)?;
    let before = vault.get_raw(&fx.head)?.expect("head");
    let backend = ScriptedBackend::new(vec![Ok(extract(&fx, "Oleksii"))]);
    let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
    assert!(matches!(
        execute(&vault, &fx, &backend, &mut sink, fx.scope.clone())?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1); // extraction only
    assert_eq!(sink.outcome.landed, vec![fx.head]);
    assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&before));
    assert_eq!(names(&vault, fx.subject)?, vec![fx.head]);
    assert_eq!(
        vault.sources(&fx.head, EdgeKind::Supports, None)?,
        vec![fx.turn]
    );
    let edges = vault.edges_out(&fx.turn)?;
    let support = edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::Supports && edge.target == fx.head)
        .expect("evidence");
    assert!(support.provenance.is_some());
    assert!(
        vault
            .store
            .gate_decisions(1_000)?
            .iter()
            .any(|receipt| receipt.claim_id == Some(*fx.head.as_bytes())
                && receipt.actor_ref.as_deref()
                    == Some(fx.run.agent_actor.entity_ref().to_hex().as_str())
                && receipt.outcome == "allow")
    );
    // Memoized replay neither calls the model nor creates a duplicate edge.
    assert!(matches!(
        execute(&vault, &fx, &backend, &mut sink, fx.scope.clone())?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    drop(sink);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&before));
    assert_eq!(names(&vault, fx.subject)?, vec![fx.head]);
    assert_eq!(
        vault.sources(&fx.head, EdgeKind::Supports, None)?,
        vec![fx.turn]
    );
    Ok(())
}

struct JudgeBackend {
    inner: ScriptedBackend,
    requests: Mutex<Vec<LlmRequest>>,
}
impl LlmBackend for JudgeBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.requests.lock().unwrap().push(request.clone());
        self.inner.generate(request, lease)
    }
    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.inner.stream(request, lease)
    }
}

#[test]
fn different_value_consults_one_prior_and_outage_leaves_original_and_open_conflict() -> Result<()> {
    for outage in [false, true] {
        let (_dir, vault) = open_vault();
        let fx = fixture(&vault)?;
        let before = vault.get_raw(&fx.head)?.expect("head");
        let judge = if outage {
            Err(crate::LlmError::Fatal(crate::FatalLlmError::InvalidRequest))
        } else {
            Ok(text_response("{\"resolution\":\"accumulate\"}".into()))
        };
        let backend = JudgeBackend {
            inner: ScriptedBackend::new(vec![Ok(extract(&fx, "Alex")), judge]),
            requests: Mutex::new(Vec::new()),
        };
        let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
        let result = execute(&vault, &fx, &backend, &mut sink, fx.scope.clone())?;
        assert_eq!(backend.inner.calls.load(Ordering::SeqCst), 2);
        let requests = backend.requests.lock().unwrap();
        let user_text: String = requests[1]
            .messages
            .iter()
            .flat_map(|message| &message.content)
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert!(user_text.contains(&fx.head.to_hex()));
        assert!(user_text.contains("Oleksii"));
        assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&before));
        if outage {
            assert!(matches!(result, DreamerAttemptExecution::Park { .. }));
            assert_eq!(names(&vault, fx.subject)?, vec![fx.head]);
            let markers = vault
                .claims_for_subject(&fx.subject)?
                .into_iter()
                .map(|id| vault.get_claim(&id))
                .collect::<Result<Vec<_>>>()?;
            assert!(
                markers
                    .iter()
                    .flatten()
                    .any(|body| body.predicate == crate::claim::PREDICATE_CONFLICT_OPEN)
            );
        } else {
            assert!(matches!(result, DreamerAttemptExecution::Completed { .. }));
            assert_eq!(names(&vault, fx.subject)?.len(), 2);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Drift {
    Source(EntityId),
    Head(EntityId),
    ReadGrant,
}

struct DriftSink<'a> {
    inner: PromotionWriterSink<'a>,
    drift: Drift,
}
impl ConsolidationSink for DriftSink<'_> {
    fn accept(&mut self, _candidates: Vec<PromotionCandidate>) -> Result<()> {
        panic!("scoped executor must not call unbounded persistence")
    }
    fn accept_scoped(&mut self, write: ScopedConsolidationWrite) -> Result<()> {
        match self.drift {
            Drift::Source(turn) => self.inner.vault.put_entity(
                &turn,
                ENTITY_TYPE_TURN,
                occurred(10),
                10,
                &turn_body("user", "changed after assembly", None),
            )?,
            Drift::Head(head) => {
                let mut body = self.inner.vault.get_claim(&head)?.expect("head");
                body.value = Value::from("owner corrected value");
                self.inner.vault.put_claim(&head, &body, occurred(2), 2)?;
            }
            Drift::ReadGrant => policy(self.inner.vault, EntityId::now(), true)?,
        }
        self.inner.accept_scoped(write)
    }
}

#[test]
fn missing_head_rights_revoked_actor_and_write_time_source_drift_refuse() -> Result<()> {
    for fault in [
        "read",
        "write",
        "actor",
        "gate",
        "revision",
        "new_revision",
        "head_revision",
        "read_revocation",
    ] {
        let (_dir, vault) = open_vault();
        let fx = fixture(&vault)?;
        let before = vault.get_raw(&fx.head)?.expect("head");
        let pin = document_version(fx.head, &vault.get(&fx.head)?.unwrap());
        let mut scope = fx.scope.clone();
        match fault {
            "read" => {
                scope.readable.remove(&pin);
            }
            "write" => {
                scope.writable.remove(&pin);
            }
            "actor" => policy(&vault, EntityId::now(), true)?,
            "gate" => policy(&vault, fx.run.agent_actor.entity_ref(), false)?,
            _ => {}
        }
        let backend = ScriptedBackend::new(vec![Ok(extract(&fx, "Oleksii"))]);
        let sink = PromotionWriterSink::new(&vault, fx.run.clone());
        let result = if fault.ends_with("revision") || fault == "read_revocation" {
            if fault == "new_revision" {
                // A genuinely new belief must carry the same transactional fence.
                scope.readable.remove(&pin);
                scope.writable.remove(&pin);
            }
            let drift = match fault {
                "head_revision" => Drift::Head(fx.head),
                "read_revocation" => Drift::ReadGrant,
                _ => Drift::Source(fx.turn),
            };
            let mut sink = DriftSink { inner: sink, drift };
            execute(&vault, &fx, &backend, &mut sink, scope)
        } else {
            let mut sink = sink;
            execute(&vault, &fx, &backend, &mut sink, scope)
        };
        assert!(result.is_err(), "{fault}");
        if fault == "head_revision" {
            assert_eq!(
                vault.get_claim(&fx.head)?.unwrap().value,
                Value::from("owner corrected value")
            );
        } else {
            assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&before));
        }
        assert_eq!(names(&vault, fx.subject)?, vec![fx.head]);
        assert!(
            vault
                .sources(&fx.head, EdgeKind::Supports, None)?
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn multiple_pinned_priors_remain_context_without_arbitrary_supersession() -> Result<()> {
    for resolution in ["merge", "escalate"] {
        let (_dir, vault) = open_vault();
        let mut fx = fixture(&vault)?;
        let second = EntityId::now();
        let mut body = vault.get_claim(&fx.head)?.unwrap();
        body.value = "Alexander".into();
        vault.put_claim(&second, &body, occurred(2), 2)?;
        let pin = document_version(second, &vault.get(&second)?.unwrap());
        fx.scope.readable.insert(pin.clone());
        fx.scope.writable.insert(pin);
        let originals = [vault.get_raw(&fx.head)?, vault.get_raw(&second)?];
        let backend = ScriptedBackend::new(vec![
            Ok(extract(&fx, "Alex")),
            Ok(text_response(
                serde_json::json!({"resolution": resolution, "value": "Alex"}).to_string(),
            )),
        ]);
        let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
        assert!(matches!(
            execute(&vault, &fx, &backend, &mut sink, fx.scope.clone())?,
            DreamerAttemptExecution::Completed { .. }
        ));
        assert_eq!(
            [vault.get_raw(&fx.head)?, vault.get_raw(&second)?],
            originals
        );
        if resolution == "merge" {
            assert_eq!(sink.outcome.landed.len(), 1, "{:?}", sink.outcome.rejected);
            assert_eq!(
                vault.get_claim(&sink.outcome.landed[0])?.unwrap().value,
                Value::from("Alex")
            );
        } else {
            let markers: Vec<_> = vault
                .claims_for_subject(&fx.subject)?
                .into_iter()
                .filter_map(|id| vault.get_claim(&id).transpose())
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .filter(|body| body.predicate == crate::claim::PREDICATE_CONFLICT_OPEN)
                .collect();
            assert_eq!(markers.len(), 1);
            let ids = markers[0]
                .value
                .as_map()
                .unwrap()
                .iter()
                .find(|(key, _)| key.as_str() == Some("prior_heads"))
                .unwrap()
                .1
                .as_array()
                .unwrap();
            assert!(ids.contains(&Value::Binary(fx.head.as_bytes().to_vec())));
            assert!(ids.contains(&Value::Binary(second.as_bytes().to_vec())));
        }
    }
    Ok(())
}
