use super::*;
use crate::llm::{
    LlmCapability, LlmCatalogCost, LlmCatalogEntry, ReasoningEffort,
    manifest::{MODEL_ROLES, ModelBinding, ModelManifest, ModelSlot},
    registry::{ModelRegistryRow, ModelWireFormat},
    seat::{SeatCandidate, SeatJudge, SeatJudgment, SeatKind, SeatTask},
};
use std::collections::BTreeMap;

struct TaskJudge {
    choice: ModelId,
}
impl SeatJudge for TaskJudge {
    fn judge(&self, task: &SeatTask, candidates: &[SeatCandidate]) -> Result<SeatJudgment> {
        assert!(candidates.iter().any(|row| row.model == self.choice));
        assert_eq!(
            candidates[0].description[0].text,
            "Can analyze a task with tools"
        );
        Ok(SeatJudgment {
            model: self.choice.clone(),
            effort: Some(ReasoningEffort::Low),
            why: format!("The owner description matches the {} task", task.task),
        })
    }
}

fn configure_seat_vault(vault: &Vault) -> Result<ModelId> {
    let model = ModelId::new("provider/seat@r1").unwrap();
    let manifest = ModelManifest {
        version: 2,
        roles: MODEL_ROLES
            .into_iter()
            .map(|role| {
                (
                    role,
                    ModelBinding {
                        model: model.clone(),
                        slot: ModelSlot::Llm,
                        tier: ModelTierRef("legacy".into()),
                        route_models: BTreeMap::new(),
                    },
                )
            })
            .collect(),
        routes: [ModelSlot::Llm, ModelSlot::Embedder, ModelSlot::Oneironer]
            .into_iter()
            .map(|slot| (slot, ModelLocality::OwnServer))
            .collect(),
        verdict: None,
        seat_policy: None,
    };
    crate::test_util::pin_model_manifest(vault, &manifest)?;
    vault.put_model_registry_row(&ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::OwnServer,
        catalog: LlmCatalogEntry {
            model: model.clone(),
            display_name: "Seat fixture".into(),
            locality: ModelLocality::OwnServer,
            context_window_tokens: 8192,
            max_output_tokens: Some(1024),
            cost: Some(LlmCatalogCost {
                input_per_million: "1".into(),
                output_per_million: "1".into(),
                cache_read_per_million: None,
                cache_write_per_million: None,
            }),
            capabilities: vec![LlmCapability::Reasoning],
            metadata: BTreeMap::new(),
        },
        scores: BTreeMap::new(),
        fetched_at: BTreeMap::new(),
    })?;
    vault.set_model_description(&crate::llm::seat::ModelDescription {
        model: model.clone(),
        facet: "tool-use reasoning".into(),
        owner: Some("Can analyze a task with tools".into()),
        measured: None,
        benchmarks: None,
        vendor: None,
    })?;
    Ok(model)
}

#[test]
fn runtime_attempt_child_and_follower_births_bind_recorded_backend_requests() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let model = configure_seat_vault(&vault)?;
    let lease = BudgetLease::for_test("seat-runtime");
    let actor = seed_person(&vault, 0xa0);
    for (index, kind) in [SeatKind::Attempt, SeatKind::Child, SeatKind::Follower]
        .into_iter()
        .enumerate()
    {
        let run_id = entity(0xc1 + index as u8);
        let task = SeatTask {
            kind,
            warm_scope: format!("run-tree-{index}"),
            task: format!("resolve work {index}"),
            purpose: CallPurpose::AnswerGen,
            facet: "tool-use reasoning".into(),
            required: Vec::new(),
            min_context_tokens: 1024,
            locality: ModelLocality::OwnServer,
            override_model: None,
            override_effort: None,
        };
        let seat = vault.birth_model_seat(
            run_id,
            &task,
            &TaskJudge {
                choice: model.clone(),
            },
        )?;
        let mut config = executor_config(run_id, EngineExecutorLimits::default());
        config.task = task.task.clone();
        config.model = seat.model().clone();
        config.model_locality = seat.locality();
        config.seat_effort = Some(seat.effort());
        let backend = FixtureBackend::new(["finish('done');"]);
        let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
        let gated_write = GatedActorWrite::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            format!("run-{index}"),
        )?;
        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write)
                .with_model_seat(&seat);
        let outcome = block_on_ready(executor.run(&config)).expect("runtime seat bound");
        assert_eq!(outcome.status, EngineExecutorStatus::Complete);
        assert_eq!(outcome.seat_receipt.unwrap().model, model);
        let requests = backend.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].model, model);
        assert_eq!(requests[0].envelope.locality, ModelLocality::OwnServer);
        assert_eq!(requests[0].envelope.seat_effort, Some(ReasoningEffort::Low));
        assert_eq!(
            requests[0].params["reasoning_effort"],
            serde_json::json!("low")
        );
        assert_eq!(vault.model_seat_receipt(run_id)?.unwrap().model, model);
    }
    Ok(())
}

#[test]
fn configured_manifest_refuses_unseated_executor_before_backend_call() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    configure_seat_vault(&vault)?;
    let backend = FixtureBackend::new(std::iter::empty::<&str>());
    let lease = BudgetLease::for_test("unseated-runtime");
    let mut runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let gated_write = gated_actor_write(&vault, "unseated");
    let config = executor_config(entity(0xda), EngineExecutorLimits::default());
    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    assert!(matches!(
        block_on_ready(executor.run(&config)),
        Err(EngineExecutorError::Engine(Error::InvalidConfig(_)))
    ));
    assert!(backend.requests.lock().unwrap().is_empty());
    Ok(())
}
