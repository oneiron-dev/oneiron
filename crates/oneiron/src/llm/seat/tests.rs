use super::*;
use crate::llm::{
    LlmCatalogCost, LlmCatalogEntry, ModelTierRef,
    manifest::{MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot},
    registry::{ModelRegistryRow, ModelWireFormat},
};
use std::collections::BTreeMap;

fn model(name: &str) -> ModelId {
    ModelId::new(name).unwrap()
}
fn manifest() -> ModelManifest {
    ModelManifest {
        version: 2,
        roles: MODEL_ROLES
            .into_iter()
            .map(|role| {
                (
                    role,
                    ModelBinding {
                        model: model("provider/a@r1"),
                        slot: ModelSlot::Llm,
                        tier: ModelTierRef("legacy".into()),
                        route_models: BTreeMap::new(),
                    },
                )
            })
            .collect(),
        routes: [ModelSlot::Llm, ModelSlot::Embedder, ModelSlot::Oneironer]
            .into_iter()
            .map(|slot| (slot, ModelLocality::ThirdParty))
            .collect(),
        verdict: None,
        seat_policy: None,
    }
}
fn register(vault: &Vault, name: &str, locality: ModelLocality, facet: &str) -> Result<ModelId> {
    let id = model(name);
    vault.put_model_registry_row(&ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::OpenaiCompat,
        catalog: LlmCatalogEntry {
            model: id.clone(),
            display_name: name.into(),
            locality,
            context_window_tokens: 8192,
            max_output_tokens: Some(1024),
            cost: Some(LlmCatalogCost {
                input_per_million: "1".into(),
                output_per_million: "2".into(),
                cache_read_per_million: None,
                cache_write_per_million: None,
            }),
            capabilities: vec![LlmCapability::Reasoning, LlmCapability::ToolCalling],
            metadata: BTreeMap::new(),
        },
        scores: BTreeMap::new(),
        fetched_at: BTreeMap::new(),
    })?;
    vault.set_model_description(&ModelDescription {
        model: id.clone(),
        facet: facet.into(),
        owner: Some(format!("Owner's description of {name}")),
        measured: Some("Measured on this vault".into()),
        benchmarks: Some("Published evaluation".into()),
        vendor: Some("Vendor copy".into()),
    })?;
    Ok(id)
}
/// Keeps the seeded policy manifest: pinning a manifest needs its
/// teacher-probe row, which the legacy test opener deletes.
fn policy_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).expect("open vault");
    (dir, vault)
}

fn task() -> SeatTask {
    SeatTask {
        kind: SeatKind::Attempt,
        warm_scope: "run-1".into(),
        task: "Analyze this task".into(),
        purpose: crate::llm::CallPurpose::AnswerGen,
        facet: "long-context reasoning".into(),
        required: vec![LlmCapability::ToolCalling],
        min_context_tokens: 4000,
        locality: ModelLocality::ThirdParty,
        override_model: None,
        override_effort: None,
    }
}
struct Judge {
    choice: ModelId,
}
impl SeatJudge for Judge {
    fn judge(&self, task: &SeatTask, candidates: &[SeatCandidate]) -> Result<SeatJudgment> {
        assert!(!task.task.is_empty());
        for candidate in candidates {
            assert!(
                candidate
                    .allowed_efforts
                    .contains(&candidate.default_effort)
            );
            assert_eq!(
                candidate
                    .description
                    .iter()
                    .map(|line| line.source)
                    .collect::<Vec<_>>(),
                vec![
                    DescriptionSource::Owner,
                    DescriptionSource::Measured,
                    DescriptionSource::Benchmarks,
                    DescriptionSource::Vendor
                ]
            );
        }
        Ok(SeatJudgment {
            model: self.choice.clone(),
            effort: None,
            why: "This model's owner line and measured result match the task; low effort first."
                .into(),
        })
    }
}
#[test]
fn task_judgment_uses_descriptions_not_static_role_and_reuses_eligible_warm_seat() -> Result<()> {
    let (_dir, vault) = policy_vault();
    crate::test_util::pin_model_manifest(&vault, &manifest())?;
    let a = register(
        &vault,
        "provider/a@r1",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    let b = register(
        &vault,
        "provider/b@r1",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    let mut pool = SeatPool::new();
    let chosen = pool.birth(&vault, &task(), &Judge { choice: b.clone() })?;
    assert_eq!(
        chosen.effort(),
        SeatPolicy::bundled()?.default_reasoning_ladder[0]
    );
    assert_eq!(chosen.model(), &b);
    assert_ne!(
        chosen.model(),
        &manifest().binding(ModelRole::GenerativeReasoner)?.model
    );
    assert!(!chosen.receipt().reused);
    let reused = pool.birth(&vault, &task(), &Judge { choice: a.clone() })?;
    assert_eq!(reused.id(), chosen.id());
    assert!(reused.receipt().reused);
    let mut child = task();
    child.kind = SeatKind::Child;
    let new = pool.birth(&vault, &child, &Judge { choice: a })?;
    assert_ne!(new.id(), chosen.id());
    assert_eq!(pool.seat(chosen.id()).unwrap().model(), &b);
    Ok(())
}
#[test]
fn fold_changes_model_only_by_new_seat_and_old_pin_survives() -> Result<()> {
    let (_dir, vault) = policy_vault();
    let mut config = manifest();
    let mut policy = SeatPolicy::bundled()?;
    policy.precedence = SeatPrecedence::SeatOverride;
    config.seat_policy = Some(policy);
    crate::test_util::pin_model_manifest(&vault, &config)?;
    let a = register(
        &vault,
        "provider/a@r1",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    let b = register(
        &vault,
        "provider/b@r2",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    let mut pool = SeatPool::new();
    let old = pool.birth(&vault, &task(), &Judge { choice: a.clone() })?;
    let mut next = task();
    next.override_model = Some(b.clone());
    next.override_effort = Some(ReasoningEffort::High);
    assert!(
        pool.birth(&vault, &next, &Judge { choice: b.clone() })
            .is_err()
    );
    assert_eq!(pool.seat(old.id()).unwrap().model(), &a);
    let new = pool.fold_epoch(&vault, old.id(), &next, &Judge { choice: b.clone() })?;
    assert_ne!(new.id(), old.id());
    assert_eq!(
        (new.model().clone(), new.effort()),
        (b, ReasoningEffort::High)
    );
    assert_eq!(
        (pool.seat(old.id()).unwrap().model().clone(), old.effort()),
        (a, ReasoningEffort::Low)
    );
    Ok(())
}
#[test]
fn route_facet_override_and_ineligible_judgment_fail_closed() -> Result<()> {
    let (_dir, vault) = policy_vault();
    crate::test_util::pin_model_manifest(&vault, &manifest())?;
    let remote = register(
        &vault,
        "provider/a@r1",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    let local = register(
        &vault,
        "local/a@r1",
        ModelLocality::OnDevice,
        "long-context reasoning",
    )?;
    let mut pool = SeatPool::new();
    let mut request = task();
    assert!(
        pool.birth(
            &vault,
            &request,
            &Judge {
                choice: local.clone()
            }
        )
        .is_err()
    );
    request.facet = "other profile".into();
    assert!(
        pool.birth(
            &vault,
            &request,
            &Judge {
                choice: remote.clone()
            }
        )
        .is_err()
    );
    request = task();
    request.override_model = Some(local.clone());
    assert!(
        pool.birth(
            &vault,
            &request,
            &Judge {
                choice: remote.clone()
            }
        )
        .is_err()
    );
    request.override_model = None;
    request.min_context_tokens = 8193;
    assert!(
        pool.birth(
            &vault,
            &request,
            &Judge {
                choice: remote.clone()
            }
        )
        .is_err()
    );
    let mut pinned = manifest();
    pinned
        .routes
        .insert(ModelSlot::Llm, ModelLocality::OnDevice);
    crate::test_util::pin_model_manifest(&vault, &pinned)?;
    assert!(
        pool.birth(&vault, &task(), &Judge { choice: remote })
            .is_err()
    );
    request = task();
    request.locality = ModelLocality::OnDevice;
    let seat = pool.birth(&vault, &request, &Judge { choice: local })?;
    assert_eq!(seat.locality(), ModelLocality::OnDevice);
    Ok(())
}
#[test]
fn descriptions_are_revision_pinned_and_require_registered_model() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let a = register(
        &vault,
        "provider/a@r1",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    assert!(vault.model_description(&model("provider/a@r2"))?.is_none());
    let lines = vault.model_description(&a)?.unwrap().lines();
    assert_eq!(lines[0].source, DescriptionSource::Owner);
    assert!(
        vault
            .set_model_description(&ModelDescription {
                model: model("provider/a@r2"),
                facet: "reasoning".into(),
                owner: Some("owner".into()),
                measured: None,
                benchmarks: None,
                vendor: None,
            })
            .is_err()
    );
    Ok(())
}

#[test]
fn failed_fold_keeps_old_prefix_and_seat_binding_controls_request() -> Result<()> {
    use crate::llm::{
        CallClass, CallEnvelope, CallPurpose, LlmRequest, ResponseFormat, TierPrecedence,
    };
    let (_dir, vault) = policy_vault();
    crate::test_util::pin_model_manifest(&vault, &manifest())?;
    let a = register(
        &vault,
        "provider/a@r1",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    let mut pool = SeatPool::new();
    let seat = pool.birth(&vault, &task(), &Judge { choice: a.clone() })?;
    let mut bad = task();
    bad.override_model = Some(model("unknown/b@r2"));
    assert!(
        pool.fold_epoch(&vault, seat.id(), &bad, &Judge { choice: a.clone() })
            .is_err()
    );
    let still_warm = pool.birth(
        &vault,
        &task(),
        &Judge {
            choice: model("unknown/c@r3"),
        },
    )?;
    assert_eq!(still_warm.id(), seat.id());
    let mut request = LlmRequest {
        model: model("host/unbound@r1"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            tier: TierPrecedence::for_purpose(&CallPurpose::AnswerGen, ModelTierRef("host".into())),
            locality: ModelLocality::OnDevice,
        },
        messages: vec![],
        tools: vec![],
        params: BTreeMap::from([("reasoning_effort".into(), serde_json::json!("stale"))]),
        provider_options: BTreeMap::new(),
    };
    seat.bind(&mut request);
    assert_eq!(request.model, a);
    assert_eq!(request.envelope.locality, ModelLocality::ThirdParty);
    assert_eq!(request.params["reasoning_effort"], serde_json::json!("low"));
    assert_eq!(request.envelope.seat_effort, Some(ReasoningEffort::Low));
    Ok(())
}

#[test]
fn stale_fold_cannot_reactivate_a_retired_seat() -> Result<()> {
    let (_dir, vault) = policy_vault();
    crate::test_util::pin_model_manifest(&vault, &manifest())?;
    let a = register(
        &vault,
        "provider/a@r1",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    let b = register(
        &vault,
        "provider/b@r2",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    let mut pool = SeatPool::new();
    let first = pool.birth(&vault, &task(), &Judge { choice: a })?;
    let mut next = task();
    next.override_model = Some(b.clone());
    let second = pool.fold_epoch(&vault, first.id(), &next, &Judge { choice: b.clone() })?;
    let mut bad = task();
    bad.override_model = Some(model("unknown/c@r3"));
    assert!(
        pool.fold_epoch(&vault, first.id(), &bad, &Judge { choice: b.clone() })
            .is_err()
    );
    let reused = pool.birth(
        &vault,
        &task(),
        &Judge {
            choice: model("unknown/d@r4"),
        },
    )?;
    assert_eq!(reused.id(), second.id());
    assert_eq!(reused.model(), &b);
    Ok(())
}

#[test]
fn run_seat_receipt_is_persisted_before_calls_and_reused_after_reopen() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let run_id = crate::test_util::entity(0xb7);
    let first = {
        let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
        crate::test_util::pin_model_manifest(&vault, &manifest())?;
        let a = register(
            &vault,
            "provider/a@r1",
            ModelLocality::ThirdParty,
            "long-context reasoning",
        )?;
        register(
            &vault,
            "provider/b@r2",
            ModelLocality::ThirdParty,
            "long-context reasoning",
        )?;
        let seat = vault.birth_model_seat(run_id, &task(), &Judge { choice: a })?;
        assert_eq!(
            vault.model_seat_receipt(run_id)?.unwrap().model,
            *seat.model()
        );
        seat
    };
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let resumed = vault.birth_model_seat(
        run_id,
        &task(),
        &Judge {
            choice: model("provider/b@r2"),
        },
    )?;
    assert_eq!(resumed.model(), first.model());
    assert_eq!(resumed.effort(), first.effort());
    assert_eq!(resumed.receipt().why, first.receipt().why);
    assert!(resumed.receipt().reused);
    let mut changed = task();
    changed.task = "different task".into();
    assert!(
        vault
            .birth_model_seat(
                run_id,
                &changed,
                &Judge {
                    choice: model("provider/b@r2")
                }
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn manifest_and_description_policy_rows_drive_defaults_and_cap_holder_widening() -> Result<()> {
    use crate::llm::routing::{DescriptionPolicy, ModelDescription as PolicyModel, OwnerModelLine};
    let (_dir, vault) = policy_vault();
    let mut config = manifest();
    let mut policy = SeatPolicy::bundled()?;
    policy.vault_ceiling = ReasoningEffort::High;
    policy.precedence = SeatPrecedence::SeatOverride;
    policy.global_default = Some(ReasoningEffort::Low);
    policy
        .purpose_defaults
        .insert("answer_gen".into(), ReasoningEffort::Medium);
    config.seat_policy = Some(policy.clone());
    crate::test_util::pin_model_manifest(&vault, &config)?;
    let model = register(
        &vault,
        "provider/worker@r1",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    // Existing per-model description-policy ladders are authoritative over the
    // bundled reasoning ladder; vault/purpose/global rows resolve here too.
    vault.set_description_policy(&DescriptionPolicy {
        models: vec![PolicyModel {
            model: model.clone(),
            wire: ModelWireFormat::OpenaiCompat,
            locality: ModelLocality::ThirdParty,
            owner: Some(OwnerModelLine {
                model: model.clone(),
                text: "task worker".into(),
                expected_quality: 900_000,
            }),
            public_benchmark: None,
            vendor: None,
            effort_ladder: vec![
                ReasoningEffort::High,
                ReasoningEffort::Medium,
                ReasoningEffort::Low,
                ReasoningEffort::XHigh,
            ],
        }],
        contradiction_margin_millionths: 100_000,
        vault_effort: None,
        purpose_effort: BTreeMap::new(),
        global_effort: None,
    })?;
    let mut task = task();
    task.warm_scope = "policy-worker".into();
    let seat = vault.birth_model_seat(
        crate::test_util::entity(0xd1),
        &task,
        &Judge {
            choice: model.clone(),
        },
    )?;
    assert_eq!(seat.effort(), ReasoningEffort::Medium);
    assert_eq!(seat.receipt().effort, ReasoningEffort::Medium);
    // Changing a policy-manifest row changes a *new* seat, not the old pin.
    policy
        .purpose_defaults
        .insert("answer_gen".into(), ReasoningEffort::High);
    config.seat_policy = Some(policy.clone());
    crate::test_util::pin_model_manifest(&vault, &config)?;
    task.warm_scope = "policy-worker-2".into();
    let next = vault.birth_model_seat(
        crate::test_util::entity(0xd2),
        &task,
        &Judge {
            choice: model.clone(),
        },
    )?;
    assert_eq!(next.effort(), ReasoningEffort::High);
    assert_eq!(seat.effort(), ReasoningEffort::Medium);
    // The holder override cannot escape the vault ceiling, even in
    // SeatOverride mode and even when the model's ladder contains xhigh.
    policy.model_ladders.insert(
        model.clone(),
        vec![
            ReasoningEffort::High,
            ReasoningEffort::XHigh,
            ReasoningEffort::Medium,
        ],
    );
    config.seat_policy = Some(policy);
    crate::test_util::pin_model_manifest(&vault, &config)?;
    task.warm_scope = "policy-worker-3".into();
    task.override_effort = Some(ReasoningEffort::XHigh);
    let run_id = crate::test_util::entity(0xd3);
    assert!(
        vault
            .birth_model_seat(run_id, &task, &Judge { choice: model })
            .is_err()
    );
    assert!(vault.model_seat_receipt(run_id)?.is_none());
    Ok(())
}

#[test]
fn default_nested_narrowing_and_manifest_description_budgets() -> Result<()> {
    let (_dir, vault) = policy_vault();
    let mut config = manifest();
    crate::test_util::pin_model_manifest(&vault, &config)?;
    let model = register(
        &vault,
        "provider/worker@r1",
        ModelLocality::ThirdParty,
        "long-context reasoning",
    )?;
    let mut task = task();
    task.warm_scope = "narrowing".into();
    task.override_effort = Some(ReasoningEffort::High);
    assert!(
        vault
            .birth_model_seat(
                crate::test_util::entity(0xd4),
                &task,
                &Judge {
                    choice: model.clone()
                }
            )
            .is_err()
    );
    let description = ModelDescription {
        model: model.clone(),
        facet: "profile".into(),
        owner: Some("x".repeat(4097)),
        measured: None,
        benchmarks: None,
        vendor: None,
    };
    assert!(vault.set_model_description(&description).is_err());
    let mut policy = SeatPolicy::bundled()?;
    policy.line_max_bytes = 5000;
    policy.facet_max_bytes = 512;
    config.seat_policy = Some(policy);
    crate::test_util::pin_model_manifest(&vault, &config)?;
    vault.set_model_description(&description)?;
    assert_eq!(vault.model_description(&model)?, Some(description));
    Ok(())
}
