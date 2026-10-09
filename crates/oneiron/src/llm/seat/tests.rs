use super::*;
use crate::llm::{
    LlmCatalogCost, LlmCatalogEntry, ModelTierRef,
    manifest::{MODEL_ROLES, ModelBinding, ModelManifest, ModelSlot},
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
    let lines = vault
        .model_description(&a)?
        .unwrap()
        .lines(&vault.seat_policy()?.evidence_order);
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
