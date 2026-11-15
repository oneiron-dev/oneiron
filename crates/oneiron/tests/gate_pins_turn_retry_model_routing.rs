//! OPUS-T0-F gate pins, PR 5 (Engine NOTE 13 Nov 02:19): green pins for five
//! model-routing write gates of OPUS-TRIAGECENSUS's census (census/TRIAGE.md,
//! class GAP-PASSES: real callers pass these gates today, and no running test
//! drove them from a door). Each test drives the door a real caller uses,
//! with that caller's inputs, through the gate, and reads the write back. A
//! pin that goes red is a live refusal of a real caller (GAP-BROKEN).
//!
//! Each test name starts with the census id, so `-- g134_` runs one gate's
//! pins.
//!
//! - G134 `write_model_manifest_in_txn`: a manifest pinned with a passing
//!   teacher probe, then written again under the saved approval.
//! - G142 `validate_context_spec`: a dispatch's context spec resolves.
//! - G55 `ModelManifest::bind_request`: the dreamer's extraction call binds
//!   the offline teacher role.
//! - G187 `declare_embedding_space_in_txn`: the host seeds a fresh space,
//!   and the owner declares it again at its width.
//! - G241 `CatalogSeed::from_installed_pack_in_txn`: the first-party model
//!   catalog pack installs and its rows are read.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test gate_pins_turn_retry_model_routing`.

use std::collections::{BTreeMap, BTreeSet};

use oneiron::context_projection::{
    ChatProjection, ContextResolutionRequest, ContextSpec, MemoryProjection, resolve_context_spec,
};
use oneiron::embed::{EmbeddingSpace, InputKind};
use oneiron::llm::manifest::{
    MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
};
use oneiron::llm::registry::ModelWireFormat;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::skill_hub::pack_catalog::{
    PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackPermissions, PackSource,
    PackSourceAdapter,
};
use oneiron::skill_hub::{
    HubFile, HubPackage, HubPin, HubRef, SkillHubAdapter, SkillHubKind, default_skill_hub_id,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EntityId, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, TimeRange, Vault, VaultConfig,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// ── model routing: G134, G55 ────────────────────────────────────────────

const PIN_TIER: &str = "gate-pins";

/// A v2 manifest binding every role, each to its own model; the extraction
/// encoder on the Oneironer slot and every other role on the LLM slot, all
/// slots routed on device.
fn manifest() -> TestResult<ModelManifest> {
    let mut roles = BTreeMap::new();
    for role in MODEL_ROLES {
        roles.insert(
            role,
            ModelBinding {
                model: ModelId::new(format!("gate-pins/{role:?}@r1"))?,
                slot: if role == ModelRole::ExtractionEncoder {
                    ModelSlot::Oneironer
                } else {
                    ModelSlot::Llm
                },
                tier: ModelTierRef(PIN_TIER.to_owned()),
                route_models: BTreeMap::new(),
                disposition: None,
                reads_audio: false,
            },
        );
    }
    Ok(ModelManifest {
        version: 2,
        roles,
        routes: BTreeMap::from([
            (ModelSlot::Llm, ModelLocality::OnDevice),
            (ModelSlot::Embedder, ModelLocality::OnDevice),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]),
        verdict: None,
        seat_policy: None,
    })
}

/// Pins `manifest` with a passing teacher-probe approval, as the bench
/// publishes one.
fn pin_manifest(vault: &Vault, manifest: &ModelManifest) -> TestResult {
    let policy = vault.teacher_probe_policy(None)?;
    let approval = TeacherProbeApproval::for_scored_checkpoint(manifest, &policy, 1_000_000)?;
    vault.set_model_manifest_with_teacher_approval(manifest, &approval)?;
    Ok(())
}

fn open_device() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    Ok((directory, vault))
}

#[test]
fn g134_a_teacher_approved_manifest_is_pinned_and_rewritten() -> TestResult {
    let (_directory, vault) = open_device()?;
    let manifest = manifest()?;
    pin_manifest(&vault, &manifest)?;
    assert_eq!(vault.model_manifest()?, Some(manifest.clone()));
    // A later write keeps the saved teacher approval.
    let mut rewritten = manifest;
    rewritten
        .roles
        .get_mut(&ModelRole::GenerativeReasoner)
        .ok_or("no reasoner row")?
        .model = ModelId::new("gate-pins/reasoner-next@r2")?;
    vault.set_model_manifest(&rewritten)?;
    assert_eq!(vault.model_manifest()?, Some(rewritten));
    Ok(())
}

#[test]
fn g55_the_dreamers_extraction_call_binds_the_offline_teacher() -> TestResult {
    let (_directory, vault) = open_device()?;
    let manifest = manifest()?;
    pin_manifest(&vault, &manifest)?;
    let teacher = manifest
        .binding(ModelRole::ExtractionTeacher)?
        .model
        .clone();
    // The dreamer's extraction request (dreamer_consolidation/follower_attempt
    // /request.rs), served by the host's supervised native transport.
    let request = LlmRequest {
        model: teacher.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("global".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    };
    let host = HostInferenceContext {
        binding: HostInferenceBinding::SupervisedNativeLocal {
            model: teacher.clone(),
            paid: false,
        },
        extraction_egress: None,
    };
    let authorized = vault.authorize_model_role(ModelRole::ExtractionTeacher, request, &host)?;
    assert_eq!(authorized.binding().model(), &teacher);
    assert_eq!(authorized.request().model, teacher);
    assert_eq!(
        authorized.request().envelope.locality,
        ModelLocality::OnDevice
    );
    Ok(())
}

// ── G142: a dispatch's context spec ─────────────────────────────────────

#[test]
fn g142_a_dispatch_context_spec_resolves() -> TestResult {
    let (_directory, vault) = open_device()?;
    // The shape `agents.spawn` and code mode's `self.context` send: named
    // layers, scoped memory, recent chat and a briefing.
    let projection = resolve_context_spec(
        &vault,
        ContextResolutionRequest {
            spec: ContextSpec {
                layers: vec!["persona".to_owned()],
                memory: MemoryProjection::Scoped {
                    domains: vec!["preference".to_owned()],
                    limit: 8,
                },
                chat: ChatProjection::Recent { last_n: 4 },
                briefing: Some("Summarise the week.".to_owned()),
                annotation: None,
            },
            parent: None,
            context_from: Vec::new(),
            world_scope: None,
        },
    )?;
    assert_eq!(projection.layers, ["persona"]);
    assert_eq!(projection.briefing.as_deref(), Some("Summarise the week."));
    assert!(projection.chat_sections.len() <= 4);
    assert!(projection.memory_sections.len() <= 8);
    Ok(())
}

// ── G187: embedding spaces ──────────────────────────────────────────────

fn text_space(id: &str) -> EmbeddingSpace {
    EmbeddingSpace {
        id: id.to_owned(),
        dimensions: 4,
        accepts: BTreeSet::from([InputKind::Text]),
        query_towers: BTreeSet::from([InputKind::Text]),
        evidence: None,
    }
}

#[test]
fn g187_a_host_seeded_space_is_declared_again_by_the_owner() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    let vault = Vault::open_owned(directory.path(), config)?;
    // The host's `[embedding]` config seeds a fresh space at startup.
    let space = text_space("gate-pins-embedder@r1@own_server");
    vault.seed_embedding_space(space.clone())?;
    let held = vault.embedding_spaces()?;
    assert!(
        held.contains(&space),
        "the seeded space is not held: {held:?}"
    );
    // The owner declares it again at its width, widening what it accepts.
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let mut widened = space.clone();
    widened.accepts.insert(InputKind::Image);
    vault.declare_embedding_space(&owner, widened.clone())?;
    let held = vault.embedding_spaces()?;
    let row = held
        .iter()
        .find(|row| row.id == space.id)
        .ok_or("the declared space is gone")?;
    assert_eq!(row.dimensions, 4);
    assert!(row.accepts.contains(&InputKind::Image));
    Ok(())
}

// ── G241: the installed model catalog ───────────────────────────────────

/// The pinned Git transport's successful fetch of the model-pack fixture
/// tree (as llm/registry/tests.rs models it).
struct CatalogAdapter {
    hub: EntityId,
    endpoint: String,
    source: PackSource,
}

impl SkillHubAdapter for CatalogAdapter {
    fn hub_id(&self) -> EntityId {
        self.hub
    }
    fn kind(&self) -> SkillHubKind {
        SkillHubKind::Git
    }
    fn endpoint(&self) -> Option<&str> {
        Some(&self.endpoint)
    }
    fn fetch_package(&self, _: &HubRef) -> oneiron::Result<HubPackage> {
        Err(oneiron::Error::EntityNotFound)
    }
}

impl PackSourceAdapter for CatalogAdapter {
    fn fetch_pack_source(&self, _: &HubRef) -> oneiron::Result<PackSource> {
        Ok(self.source.clone())
    }
}

/// A data-only pack fits.
struct DataOnlyFit;

impl PackFitPolicy for DataOnlyFit {
    fn evaluate(
        &self,
        _: &PackSource,
        permissions: &PackPermissions,
    ) -> oneiron::Result<PackFitVerdict> {
        assert!(permissions.grants.is_empty());
        assert!(permissions.wakes.is_empty());
        assert!(permissions.bundled_skills.is_empty());
        Ok(PackFitVerdict {
            fits: true,
            rules_hit: false,
            code_auto_install: false,
        })
    }
}

#[test]
fn g241_the_first_party_model_catalog_installs() -> TestResult {
    let (_directory, vault) = open_device()?;
    let source = PackSource::from_files(vec![
        HubFile::new(
            "PACK.md",
            include_bytes!("fixtures/model-pack/PACK.md").to_vec(),
        ),
        HubFile::new(
            "knowledge/catalog.json",
            include_bytes!("fixtures/model-pack/knowledge/catalog.json").to_vec(),
        ),
    ])?;
    let at = TimeRange { start: 1, end: 1 };
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(
        owner,
        "principal:catalog-owner",
        true,
        GateDecisionId::now(),
    )?;
    let hub = default_skill_hub_id()?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:model-catalog", hub)?;
    // The first-party hub's model-catalog subtree, pinned to the fetched bytes.
    let reference = HubRef::new(
        hub,
        "packs/model-catalog",
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    let adapter = CatalogAdapter {
        hub,
        endpoint: vault.skill_hub_record(&hub)?.endpoint,
        source: source.clone(),
    };
    let (source_id, pinned) =
        vault.fetch_pack_from_adapter(&adapter, &reference, &publisher, at, 1)?;
    let ask = vault.prepare_pack_install(source_id, &pinned, &publisher, &DataOnlyFit)?;
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        return Err("the data-only model pack did not install".into());
    };
    assert!(receipt.skills.is_empty());
    let entries = vault.model_catalog_entries(ModelWireFormat::OpenaiCompat)?;
    assert!(!entries.is_empty(), "the installed catalog serves no model");
    assert_eq!(vault.model_registry_rows()?.len(), entries.len());
    // Catalog data never binds a role.
    assert!(vault.model_manifest()?.is_none());
    Ok(())
}
