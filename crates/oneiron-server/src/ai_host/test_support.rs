//! Shared fixtures for the AI host's tests: a rooted, granted vault and
//! `[models]` pointed at the local fake model server.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

use crate::config::models::{ModelsConfig, ModelsFile};
use crate::fake_llm::Reply;

pub(crate) const TEST_SECRET: &str = "ai-host-test-host-secret";

/// A vault rooted by the test host, with its engine machine writers.
pub(crate) fn rooted_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(TEST_SECRET.as_bytes()).unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    vault.provision_engine_machine_identities(&issuer).unwrap();
    (dir, vault)
}

/// The vault's model route for extraction, as the owner sets it
/// (`oneiron dreamer grant --extraction-route own_server`, or
/// `PUT /v1/llm/defaults`). Boot never writes it.
pub(crate) fn route_extraction(vault: &Vault) {
    super::route_dreamer_extraction(vault, oneiron::ModelLocality::OwnServer).unwrap();
}

/// A model manifest pinning every role to `model` on the LLM slot at
/// `route`, its extraction teacher probe-approved, as an owner pins one.
pub(crate) fn pin_every_role(vault: &Vault, model: &str, route: oneiron::ModelLocality) {
    use oneiron::llm::manifest::{
        MODEL_ROLES, ModelBinding, ModelManifest, ModelSlot, TeacherProbeApproval,
    };
    let manifest = ModelManifest {
        version: 2,
        roles: MODEL_ROLES
            .into_iter()
            .map(|role| {
                (
                    role,
                    ModelBinding {
                        model: oneiron::ModelId::new(model).unwrap(),
                        slot: ModelSlot::Llm,
                        tier: oneiron::ModelTierRef("pinned".into()),
                        route_models: Default::default(),
                    },
                )
            })
            .collect(),
        routes: [
            (ModelSlot::Llm, route),
            (ModelSlot::Embedder, oneiron::ModelLocality::OnDevice),
            (ModelSlot::Oneironer, oneiron::ModelLocality::OnDevice),
        ]
        .into_iter()
        .collect(),
        verdict: None,
        seat_policy: None,
    };
    let approval = TeacherProbeApproval::for_scored_checkpoint(
        &manifest,
        &vault.teacher_probe_policy(None).unwrap(),
        1_000_000,
    )
    .unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &approval)
        .unwrap();
}

/// HIGH-level config: one local model for every seat, egress opted in.
pub(crate) fn models(base_url: &str, extra: &str) -> ModelsConfig {
    models_toml(&format!(
        "default = \"local:test-model\"\nextraction_egress = true\n{extra}\n[providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    ))
}

/// `[models]` as written in `oneiron.toml`.
pub(crate) fn models_toml(text: &str) -> ModelsConfig {
    let file: ModelsFile = toml::from_str(text).unwrap();
    file.resolve(None).unwrap()
}

/// Captures one user turn the way the core turn door does
/// (`POST /v1/core/conversations/{id}/turns`): the text in the TURN body,
/// the TURN a child of a fresh conversation. Returns the TURN id.
pub(crate) fn capture_user_turn(vault: &Vault, text: &str) -> EntityId {
    let conversation = EntityId::now();
    let turn = EntityId::now();
    let at = vault.now_recorded_at();
    let when = TimeRange { start: at, end: at };
    let encode = |body: Value| rmp_serde::to_vec_named(&body).unwrap();
    vault
        .batch()
        .put(
            &conversation,
            ENTITY_TYPE_CONVERSATION,
            when,
            at,
            &encode(json!({"title": "test"})),
        )
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            when,
            at,
            &encode(json!({"txt": text, "spkr": "user", "at": at})),
        )
        .edge_checked(&turn, &conversation, 1.0)
        .commit()
        .unwrap();
    turn
}

/// An extraction answer citing the first turn the transcript shows, as a
/// real model would: the fake reads the source id out of the request.
pub(crate) fn extraction_reply(subject: EntityId, value: &str) -> Reply {
    let value = value.to_owned();
    Reply::Computed(Arc::new(move |request: &Value| {
        let transcript = request["messages"]
            .as_array()
            .and_then(|messages| messages.last())
            .and_then(|message| message["content"].as_str())
            .unwrap_or_default()
            .to_owned();
        let source = transcript
            .split('[')
            .nth(1)
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or_default()
            .to_owned();
        json!({"candidates": [{
            "subject": subject.to_hex(),
            "predicate": "profile.name",
            "value": value,
            "confidence": 0.9,
            "evidence_refs": [{"source_id": source, "byte_range": [0, 4]}],
        }]})
        .to_string()
    }))
}

/// A custom agent definition the pump can dispatch: the seeded default's
/// shape with its own instructions.
pub(crate) fn saved_agent(vault: &Vault, name: &str, instructions: &str) -> EntityId {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .unwrap()
        .expect("seeded default");
    definition.logical_id = None;
    definition.agent_id = format!("test.pump.{name}");
    definition.instructions = Some(instructions.to_owned());
    definition.skills.clear();
    let id = EntityId::now();
    vault
        .put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    id
}

/// Polls `condition` until it holds or `timeout` passes.
pub(crate) async fn eventually(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    condition()
}

/// Every `profile.name` claim about `subject`, with its approval.
pub(crate) fn name_claims(vault: &Vault, subject: &EntityId) -> Vec<oneiron::ClaimBody> {
    vault
        .claims_for_subject(subject)
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).ok().flatten())
        .filter(|body| body.predicate == "profile.name")
        .collect()
}
