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

/// The owner's one-time grant, as `oneiron dreamer grant --extraction-route
/// own_server` makes it.
pub(crate) fn grant_dreamer(vault: &Vault) {
    grant_dreamer_weave_only(vault);
    super::route_dreamer_extraction(vault, oneiron::ModelLocality::OwnServer).unwrap();
}

/// The weave grant alone, leaving the vault's inference defaults as shipped.
pub(crate) fn grant_dreamer_weave_only(vault: &Vault) {
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let owner = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    vault.grant_dreamer_weave(&owner, 1).unwrap();
}

/// HIGH-level config: one local model for every seat, egress opted in.
pub(crate) fn models(base_url: &str, extra: &str) -> ModelsConfig {
    let file: ModelsFile = toml::from_str(&format!(
        "default = \"local:test-model\"\nextraction_egress = true\n{extra}\n[providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    ))
    .unwrap();
    file.resolve(None).unwrap()
}

/// Captures one user turn the way the core turn door does
/// (`POST /v1/core/conversations/{id}/turns`): the text in the TURN body,
/// the TURN a child of a fresh conversation. Returns the TURN id.
///
/// Not through `Memory::witness`: a witnessed TURN keeps its text in MESSAGE
/// children, which the Dreamer does not read yet.
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
