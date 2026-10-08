//! Shared fixtures for the AI host's tests: a rooted, granted vault and
//! `[models]` pointed at the local fake model server.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
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

/// The owner's one-time weave grant, as `oneiron dreamer grant` makes it.
pub(crate) fn grant_dreamer(vault: &Vault) {
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

/// Witnesses one user turn as the vault owner; returns the TURN id.
pub(crate) fn witness_user_turn(vault: &Vault, conversation: &EntityId, text: &str) -> EntityId {
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&oneiron::memory::WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![oneiron::memory::WitnessMessage {
                id: None,
                author: oneiron::memory::WitnessAuthor::User,
                message_type: "text".into(),
                content: text.into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: vault.now_recorded_at(),
        })
        .unwrap();
    oneiron::memory::resolve_entity_ref(vault, &receipt.turn_short_id).unwrap()
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
