//! Serving keeps the owner's current view while an admitted agent receives
//! the scoped export's typed Nulled body, without changing stored evidence.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::vault_read::{
    CoreEntityRecord, CoreHydrateRequest, CoreHydrateResponse, CoreHydrateStatus, CoreQueryRequest,
    CountMode, InProcessVaultReadAdapter, VaultReadClient, View,
};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::ModelId;
use oneiron::llm::image::{ImageBytes, ImageResponse};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    agent: EntityId,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let config = VaultConfig {
            dimensions: 4,
            embedding_model: Some("test/model@v1".to_owned()),
            ..VaultConfig::default()
        };
        let vault = Vault::open(dir.path(), config)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"serving-scoped-credentials-host")?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let owner_proof =
            vault.authenticate_owner(owner, "principal:owen", true, GateDecisionId::now())?;
        vault.set_secret_scan_mode(&owner_proof, SecretScanMode::Off, 10)?;

        let agent = EntityId::now();
        create_agent_definition_as(
            &vault,
            &owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": "serving_scoped_reader",
                    "desc": "Read-only credential release fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))?,
            },
        )?;
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let minted = mint_agent_grant_as(
            &vault,
            &owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope: scope.clone(),
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )?;
        assert_eq!(minted.grant.agent, agent, "the read Grant names this agent");
        assert!(minted.grant.confers, "the agent's read Grant is live");
        assert_eq!(
            minted.grant.authority_scope, scope,
            "the live Grant admits all row bands but only the read verb"
        );
        Ok(Self {
            vault,
            _dir: dir,
            owner,
            agent,
        })
    }

    fn store(&self, entity_type: u8, bytes: &[u8]) -> TestResult<EntityId> {
        let id = EntityId::now();
        self.vault.put_entity(
            &id,
            entity_type,
            TimeRange {
                start: 123,
                end: 456,
            },
            789,
            bytes,
        )?;
        assert_eq!(
            self.vault.get(&id)?.as_deref(),
            Some(bytes),
            "raw storage keeps the fixture byte-equal before any serving read"
        );
        Ok(id)
    }

    fn key(&self, actor: EntityId, class: EdgeActorClass) -> TestResult<ScopedReadActorKey> {
        Ok(self.vault.memory(actor, class).read_key()?)
    }

    fn short_ref(&self, id: EntityId) -> TestResult<String> {
        let read = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .get_entity(&id.to_hex())?;
        let view = read
            .value
            .expect("the owner admits the short-ref source row");
        assert_eq!(
            view.id_hex,
            id.to_hex(),
            "the short ref belongs to the fixture row"
        );
        Ok(view
            .short_ref
            .expect("the stored fixture has a canonical short ref"))
    }

    fn core_hydrate(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        reference: &str,
    ) -> TestResult<CoreHydrateResponse> {
        let adapter = InProcessVaultReadAdapter::new(&self.vault, self.key(actor, class)?);
        Ok(adapter.hydrate(CoreHydrateRequest {
            reference: Some(reference.to_owned()),
            short_id: None,
            content_hash: None,
            view: Some(View::Full),
            image_input: false,
            task: None,
            filter: None,
        })?)
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("encode the MessagePack fixture");
    bytes
}

fn credential_person() -> Vec<u8> {
    let credential = format!("ghp_{}", "a".repeat(36));
    let nested_payload = encode(&Value::Map(vec![(
        Value::from("password"),
        Value::from("nested-secret"),
    )]));
    let byte_map_payload = encode(&Value::Map(vec![(
        Value::from("password"),
        Value::from("byte-map-secret"),
    )]));
    let json_bytes_payload = br#"{"api_key":"json-secret"}"#.to_vec();
    let json_encoded_bytes =
        serde_json::json!({"payload": credential.bytes().collect::<Vec<_>>()}).to_string();
    let json_encoded_map =
        serde_json::json!({"payload": br#"{"password":"array-wrapped-secret"}"#.to_vec()})
            .to_string();
    let bytes = encode(&Value::Map(vec![
        (Value::from("name"), Value::from("portable person")),
        (
            Value::from("api_key"),
            Value::from("unrecognizable-but-named-secret"),
        ),
        (
            Value::from("binary"),
            Value::Binary(credential.as_bytes().to_vec()),
        ),
        (
            Value::from("nested_binary"),
            Value::Binary(nested_payload.clone()),
        ),
        (
            Value::from("byte_array"),
            Value::Array(credential.bytes().map(Value::from).collect()),
        ),
        (
            Value::from("json_bytes"),
            Value::Binary(json_bytes_payload.clone()),
        ),
        (
            Value::from("public_binary"),
            Value::Binary(b"inspectable public bytes".to_vec()),
        ),
        (
            Value::from("byte_map"),
            Value::Array(byte_map_payload.iter().copied().map(Value::from).collect()),
        ),
        (
            Value::from("json_encoded_bytes"),
            Value::from(json_encoded_bytes.as_str()),
        ),
        (
            Value::from("json_encoded_map"),
            Value::from(json_encoded_map.as_str()),
        ),
        (Value::from("signature"), Value::Binary(vec![1, 2, 3])),
    ]));
    bytes
}

fn assert_no_secret_text(text: &str) {
    let credential = format!("ghp_{}", "a".repeat(36));
    for secret in [
        credential.as_str(),
        "unrecognizable-but-named-secret",
        "nested-secret",
        "json-secret",
        "byte-map-secret",
        "array-wrapped-secret",
    ] {
        assert!(
            !text.contains(secret),
            "the released body contains no fixture secret, including decoded carriers: {secret}"
        );
    }
}

/// Inspect strings, JSON text, and byte arrays carrying UTF-8 or MessagePack.
fn assert_no_encoded_secrets(value: &serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            assert_no_secret_text(text);
            if let Ok(decoded) = serde_json::from_str::<serde_json::Value>(text) {
                assert_no_encoded_secrets(&decoded);
            }
        }
        serde_json::Value::Array(items) => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            if let Some(bytes) = bytes {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    assert_no_encoded_secrets(&json!(text));
                }
                let mut cursor = bytes.as_slice();
                if let Ok(decoded) = rmpv::decode::read_value(&mut cursor)
                    && cursor.is_empty()
                {
                    assert_no_secret_text(&decoded.to_string());
                }
            }
            for item in items {
                assert_no_encoded_secrets(item);
            }
        }
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                assert_no_secret_text(name);
                assert_no_encoded_secrets(value);
            }
        }
        _ => {}
    }
}

fn assert_nulled_carriers(body: &serde_json::Value) {
    assert_eq!(
        body["name"],
        json!("portable person"),
        "the safe person name is kept"
    );
    for name in ["byte_map", "json_encoded_bytes", "json_encoded_map"] {
        assert!(
            body.get(name).is_none_or(serde_json::Value::is_null),
            "the encoded credential carrier {name} is null or absent"
        );
    }
    assert_no_encoded_secrets(body);
}

fn live_item(response: &CoreHydrateResponse, id: EntityId, entity_type: u8) -> &CoreEntityRecord {
    assert_eq!(
        response.status,
        CoreHydrateStatus::Live,
        "core hydrate admits a live row"
    );
    assert_eq!(
        response.id.as_deref(),
        Some(id.to_hex().as_str()),
        "core hydrate keeps the admitted row id"
    );
    assert_eq!(
        response.entity_type,
        Some(entity_type),
        "core hydrate keeps the admitted row kind"
    );
    let item = response
        .item
        .as_ref()
        .expect("a live admitted row keeps its core item");
    assert_eq!(
        item.id,
        id.to_hex(),
        "the core item belongs to the admitted row"
    );
    item
}

#[test]
fn agent_get_entity_nulls_encoded_credential_carriers() -> TestResult {
    let fixture = Fixture::new()?;
    let id = fixture.store(ENTITY_TYPE_PERSON, &credential_person())?;
    let read = fixture
        .vault
        .memory(fixture.agent, EdgeActorClass::Agent)
        .get_entity(&id.to_hex())?;
    let view = read
        .value
        .expect("the agent's live read Grant admits the PERSON");
    assert_eq!(
        view.id_hex,
        id.to_hex(),
        "the admitted agent view keeps the PERSON id"
    );
    assert_nulled_carriers(
        view.body
            .as_ref()
            .expect("the admitted PERSON keeps its safe body"),
    );
    Ok(())
}

#[test]
fn owner_get_entity_keeps_todays_view() -> TestResult {
    let fixture = Fixture::new()?;
    let bytes = credential_person();
    let id = fixture.store(ENTITY_TYPE_PERSON, &bytes)?;
    let read = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .get_entity(&id.to_hex())?;
    let view = read.value.expect("the owner admits the PERSON");
    assert_eq!(
        view.id_hex,
        id.to_hex(),
        "the owner's view keeps the PERSON id"
    );
    let body = view
        .body
        .expect("the owner keeps today's decoded PERSON body");
    let stored = rmpv::decode::read_value(&mut bytes.as_slice())?;
    let fields = stored.as_map().expect("the fixture is a MessagePack map");
    for name in ["byte_map", "json_encoded_bytes", "json_encoded_map"] {
        let expected = fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
            .expect("the fixture contains the carrier");
        let expected = if name == "byte_map" {
            json!(
                expected
                    .as_array()
                    .expect("byte_map is an array")
                    .iter()
                    .map(|value| value.as_u64().expect("byte_map has byte integers"))
                    .collect::<Vec<_>>()
            )
        } else {
            json!(expected.as_str().expect("the JSON-encoded carrier is text"))
        };
        assert_eq!(
            body[name], expected,
            "the owner's current view keeps {name} as written"
        );
    }
    assert_eq!(
        body["name"],
        json!("portable person"),
        "the owner's view keeps the name"
    );
    Ok(())
}

#[test]
fn agent_reads_a_clean_person_as_the_owner_reads_it() -> TestResult {
    let fixture = Fixture::new()?;
    let expected = json!({
        "name": "yuki",
        "visits": 7,
        "rating": 1.25,
        "interests": ["gardening", 3, 2.5],
        "address": {"city": "Oslo", "floor": 2},
    });
    let bytes = rmp_serde::to_vec_named(&expected)?;
    let id = fixture.store(ENTITY_TYPE_PERSON, &bytes)?;
    let owner = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .get_entity(&id.to_hex())?
        .value
        .expect("the owner admits the clean PERSON");
    let agent = fixture
        .vault
        .memory(fixture.agent, EdgeActorClass::Agent)
        .get_entity(&id.to_hex())?
        .value
        .expect("the agent's live read Grant admits the clean PERSON");
    assert_eq!(
        owner.id_hex,
        id.to_hex(),
        "the owner reads the clean PERSON id"
    );
    assert_eq!(
        agent.id_hex,
        id.to_hex(),
        "the agent reads the same clean PERSON id"
    );
    assert_eq!(
        owner.body.as_ref(),
        Some(&expected),
        "the owner's clean body keeps every JSON type and value"
    );
    assert_eq!(
        agent.body, owner.body,
        "the agent reads the same clean JSON body as the owner"
    );
    Ok(())
}

#[test]
fn agent_core_hydrate_omits_a_changed_asset_body() -> TestResult {
    let fixture = Fixture::new()?;
    let bytes = br#"{"name":"signature.json","signature":"residual-signature"}"#;
    let id = fixture.store(ENTITY_TYPE_ASSET, bytes)?;
    let reference = fixture.short_ref(id)?;
    let owner = fixture.core_hydrate(fixture.owner, EdgeActorClass::Human, &reference)?;
    let owner_item = live_item(&owner, id, ENTITY_TYPE_ASSET);
    let owner_body = owner_item
        .body
        .as_ref()
        .expect("the owner keeps the ASSET body");
    assert_eq!(
        owner_body["name"],
        json!("signature.json"),
        "the owner's hydrate keeps the ASSET name"
    );
    assert_eq!(
        owner_body["signature"],
        json!("residual-signature"),
        "the owner's hydrate keeps today's signature member"
    );
    let agent = fixture.core_hydrate(fixture.agent, EdgeActorClass::Agent, &reference)?;
    let agent_item = live_item(&agent, id, ENTITY_TYPE_ASSET);
    assert!(
        agent_item.body.is_none(),
        "the agent's live ASSET item withholds a body the release rule would change"
    );
    Ok(())
}

#[test]
fn agent_core_hydrate_nulls_encoded_carriers() -> TestResult {
    let fixture = Fixture::new()?;
    let id = fixture.store(ENTITY_TYPE_PERSON, &credential_person())?;
    let reference = fixture.short_ref(id)?;
    let agent = fixture.core_hydrate(fixture.agent, EdgeActorClass::Agent, &reference)?;
    let item = live_item(&agent, id, ENTITY_TYPE_PERSON);
    assert_nulled_carriers(
        item.body
            .as_ref()
            .expect("the agent's admitted core PERSON keeps its safe body"),
    );
    Ok(())
}

#[test]
fn agent_image_hydrate_does_not_serve_encoded_credentials_from_asset_text() -> TestResult {
    let fixture = Fixture::new()?;
    let description =
        json!({"payload": br#"{"password":"array-wrapped-secret"}"#.to_vec()}).to_string();
    let pixels = b"\x89PNG\r\n\x1a\nfixture pixels";
    let response = ImageResponse {
        image: ImageBytes {
            bytes: pixels.to_vec(),
            media_type: "image/png".to_owned(),
        },
        model: ModelId::new("test/image@v1")?,
        metadata: Default::default(),
    };
    let landed = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .land_generated_image(&response, &description, 789)?;
    let id = EntityId::from_hex(&landed.asset_ref)?;
    let text_id = EntityId::from_hex(&landed.asset_text_ref)?;
    let expected_asset = encode(&Value::Map(vec![
        (Value::from("kind"), Value::from("image")),
        (Value::from("mime_type"), Value::from("image/png")),
        (
            Value::from("blake3"),
            Value::from(blake3::hash(pixels).to_hex().as_str()),
        ),
        (Value::from("byte_size"), Value::from(pixels.len() as u64)),
        (Value::from("model"), Value::from("test/image@v1")),
        (Value::from("source"), Value::from("generated")),
    ]));
    assert_eq!(
        fixture.vault.get(&id)?.as_deref(),
        Some(expected_asset.as_slice()),
        "the generated ASSET metadata is stored byte-equal before serving"
    );
    assert_eq!(
        fixture.vault.get(&text_id)?.as_deref(),
        Some(description.as_bytes()),
        "the generated ASSET_TEXT keeps the encoded fixture byte-equal before serving"
    );
    let reference = fixture.short_ref(id)?;
    let owner = fixture.core_hydrate(fixture.owner, EdgeActorClass::Human, &reference)?;
    let owner_item = live_item(&owner, id, ENTITY_TYPE_ASSET);
    let owner_body = owner_item
        .body
        .as_ref()
        .expect("the owner's image hydrate serves a text rung");
    assert_eq!(
        owner_body["form"],
        json!("asset_text"),
        "the owner control selects the ASSET_TEXT rung"
    );
    assert_eq!(
        owner_body["asset_text_ref"],
        json!(landed.asset_text_ref),
        "the owner control serves the landed ASSET_TEXT"
    );
    assert_eq!(
        owner_body["text"],
        json!(description),
        "the owner keeps today's encoded ASSET_TEXT text"
    );
    let agent = fixture.core_hydrate(fixture.agent, EdgeActorClass::Agent, &reference)?;
    let item = live_item(&agent, id, ENTITY_TYPE_ASSET);
    if let Some(body) = &item.body {
        assert_ne!(
            body["text"],
            json!(description),
            "the agent is not served the credential-bearing original ASSET_TEXT"
        );
        assert_no_encoded_secrets(body);
    }
    Ok(())
}

#[test]
fn agent_core_query_nulls_encoded_carriers() -> TestResult {
    let fixture = Fixture::new()?;
    let id = fixture.store(ENTITY_TYPE_PERSON, &credential_person())?;
    let vector = [1.0_f32, 0.0, 0.0, 0.0];
    fixture.vault.batch().vector(&id, &vector).commit()?;
    let adapter = InProcessVaultReadAdapter::new(
        &fixture.vault,
        fixture.key(fixture.agent, EdgeActorClass::Agent)?,
    );
    let query = adapter.query(CoreQueryRequest {
        query: None,
        query_vector: Some(vector.to_vec()),
        media: None,
        query_affect: None,
        limit: 10,
        view: Some(View::Full),
        count_mode: CountMode::Exact,
        filter: None,
    })?;
    let item = query
        .items
        .iter()
        .find(|item| item.id == id.to_hex())
        .expect("the agent's live read Grant admits the indexed PERSON in core query");
    assert_eq!(
        item.id,
        id.to_hex(),
        "the agent's core query retains the admitted PERSON id"
    );
    assert_eq!(
        item.entity_type, ENTITY_TYPE_PERSON,
        "the agent's core query retains the PERSON kind"
    );
    assert_nulled_carriers(
        item.body
            .as_ref()
            .expect("the agent's core-query PERSON keeps its safe body"),
    );
    Ok(())
}
