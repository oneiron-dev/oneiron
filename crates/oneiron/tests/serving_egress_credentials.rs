//! Admitted agent egresses release typed Nulled bodies while the owner
//! keeps encoded carriers and graph source hashes still pin stored bytes.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::batch::export::{claim_reads_as_secret, redacted_memory_body};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ScopedReadActorKey};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::decision::questions::{
    GraphAnswerer, GraphPrediction, GraphUnitContext, run_graph_ask, select_graph_units_by_type,
};
use oneiron::llm::decision::{AnswerContract, DecisionClass, DecisionQuestion};
use oneiron::memory::{ClaimInput, Effort, RecallScope};
use oneiron::pipeline::retrieval_loop::RetrievalLoopAction;
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig, WriteActor};
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
        let mut config = VaultConfig::default();
        config.dimensions = 4;
        config.embedding_model = Some("test/model@v1".to_owned());
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

fn decoded_body(bytes: &[u8]) -> TestResult<serde_json::Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)?;
    assert!(
        cursor.is_empty(),
        "the source body is exactly one MessagePack value"
    );
    Ok(oneiron::msgpack_value_to_json(&value))
}

fn assert_owner_carriers(body: &serde_json::Value, stored: &serde_json::Value) {
    assert_eq!(
        body["name"], stored["name"],
        "the owner's safe name is unchanged"
    );
    for name in ["byte_map", "json_encoded_bytes", "json_encoded_map"] {
        assert_eq!(body[name], stored[name], "the owner keeps {name} as stored");
    }
    assert!(
        body["byte_map"].is_array(),
        "the owner keeps the byte_map array"
    );
    assert!(
        body["json_encoded_bytes"].is_string(),
        "the owner keeps the encoded byte text"
    );
    assert!(
        body["json_encoded_map"].is_string(),
        "the owner keeps the encoded map text"
    );
}

#[test]
fn agent_retrieval_loop_read_nulls_encoded_carriers() -> TestResult {
    let fixture = Fixture::new()?;
    let bytes = credential_person();
    let stored = decoded_body(&bytes)?;
    let id = fixture.store(ENTITY_TYPE_PERSON, &bytes)?;
    let vector = [1.0_f32, 0.0, 0.0, 0.0];
    fixture.vault.batch().vector(&id, &vector).commit()?;

    for (actor, class, owner_control) in [
        (fixture.owner, EdgeActorClass::Human, true),
        (fixture.agent, EdgeActorClass::Agent, false),
    ] {
        let lane = fixture.vault.scoped_read(fixture.key(actor, class)?);
        let mut retrieval = fixture
            .vault
            .query()
            .search_vector(&vector, 10)
            .limit(10)
            .read_only_loop(&lane)?;
        assert!(
            retrieval
                .observation()
                .handles
                .iter()
                .any(|handle| handle.id == id),
            "the reader's first deterministic observation admits the fixture PERSON handle"
        );
        let observation = retrieval.step(RetrievalLoopAction::Read { handles: vec![id] })?;
        let evidence = observation
            .evidence
            .iter()
            .find(|evidence| evidence.handle.id == id)
            .expect("the admitted fixture PERSON remains evidence after Read");
        assert_eq!(
            evidence.entity_type, ENTITY_TYPE_PERSON,
            "Read keeps the admitted PERSON kind"
        );
        if owner_control {
            assert_owner_carriers(&evidence.body, &stored);
        } else {
            assert_nulled_carriers(&evidence.body);
        }
    }
    Ok(())
}

#[derive(Default)]
struct RecordingAnswerer {
    calls: Vec<(GraphUnitContext, serde_json::Value)>,
}

impl GraphAnswerer for RecordingAnswerer {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        context: &GraphUnitContext,
    ) -> oneiron::Result<Option<GraphPrediction>> {
        self.calls.push((context.clone(), context.state(&[], &[])));
        Ok(None)
    }
}

#[test]
fn agent_graph_ask_is_shown_the_released_source_body() -> TestResult {
    let fixture = Fixture::new()?;
    let bytes = credential_person();
    let stored = decoded_body(&bytes)?;
    let id = fixture.store(ENTITY_TYPE_PERSON, &bytes)?;
    let question = DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Is the graph evidence relevant?".to_owned(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Choice {
            options: vec!["yes".to_owned(), "no".to_owned()],
        },
        accept_type: false,
    };

    for (actor, class, owner_control) in [
        (fixture.owner, EdgeActorClass::Human, true),
        (fixture.agent, EdgeActorClass::Agent, false),
    ] {
        let lane = fixture.vault.scoped_read(fixture.key(actor, class)?);
        let units = select_graph_units_by_type(&lane, ENTITY_TYPE_PERSON, 64)?;
        assert!(
            units.contains(&id),
            "the reader's graph selector admits the fixture PERSON unit"
        );
        let mut answerer = RecordingAnswerer::default();
        let result = run_graph_ask(
            &lane,
            WriteActor::new(actor, class),
            question.clone(),
            &[id],
            &mut answerer,
            790,
        )?;
        assert!(
            result.answers.is_empty(),
            "the recording answerer writes no graph answer"
        );
        assert_eq!(
            result.abstained,
            vec![id],
            "the visible fixture unit abstains rather than disappearing"
        );
        assert_eq!(
            answerer.calls.len(),
            1,
            "the answerer is called once for the admitted fixture unit"
        );
        let (context, state) = &answerer.calls[0];
        assert_eq!(
            context.unit, id,
            "the recorded graph context belongs to the fixture unit"
        );
        let source = context
            .sources
            .iter()
            .find(|source| source.id == id)
            .expect("the answerer receives the admitted fixture source");
        assert_eq!(
            context.sources.len(),
            1,
            "the unlinked fixture has only its own source"
        );
        assert_eq!(
            context.sources[0].id, id,
            "the fixture unit is the first source"
        );
        assert_eq!(
            source.entity_type, ENTITY_TYPE_PERSON,
            "the source keeps the PERSON kind"
        );
        assert_eq!(
            source.hash,
            *blake3::hash(&bytes).as_bytes(),
            "the source hash pins the stored body, not the released body"
        );
        let body = decoded_body(&source.body)?;
        let state_source = state["sources"]
            .as_array()
            .expect("the rendered graph state has a source list")
            .iter()
            .find(|source| source["ref"] == json!(id.to_hex()))
            .expect("the rendered graph state includes the admitted fixture source");
        let state_body: serde_json::Value = serde_json::from_str(
            state_source["body"]
                .as_str()
                .expect("the rendered source body is JSON text"),
        )?;
        if owner_control {
            assert_eq!(
                source.body, bytes,
                "the owner's graph source is byte-equal to stored evidence"
            );
            assert_owner_carriers(&body, &stored);
            assert_owner_carriers(&state_body, &stored);
        } else {
            assert_nulled_carriers(&body);
            assert_nulled_carriers(&state_body);
            assert_no_encoded_secrets(state);
        }
    }
    Ok(())
}

#[test]
fn agent_lexical_hit_snippet_nulls_encoded_content() -> TestResult {
    let fixture = Fixture::new()?;
    let person = decoded_body(&credential_person())?;
    let content = person["json_encoded_map"]
        .as_str()
        .expect("the fixture's encoded map carrier is text");
    let bytes = encode(&Value::Map(vec![
        (Value::from("name"), Value::from("portable person")),
        (Value::from("content"), Value::from(content)),
    ]));
    assert_eq!(
        redacted_memory_body(&bytes)["content"],
        json!(content),
        "the ordinary serving scan keeps the encoded content fixture"
    );
    assert!(
        content.chars().count() <= 160,
        "the owner control fits the lexical snippet bound"
    );
    let id = fixture.store(ENTITY_TYPE_PERSON, &bytes)?;
    fixture
        .vault
        .batch()
        .text(&id, &[("content", content)])
        .commit()?;

    for (actor, class, owner_control) in [
        (fixture.owner, EdgeActorClass::Human, true),
        (fixture.agent, EdgeActorClass::Agent, false),
    ] {
        let read = fixture
            .vault
            .memory(actor, class)
            .query_bm25("payload", 10)?;
        let hit = read
            .value
            .iter()
            .find(|hit| {
                hit.record
                    .as_ref()
                    .is_some_and(|record| record.id == id.to_hex())
            })
            .expect("the reader's BM25 results admit the encoded-content fixture id");
        let record = hit
            .record
            .as_ref()
            .expect("the admitted lexical hit keeps its record ref");
        assert_eq!(
            record.id,
            id.to_hex(),
            "the lexical record ref names the fixture row"
        );
        assert_eq!(
            record.label, "portable person",
            "the lexical record label keeps the safe PERSON name"
        );
        if owner_control {
            assert_eq!(
                hit.snippet.as_deref(),
                Some(content),
                "the owner's lexical snippet keeps the stored encoded text"
            );
        } else {
            assert_ne!(
                hit.snippet.as_deref(),
                Some(content),
                "the agent is not served the original encoded content"
            );
            if let Some(snippet) = &hit.snippet {
                assert_no_encoded_secrets(&json!(snippet));
            }
            assert_no_encoded_secrets(&json!(record.label));
        }
    }
    Ok(())
}

#[test]
fn agent_recall_claim_value_nulls_encoded_carriers() -> TestResult {
    let fixture = Fixture::new()?;
    let person = decoded_body(&credential_person())?;
    let value = json!({
        "name": "portable person",
        "lookup": "claimcarrierneedle",
        "byte_map": person["byte_map"],
    });
    let id = EntityId::now();
    let written = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.note".to_owned(),
            subject_ref: fixture.owner.to_hex(),
            value: value.clone(),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        })?;
    assert_eq!(
        written.approval, "auto",
        "the owner's declared profile claim lands surfaceable, not proposed"
    );
    let landed = written
        .claim
        .as_ref()
        .expect("the committed claim receipt names a landed record");
    assert_eq!(
        landed.id,
        id.to_hex(),
        "the claim receipt names the fixture id"
    );
    let raw = fixture
        .vault
        .get(&id)?
        .expect("the claim write leaves stored evidence");
    assert_eq!(
        decoded_body(&raw)?["val"],
        value,
        "the stored CLAIM value keeps the byte-map carrier"
    );
    let claim = fixture
        .vault
        .get_claim(&id)?
        .expect("the stored fixture decodes as a CLAIM");
    assert_eq!(
        claim.approval,
        ClaimApprovalStatus::Auto,
        "the stored claim is automatically approved"
    );
    assert_eq!(
        claim.lifecycle,
        ClaimLifecycleStatus::Active,
        "the stored claim is Active"
    );
    assert!(
        !claim_reads_as_secret(&claim),
        "the encoded byte-map fixture is not already withheld by the CLAIM joint-read guard"
    );
    assert_eq!(
        redacted_memory_body(&encode(&claim.value)),
        value,
        "the ordinary serving projection keeps the encoded CLAIM value fixture"
    );

    for (actor, class, owner_control) in [
        (fixture.owner, EdgeActorClass::Human, true),
        (fixture.agent, EdgeActorClass::Agent, false),
    ] {
        let pack = fixture.vault.memory(actor, class).recall(
            "claimcarrierneedle",
            Effort::Light,
            &RecallScope::default(),
            10,
            None,
            None,
        )?;
        let item = pack
            .items
            .iter()
            .find(|item| item.provenance.source_revision_ids.contains(&id.to_hex()))
            .expect("the reader's recall admits an item sourced from the fixture CLAIM id");
        assert_eq!(
            item.short_id, written.claim_short_id,
            "the recalled item names the fixture CLAIM's short id"
        );
        assert_eq!(
            item.predicate.as_deref(),
            Some("profile.note"),
            "the recalled claim keeps its safe predicate"
        );
        let recalled: serde_json::Value = serde_json::from_str(&item.value_text)?;
        if owner_control {
            assert_eq!(
                recalled, value,
                "the owner's recall keeps the stored CLAIM value and byte-map carrier"
            );
            assert!(
                recalled["byte_map"].is_array(),
                "the owner keeps the CLAIM byte_map as an array"
            );
        } else {
            assert_nulled_carriers(&recalled);
            assert_eq!(
                recalled["lookup"],
                json!("claimcarrierneedle"),
                "recall keeps the safe lookup text beside the nulled carrier"
            );
        }
    }
    Ok(())
}
