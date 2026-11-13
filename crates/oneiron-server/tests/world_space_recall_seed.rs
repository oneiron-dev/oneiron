//! A private world's device text space resolves without an ai.embed seat, fills only
//! that world's rows, and contributes its own recall list above light effort. A
//! world space with no text query tower adds no list. An explicit media query
//! refuses an unloaded device model instead of loading it.
//!
//! Deterministic: in-process vault and router, `oneshot`, no TCP ports, no sleeps,
//! no network, no model download. The device model is an installed text function.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test world_space_recall_seed`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron::authority::{
    ActSurface, CapabilitySlip, HostSlipIssuer, MachineOwnership, MachineRole, ModelOrder,
    ReadLocation, SealedCopies, WorldPrivacy,
};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::embed::{EmbedderLocality, EmbeddingSpace, InputKind};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::world_space::{
    DOOR_DEVICE_RUNTIME, install_device_text_model, media_backfill_pass, media_embedder_locality,
};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const WORLD_SPACE: &str = "owen-lab/tiny-text@0123456789abcdef0123456789abcdef01234567@device";
const UNLOADED_SPACE: &str = "owen-lab/other-text@89abcdef0123456789abcdef0123456789abcdef@device";
const UNPINNED_SPACE: &str = "owen-lab/tiny-text@main@device";
const DOCUMENT_ONLY_SPACE: &str =
    "owen-lab/doc-text@fedcba9876543210fedcba9876543210fedcba98@device";
const DIMENSIONS: usize = 8;
const RECALL: &str = "/v1/core/facade/vault.recall";
const CONTEXT_PACK: &str = "/v1/core/context-pack";

struct Host {
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    server: Arc<SyncServer>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    world: EntityId,
    world_claim: EntityId,
    world_claim_short_id: String,
    base_claim: EntityId,
    _dir: tempfile::TempDir,
}

fn run_on_engine_stack(name: &str, test: impl std::future::Future<Output = ()> + Send + 'static) {
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test)
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

fn text_space(id: &str) -> EmbeddingSpace {
    EmbeddingSpace {
        id: id.to_owned(),
        dimensions: DIMENSIONS,
        accepts: BTreeSet::from([InputKind::Text]),
        query_towers: BTreeSet::from([InputKind::Text]),
        evidence: None,
    }
}

fn model(text: &str) -> Vec<f32> {
    let mut vector = vec![0.0; DIMENSIONS];
    vector[usize::from(!text.to_ascii_lowercase().contains("harbor"))] = 1.0;
    vector
}

fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary world-space vault directory");
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.embedding_model = None;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("fresh world-space vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("install signing key");
    let person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = vault
        .bootstrap_host_slip_issuer()
        .expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
        .expect("this install is one of the owner's machines");
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner");
    let at = vault.now_recorded_at();
    let world = vault
        .create_world(&owner, "Owen private text world", at)
        .expect("owner creates W");
    vault
        .declare_embedding_space(&owner, text_space(WORLD_SPACE))
        .expect("owner declares S");
    vault
        .declare_embedding_space(&owner, text_space(UNLOADED_SPACE))
        .expect("owner declares S2");
    vault
        .set_world_privacy_as(
            &owner,
            ActSurface::ThisInstall,
            world,
            WorldPrivacy {
                read: ReadLocation::MyMachines,
                sealed: SealedCopies::MyMachines,
                models: ModelOrder::Ordered(vec![WORLD_SPACE.to_owned()]),
            },
            None,
        )
        .expect("owner names S as W's private text space");
    let facet = vault.default_facet().expect("owner default facet");
    let write_claim = |world_id: EntityId, text: &str| {
        let id = EntityId::now();
        let receipt = vault
            .memory(person, EdgeActorClass::Human)
            .with_owner_authorship(&owner)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(id.to_hex()),
                predicate: "profile.preference".to_owned(),
                subject_ref: person.to_hex(),
                value: json!(text),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: world_id.to_hex(),
                    scope_facet_id: facet.to_hex(),
                    scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                    scope_project_id: default_project_id().to_hex(),
                },
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(at),
                learned_at: Some(at),
                salience: None,
            })
            .expect("owner writes a text claim in its requested world");
        (id, receipt.claim_short_id)
    };
    let (world_claim, world_claim_short_id) = write_claim(world, "Owen likes the harbor");
    let (base_claim, _) = write_claim(base_world_id(), "Owen likes the mountains");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("world-space-recall-seed".to_owned()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    install_device_text_model(&server, WORLD_SPACE, Arc::new(model))
        .expect("install S's in-process device model");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    let app = build_app(Arc::clone(&server));
    Host {
        vault,
        owner,
        server,
        app,
        issuer,
        owner_slip,
        owner_token,
        world,
        world_claim,
        world_claim_short_id,
        base_claim,
        _dir: dir,
    }
}

impl Host {
    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("owner JSON request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("router response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("router response body");
        let answer = serde_json::from_slice(&bytes).expect("router response JSON");
        (status, answer)
    }

    async fn recall(&self, effort: &str) -> (StatusCode, Value) {
        self.post(
            RECALL,
            json!({
                "query": "harbor",
                "effort": effort,
                "limit": 10,
                "scope": {"world_ref": self.world.to_hex()}
            }),
        )
        .await
    }
}

fn world_item<'a>(host: &Host, pack: &'a Value) -> Option<&'a Value> {
    pack["items"]
        .as_array()?
        .iter()
        .find(|item| item["short_id"].as_str() == Some(host.world_claim_short_id.as_str()))
}

fn has_world_space_match(item: &Value) -> bool {
    item["embedding_matches"].as_array().is_some_and(|matches| {
        matches
            .iter()
            .any(|entry| entry["space"].as_str() == Some(WORLD_SPACE))
    })
}

#[test]
fn a_device_text_space_resolves_to_a_model_on_this_machine() {
    run_on_engine_stack("device-text-space-locality", async {
        let host = host();
        assert_eq!(
            media_embedder_locality(&host.server, WORLD_SPACE),
            Ok(EmbedderLocality::OnDevice),
            "a world's device text space resolves to a model on this machine",
        );
        assert_eq!(
            media_embedder_locality(&host.server, UNLOADED_SPACE),
            Ok(EmbedderLocality::OnDevice),
            "resolving S2 neither loads nor fetches its model",
        );
        host.vault
            .declare_embedding_space(&host.owner, text_space(UNPINNED_SPACE))
            .expect("owner declares S3 with a moving ref");
        let unpinned = media_embedder_locality(&host.server, UNPINNED_SPACE);
        assert!(
            matches!(&unpinned, Err(error) if error.contains("names no device model")),
            "a moving ref is not a device model pin: {unpinned:?}",
        );
    });
}

#[test]
fn the_backfill_fills_a_world_text_space_with_the_worlds_rows_alone() {
    run_on_engine_stack("device-text-space-backfill", async {
        let host = host();
        let passes = media_backfill_pass(Arc::clone(&host.server)).await;
        let report = passes
            .iter()
            .find_map(|(space, report)| (space == WORLD_SPACE).then_some(report));
        assert!(
            report.is_some(),
            "the media backfill visits W's text space: {passes:?}",
        );
        assert!(
            matches!(report, Some(Ok(_))),
            "W's text-space backfill succeeds: {report:?}",
        );
        assert_eq!(
            report
                .and_then(|report| report.as_ref().ok())
                .map(|report| report.embedded),
            Some(1),
            "only A embeds into S",
        );
        let world_mark = host
            .vault
            .media_embedding_provenance(WORLD_SPACE, &host.world_claim)
            .expect("read A's provenance in S");
        assert!(world_mark.is_some(), "S holds A's vector");
        assert_eq!(
            world_mark.as_ref().map(|mark| mark.runtime.as_str()),
            Some(DOOR_DEVICE_RUNTIME),
            "S's device model computed A's vector",
        );
        let base_mark = host
            .vault
            .media_embedding_provenance(WORLD_SPACE, &host.base_claim)
            .expect("read B's provenance in S");
        assert!(base_mark.is_none(), "S never takes the base-world claim B");
    });
}

#[test]
fn recall_searches_the_world_text_space_as_its_own_list() {
    run_on_engine_stack("device-text-space-recall", async {
        let host = host();
        let _passes = media_backfill_pass(Arc::clone(&host.server)).await;
        let (status, medium) = host.recall("medium").await;
        assert_eq!(status, StatusCode::OK, "medium recall: {medium}");
        assert!(
            world_item(&host, &medium).is_some(),
            "medium recall contains A by its short_id: {medium}",
        );
        assert!(
            world_item(&host, &medium).is_some_and(has_world_space_match),
            "A carries an embedding_matches entry for S: {medium}",
        );
        let (status, light) = host.recall("light").await;
        assert_eq!(status, StatusCode::OK, "light recall: {light}");
        assert!(
            world_item(&host, &light).is_some(),
            "light recall still finds A lexically: {light}",
        );
        assert!(
            light["items"]
                .as_array()
                .is_some_and(|items| { items.iter().all(|item| !has_world_space_match(item)) }),
            "light makes no model call and carries no match from S: {light}",
        );
    });
}

#[test]
fn a_world_text_space_with_no_text_query_tower_adds_no_recall_list() {
    run_on_engine_stack("device-text-space-no-query-tower", async {
        let host = host();
        host.vault
            .declare_embedding_space(
                &host.owner,
                EmbeddingSpace {
                    query_towers: BTreeSet::new(),
                    ..text_space(DOCUMENT_ONLY_SPACE)
                },
            )
            .expect("owner declares a device space that takes text but answers no text query");
        host.vault
            .set_world_privacy_as(
                &host.owner,
                ActSurface::ThisInstall,
                host.world,
                WorldPrivacy {
                    read: ReadLocation::MyMachines,
                    sealed: SealedCopies::MyMachines,
                    models: ModelOrder::Ordered(vec![DOCUMENT_ONLY_SPACE.to_owned()]),
                },
                None,
            )
            .expect("owner names the document-only space as W's text space");
        install_device_text_model(&host.server, DOCUMENT_ONLY_SPACE, Arc::new(model))
            .expect("install the document-only space's in-process device model");
        let (status, medium) = host.recall("medium").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a world text space with no text query tower fails no recall: {medium}",
        );
        assert!(
            world_item(&host, &medium).is_some(),
            "medium recall still finds A lexically: {medium}",
        );
    });
}

#[test]
fn a_query_never_loads_a_device_model() {
    run_on_engine_stack("device-text-space-unloaded-query", async {
        let host = host();
        let (status, answer) = host
            .post(
                CONTEXT_PACK,
                json!({
                    "query": "harbor",
                    "media": {
                        "space": UNLOADED_SPACE,
                        "mime": "text/plain",
                        "bytes_b64": STANDARD.encode(b"harbor")
                    }
                }),
            )
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
        assert!(
            answer["error"]["message"]
                .as_str()
                .is_some_and(|message| { message.contains("is not loaded on this machine yet") }),
            "an explicit query refuses S2's unloaded model without loading it: {answer}",
        );
    });
}
