#![cfg(all(oneiron_test_support, unix))]
//! `vault.artifacts.image.edit` through the real facade router (L4-15; the
//! Engine's rulings of 13 Nov 09:34 and 09:53): the verb reaches the host's
//! image organ door; a caller whose own lane does not read the artifact is
//! refused as if it were absent; with no image organ on the host the
//! owner's whole edit is one held call with the reason, and nothing lands
//! (RULING 09:53, IO-HOLD C); and a request no organ takes gets its typed
//! refusal. A server test cannot
//! start the organ binary (cargo names it only to its own package's tests),
//! so the real crop is `oneiron-image`'s `image_edit_landing` test.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test image_organ_route`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_dispatch::DEFAULT_BASE_LOGICAL_ID;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EDIT: &str = "vault.artifacts.image.edit";
/// A 1 x 1 PNG.
const PNG_BASE64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

/// Who signs a request's holder proof: the host's issuer for its root
/// slip, or a slip's own binding key.
enum Holder {
    Issuer(HostSlipIssuer),
    Key(SigningKey),
}

struct Credential {
    slip: CapabilitySlip,
    holder: Holder,
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    /// The host's root slip: the owner.
    owner: Credential,
    /// An agent on a slip of its own, which holds no grant and reads only
    /// [`Self::agent_facets`].
    agent: Credential,
    /// The one facet the agent's slip reads: it holds none of the owner's
    /// rows.
    agent_facets: ScopeAxis<ScopeId>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
            .ok_or("the base agent is seeded")?;
        let work = EntityId::now();
        vault.put_entity(
            &work,
            oneiron::registry::ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"work",
        )?;
        let agent_facets = ScopeAxis::Some(BTreeSet::from([ScopeId(work)]));
        // HTTP trusts the logged issuer of each mint; root the vault here.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-image-organ-route")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = agent.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = Scope::top();
        claims.scope.facets = agent_facets.clone();
        claims.slip_id = [0x71; 32];
        let agent = Credential {
            slip: vault.mint_capability_slip(&issuer, claims)?,
            holder: Holder::Key(key),
        };
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig::default(),
        )?);
        Ok(Self {
            app: build_app(server),
            vault,
            owner: Credential {
                slip: root,
                holder: Holder::Issuer(issuer),
            },
            agent,
            agent_facets,
            _dir: dir,
        })
    }

    /// One facade call as `credential`, or with no credential: its status
    /// and body.
    async fn call(
        &self,
        credential: Option<&Credential>,
        verb: &str,
        input: &Value,
    ) -> TestResult<(u16, Value)> {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json");
        if let Some(credential) = credential {
            let timestamp = self.vault.now_recorded_at();
            let nonce = EntityId::now().to_hex();
            let challenge = holder_proof_challenge(timestamp, &nonce);
            let signature = match &credential.holder {
                Holder::Issuer(issuer) => issuer.binding_proof(&credential.slip, &challenge)?,
                Holder::Key(key) => key
                    .sign(&credential.slip.binding_transcript(&challenge)?)
                    .to_bytes()
                    .to_vec(),
            };
            let binding = json!({
                "timestamp": timestamp,
                "nonce": nonce,
                "signature": hex(&signature),
            });
            request = request
                .header(
                    "authorization",
                    format!("Bearer {}", credential.slip.to_token()?),
                )
                .header("x-oneiron-binding", binding.to_string());
        }
        let request = request.body(Body::from(input.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
    }

    /// A new artifact the owner made, with its first version.
    async fn artifact(
        &self,
        name: &str,
        media_type: &str,
        content_base64: &str,
    ) -> TestResult<String> {
        let (status, body) = self
            .call(
                Some(&self.owner),
                "vault.artifacts.create",
                &json!({
                    "name": name,
                    "media_type": media_type,
                    "content_base64": content_base64,
                }),
            )
            .await?;
        assert_eq!(status, 200, "the owner makes {name}: {body}");
        let view = if body.get("artifact_id").is_some() {
            &body
        } else {
            &body["value"]
        };
        Ok(view["artifact_id"]
            .as_str()
            .ok_or_else(|| format!("{name} has an id: {body}"))?
            .to_owned())
    }

    /// The owner's edit of `artifact` with `ops`.
    async fn owner_edit(&self, artifact: &str, ops: Value) -> TestResult<(u16, Value)> {
        self.call(Some(&self.owner), EDIT, &edit(artifact, ops))
            .await
    }

    /// What waits beside `artifact`, read by the owner: its held organ
    /// calls and its proposals.
    async fn waiting(&self, artifact: &str) -> TestResult<(Vec<Value>, Vec<Value>)> {
        let input = json!({ "artifact_ref": artifact });
        let mut lists = Vec::new();
        for verb in ["vault.artifacts.waits", "vault.artifacts.proposals"] {
            let (status, body) = self.call(Some(&self.owner), verb, &input).await?;
            assert_eq!(status, 200, "the owner reads {verb}: {body}");
            let list = if body.is_array() {
                &body
            } else {
                &body["value"]
            };
            lists.push(
                list.as_array()
                    .ok_or_else(|| format!("{verb} answers a list: {body}"))?
                    .clone(),
            );
        }
        let proposals = lists.pop().unwrap_or_default();
        let held = lists.pop().unwrap_or_default();
        Ok((held, proposals))
    }
}

fn edit(artifact: &str, ops: Value) -> Value {
    json!({
        "artifact_ref": artifact,
        "ops": ops,
        "run_ref": "image-edit-test",
    })
}

fn crop() -> Value {
    json!([{ "op": "crop", "x": 0, "y": 0, "w": 1, "h": 1 }])
}

/// The edit's answer, bare or as the facade's `value`.
fn answer(body: &Value) -> &Value {
    if body.get("artifact_ref").is_some() {
        body
    } else {
        &body["value"]
    }
}

fn code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

fn message(body: &Value) -> &str {
    body["error"]["message"].as_str().unwrap_or_default()
}

/// Runs `test` as the server's binary runs its app: on a multi-thread
/// runtime whose threads have the engine's stack, driven from a thread that
/// has it too (the generated facade dispatch's poll frame is several MiB in
/// a dev build).
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_caller_whose_lane_does_not_read_the_artifact_is_refused_and_nothing_waits() -> TestResult {
    on_engine_stack(caller_refused)
}

async fn caller_refused() -> TestResult {
    let fixture = Fixture::new()?;
    let photo = fixture
        .artifact("photo.png", "image/png", PNG_BASE64)
        .await?;
    let (status, body) = fixture.owner_edit(&photo, crop()).await?;
    assert_eq!(
        status, 200,
        "FAILBEFORE: the owner's edit reaches the image organ's door and is held: {body}"
    );
    assert!(answer(&body)["held"].is_object(), "{body}");

    // The agent's own slip binds it, holds no grant, and reads one facet
    // that does not hold the owner's artifact: the edit is refused as if
    // the artifact were absent.
    assert!(
        !fixture
            .vault
            .row_in_facets(&EntityId::from_hex(&photo)?, &fixture.agent_facets)?,
        "the agent's facet does not hold the photo"
    );
    let (status, body) = fixture
        .call(Some(&fixture.agent), EDIT, &edit(&photo, crop()))
        .await?;
    assert_eq!(
        (status, code(&body)),
        (404, Some("NOT_FOUND")),
        "an agent whose lane does not read the artifact: {body}"
    );
    // No credential at all is refused before any door.
    let (status, body) = fixture.call(None, EDIT, &edit(&photo, crop())).await?;
    assert_eq!(status, 401, "a call with no credential: {body}");

    let (held, proposals) = fixture.waiting(&photo).await?;
    assert_eq!(held.len(), 1, "only the owner's edit is held: {held:?}");
    assert!(
        proposals.is_empty(),
        "nothing waits for Keep: {proposals:?}"
    );
    Ok(())
}

#[test]
fn with_no_image_organ_on_the_host_the_owners_edit_is_held_with_the_reason_and_nothing_lands()
-> TestResult {
    on_engine_stack(no_organ_held)
}

async fn no_organ_held() -> TestResult {
    let fixture = Fixture::new()?;
    let photo = fixture
        .artifact("photo.png", "image/png", PNG_BASE64)
        .await?;
    let ops = json!([
        { "op": "crop", "x": 0, "y": 0, "w": 1, "h": 1 },
        { "op": "resize", "w": 2, "h": 2, "filter": "nearest" },
    ]);
    let (status, body) = fixture.owner_edit(&photo, ops).await?;
    assert_eq!(
        status, 200,
        "FAILBEFORE: the owner's edit, with no image organ on the host, is held: {body}"
    );
    let edited = answer(&body);
    assert_eq!(edited["artifact_ref"], json!(photo), "{body}");
    assert_eq!(edited["born"], json!(false), "{body}");
    assert_eq!(
        edited["proposals"],
        json!([]),
        "nothing waits for Keep: {body}"
    );
    // The whole edit is one call, and the reason names it and each place tried.
    let wait = &edited["held"];
    assert_eq!(wait["verb"], json!("image.render"), "{body}");
    assert_eq!(wait["run_ref"], json!("image-edit-test"), "{body}");
    let reason = wait["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("image.render") && reason.contains("here:"),
        "the hold says why: {body}"
    );

    let (held, proposals) = fixture.waiting(&photo).await?;
    assert_eq!(held.len(), 1, "the whole edit is one held call: {held:?}");
    assert_eq!(held[0]["verb"], json!("image.render"), "{held:?}");
    assert!(
        proposals.is_empty(),
        "nothing waits for Keep: {proposals:?}"
    );
    let (status, body) = fixture
        .call(
            Some(&fixture.owner),
            "vault.artifacts.view",
            &json!({ "artifact_ref": photo }),
        )
        .await?;
    assert_eq!(status, 200, "the owner reads the artifact: {body}");
    let view = if body.get("head").is_some() {
        &body
    } else {
        &body["value"]
    };
    assert_eq!(
        view["head"],
        json!(1),
        "the artifact keeps its one version: {body}"
    );

    // A version the artifact does not hold is absent.
    let mut input = edit(&photo, crop());
    input["version"] = json!(9);
    let (status, body) = fixture.call(Some(&fixture.owner), EDIT, &input).await?;
    assert_eq!(
        (status, code(&body)),
        (404, Some("NOT_FOUND")),
        "a version the artifact does not hold: {body}"
    );
    Ok(())
}

#[test]
fn a_request_no_organ_takes_gets_its_typed_refusal() -> TestResult {
    on_engine_stack(typed_refusals)
}

async fn typed_refusals() -> TestResult {
    let fixture = Fixture::new()?;
    let photo = fixture
        .artifact("photo.png", "image/png", PNG_BASE64)
        .await?;
    let (status, body) = fixture.owner_edit(&photo, json!([])).await?;
    assert_eq!(
        (status, code(&body)),
        (400, Some("image_no_ops")),
        "FAILBEFORE: an edit with no op: {body}"
    );

    let ops: Vec<Value> = (0..257).map(|_| crop()[0].clone()).collect();
    let (status, body) = fixture.owner_edit(&photo, Value::Array(ops)).await?;
    assert_eq!(
        (status, code(&body)),
        (400, Some("image_too_many_ops")),
        "an edit of 257 ops: {body}"
    );

    // "a note", as text.
    let note = fixture
        .artifact("note.txt", "text/plain", "YSBub3Rl")
        .await?;
    let (status, body) = fixture.owner_edit(&note, crop()).await?;
    assert_eq!(
        (status, code(&body)),
        (400, Some("image_not_an_image")),
        "a text artifact: {body}"
    );
    assert!(
        message(&body).contains("text/plain"),
        "the refusal names the type: {body}"
    );

    let (status, body) = fixture
        .owner_edit(&EntityId::now().to_hex(), crop())
        .await?;
    assert_eq!(
        (status, code(&body)),
        (404, Some("NOT_FOUND")),
        "an artifact this vault does not hold: {body}"
    );

    let mut input = edit(&photo, crop());
    input["run_ref"] = json!(" ");
    let (status, body) = fixture.call(Some(&fixture.owner), EDIT, &input).await?;
    assert_eq!(status, 400, "a blank run_ref: {body}");

    for refused in [&photo, &note] {
        let (held, proposals) = fixture.waiting(refused).await?;
        assert!(held.is_empty(), "nothing is held: {held:?}");
        assert!(
            proposals.is_empty(),
            "nothing waits for Keep: {proposals:?}"
        );
    }
    Ok(())
}
