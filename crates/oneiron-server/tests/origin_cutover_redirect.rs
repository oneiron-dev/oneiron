//! RA7 (ARCH-0068): after a cutover the old origin redirects a push to the
//! host that writes the new epoch (FIX 282). The owner's cutover names that
//! host's git door (`writer_door`); a stock push's ref advertisement to this
//! former origin then answers `307` with the same repository at that door,
//! and the pack request past it is refused naming it. A caller the push gate
//! refuses gets its own refusal and never learns the door; a door carrying
//! userinfo is refused at the cutover and installs nothing.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test origin_cutover_redirect`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "the fixture creates the served bare repository with the git binary"
)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::SigningKey;
use engine_stack::on_engine_stack;
use oneiron::agent_dispatch::DEFAULT_BASE_LOGICAL_ID;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof, holder_proof_challenge};
use oneiron::origin::smart_http::origin_serving_root;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REPO: &str = "demo";
const WRITER_DOOR: &str = "https://cloud.example/git";
const ADVERTISE_PUSH: &str = "/git/demo.git/info/refs?service=git-receive-pack";
const RECEIVE_PACK: &str = "/git/demo.git/git-receive-pack";
const CUTOVER: &str = "/v1/owner/origin-authority";

/// The Bearer token and binding header of one request.
struct Credential {
    bearer: String,
    binding: String,
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// One vault serving one empty bare repository, `demo`.
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        let served = origin_serving_root(&vault)?.join(format!("{REPO}.git"));
        let status = std::process::Command::new("git")
            .args(["init", "--quiet", "--bare", "--initial-branch=main"])
            .arg(&served)
            .status()?;
        assert!(status.success(), "git init --bare {}", served.display());
        let issuer = vault.bootstrap_host_slip_issuer()?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig::default(),
        )?);
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            _dir: dir,
        })
    }

    /// The host root credential: the owner's own act at the owner routes.
    fn host_root(&self) -> TestResult<Credential> {
        let slip = self.vault.ensure_host_root_slip(&self.issuer)?;
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let proof = self
            .issuer
            .binding_proof(&slip, &holder_proof_challenge(timestamp, &nonce))?;
        let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&proof)});
        Ok(Credential {
            bearer: slip.to_token()?,
            binding: binding.to_string(),
        })
    }

    /// A slip this host mints for `holder` as `class`, at the host root's
    /// own scope, bound to `key`, with slip id `[seed; 32]`.
    fn slip(
        &self,
        holder: EntityId,
        class: &str,
        key: &SigningKey,
        seed: u8,
    ) -> TestResult<CapabilitySlip> {
        let mut claims = self.vault.ensure_host_root_slip(&self.issuer)?.claims;
        claims.slip_id = [seed; 32];
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.actor_class = Some(class.to_owned());
        claims.binding_key = key.verifying_key().to_bytes();
        Ok(self.vault.mint_capability_slip(&self.issuer, claims)?)
    }

    /// `slip`'s credential with a fresh holder proof.
    fn held(&self, slip: &CapabilitySlip, key: &SigningKey) -> TestResult<Credential> {
        let binding = holder_proof(slip, key, self.vault.now_recorded_at())?;
        Ok(Credential {
            bearer: slip.to_token()?,
            binding: binding.to_string(),
        })
    }

    /// The owner's cutover of `demo` to another host, through the owner route.
    async fn cut_over(&self, writer_door: &str) -> TestResult<(u16, String)> {
        let body = json!({
            "repo": REPO,
            "expected_epoch": null,
            "residence": "cloud-vault",
            "writer": EntityId::now().to_hex(),
            "writer_door": writer_door,
        });
        let request = Request::builder()
            .method("POST")
            .uri(CUTOVER)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        self.send(request, &self.host_root()?).await
    }

    /// The authority row of `demo`, as the owner reads it.
    async fn authority(&self) -> TestResult<Value> {
        let request = Request::builder()
            .method("GET")
            .uri(format!("{CUTOVER}?repo={REPO}"))
            .body(Body::empty())?;
        let (status, body) = self.send(request, &self.host_root()?).await?;
        assert_eq!(status, 200, "the owner reads the row: {body}");
        Ok(serde_json::from_str::<Value>(&body)?["authority"].clone())
    }

    /// One git request as `who`: a stock push's ref advertisement, or its
    /// pack request.
    async fn git(
        &self,
        method: &str,
        path: &str,
        who: &Credential,
    ) -> TestResult<(u16, Option<String>, String)> {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/x-git-receive-pack-request")
            .body(Body::empty())?;
        let request = authorized(request, who);
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get("location")
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()?;
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        Ok((
            status,
            location,
            String::from_utf8_lossy(&body).into_owned(),
        ))
    }

    async fn send(&self, request: Request<Body>, who: &Credential) -> TestResult<(u16, String)> {
        let response = self.app.clone().oneshot(authorized(request, who)).await?;
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }
}

fn authorized(mut request: Request<Body>, who: &Credential) -> Request<Body> {
    let headers = request.headers_mut();
    headers.insert(
        "authorization",
        format!("Bearer {}", who.bearer)
            .parse()
            .expect("bearer header"),
    );
    headers.insert(
        "x-oneiron-binding",
        who.binding.parse().expect("binding header"),
    );
    request
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_push_to_a_former_origin_is_redirected_to_the_writers_door() -> TestResult {
    on_engine_stack(former_origin_redirects_an_admitted_pusher)
}

async fn former_origin_redirects_an_admitted_pusher() -> TestResult {
    let fixture = Fixture::new()?;
    let (status, body) = fixture.cut_over(WRITER_DOOR).await?;
    assert_eq!(
        status, 200,
        "the owner's cutover names the writer's door: {body}"
    );
    let row = fixture.authority().await?;
    assert_eq!(row["writer_door"], WRITER_DOOR, "row: {row}");

    // The owner pushes here: the advertisement a stock push starts with is
    // sent to the same repository at the writer's door.
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let owner_key = SigningKey::from_bytes(&[0x52; 32]);
    let owner_slip = fixture.slip(owner, "human", &owner_key, 0x52)?;
    let (status, location, body) = fixture
        .git(
            "GET",
            ADVERTISE_PUSH,
            &fixture.held(&owner_slip, &owner_key)?,
        )
        .await?;
    assert_eq!(status, 307, "the former origin redirects the push: {body}");
    assert_eq!(
        location.as_deref(),
        Some("https://cloud.example/git/demo.git/info/refs?service=git-receive-pack"),
        "body: {body}"
    );

    // A pack request past the advertisement is refused, naming the door.
    let (status, location, body) = fixture
        .git(
            "POST",
            RECEIVE_PACK,
            &fixture.held(&owner_slip, &owner_key)?,
        )
        .await?;
    assert_eq!(status, 403, "body: {body}");
    assert_eq!(location, None);
    assert!(
        body.contains("https://cloud.example/git/demo.git"),
        "the refusal names the writer's repository: {body}"
    );

    // An agent with no git_push grant gets the gate's refusal, not the door.
    let (agent, _) = fixture
        .vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let agent_key = SigningKey::from_bytes(&[0x41; 32]);
    let agent_slip = fixture.slip(agent, "agent", &agent_key, 0x41)?;
    let (status, location, body) = fixture
        .git(
            "GET",
            ADVERTISE_PUSH,
            &fixture.held(&agent_slip, &agent_key)?,
        )
        .await?;
    assert_eq!(status, 403, "body: {body}");
    assert_eq!(location, None);
    assert!(
        body.contains("git_push_capability_required"),
        "the gate's own refusal: {body}"
    );
    assert!(
        !body.contains("cloud.example"),
        "a refused caller never learns the writer's door: {body}"
    );
    Ok(())
}

#[test]
fn a_writer_door_with_userinfo_is_refused_at_the_cutover() -> TestResult {
    on_engine_stack(writer_door_with_userinfo_installs_nothing)
}

async fn writer_door_with_userinfo_installs_nothing() -> TestResult {
    let fixture = Fixture::new()?;
    let (status, body) = fixture
        .cut_over("https://owner:secret@cloud.example/git")
        .await?;
    assert!(
        (400..500).contains(&status),
        "a door carrying credentials is refused: {status} {body}"
    );
    assert!(
        !body.contains("secret"),
        "the refusal does not echo the userinfo: {body}"
    );
    assert_eq!(
        fixture.authority().await?,
        Value::Null,
        "nothing was installed"
    );
    Ok(())
}
