#![cfg(oneiron_test_support)]
//! L1-04 (canon ARCH-0028 "Discover catalog"; Engine RULING L1-04 = B,
//! 13 Nov 2026): `server/discover` on the MCP gateway answers the static,
//! account-neutral identity and capability summary before any caller is
//! resolved. An unauthenticated prober (no credential at all), the owner (the
//! self-hosted root slip) and a distinct person's `core:read` slip, narrowed
//! by its holder to one world, get byte-identical replies on both endpoints.
//! None names the vault, a caller or a world, while the reader's own
//! `initialize` names the world its caveat holds it to.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test mcp_server_discover`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, SlipCaveat, holder_proof_challenge,
};
use oneiron::claim::base_world_id;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::mcp::MCP_SERVER_NAME;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CREATED_AT: u64 = 1_769_947_200;
const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
const DISCOVER_METHOD: &str = "server/discover";
/// Both MCP endpoints, primary first, as the catalog lists them.
const ENDPOINTS: [&str; 2] = ["/mcp", "/mcp/tool-first"];
/// A world the owner names; no caller's discover reply may name it.
const WORLD_NAME: &str = "Discover harbor partition";
/// One request id for every discover call, so the replies compare byte for
/// byte.
const DISCOVER_REQUEST_ID: u64 = 7;

/// Who sends a request.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// No credential header at all.
    Prober,
    /// The self-hosted root slip, proved by the vault's issuer.
    Owner,
    /// A distinct person's `core:read` slip, narrowed to the base world.
    Reader,
}

const CALLERS: [Caller; 3] = [Caller::Prober, Caller::Owner, Caller::Reader];

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    reader: CapabilitySlip,
    reader_key: SigningKey,
    reader_person: EntityId,
    owner: EntityId,
    world: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A rooted vault behind the MCP gateway with one named world, its root
    /// slip, and a distinct person's `core:read` slip minted under the vault's
    /// logged issuer as pairing mints one, then narrowed by its holder to the
    /// base world (as `mcp_caveated_reader.rs` narrows its reader).
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let world = vault.create_world(&owner_proof, WORLD_NAME, CREATED_AT)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let reader_person = EntityId::now();
        vault.put_entity(
            &reader_person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a distinct reader",
        )?;
        let reader_key = SigningKey::from_bytes(&[0x64; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [0x64; 32];
        claims.holder_ref = reader_person.to_hex();
        claims.binding_key = reader_key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
        let mut reader = vault.mint_capability_slip(&issuer, claims)?;
        let mut ceiling = Scope::top();
        ceiling.worlds = ScopeAxis::Some(
            [base_world_id()]
                .iter()
                .map(|world| ScopeId(*world))
                .collect(),
        );
        reader.attenuate(
            SlipCaveat {
                scope: Some(ceiling),
                ..Default::default()
            },
            &reader_key,
        )?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("mcp-server-discover".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            root,
            reader,
            reader_key,
            reader_person,
            owner,
            world,
            _dir: dir,
        })
    }

    /// One JSON-RPC request to the MCP endpoint at `path`, as `caller`: under
    /// its slip and a fresh holder proof, or with no credential at all. The
    /// HTTP status and the reply body exactly as it arrived.
    async fn rpc(
        &self,
        caller: Caller,
        path: &str,
        id: u64,
        method: &str,
        params: Value,
    ) -> TestResult<(u16, String)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signed = match caller {
            Caller::Prober => None,
            Caller::Owner => Some((
                &self.root,
                self.issuer.binding_proof(&self.root, &challenge)?,
            )),
            Caller::Reader => Some((
                &self.reader,
                self.reader_key
                    .sign(&self.reader.binding_transcript(&challenge)?)
                    .to_bytes()
                    .to_vec(),
            )),
        };
        let mut request = Request::post(path)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", MCP_PROTOCOL_VERSION);
        if let Some((slip, signature)) = signed {
            let binding = json!({
                "timestamp": timestamp,
                "nonce": nonce,
                "signature": hex(&signature),
            });
            request = request
                .header("authorization", format!("Bearer {}", slip.to_token()?))
                .header("x-oneiron-binding", binding.to_string());
        }
        let request = request.body(Body::from(
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string(),
        ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
    }

    async fn initialize(&self, caller: Caller, path: &str, id: u64) -> TestResult<(u16, Value)> {
        let (status, body) = self
            .rpc(
                caller,
                path,
                id,
                "initialize",
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "mcp-server-discover", "version": "1" },
                }),
            )
            .await?;
        Ok((status, parsed(&body)))
    }
}

fn parsed(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.to_owned()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs `test` as the server's binary runs its app: on a multi-thread runtime
/// whose threads have the engine's stack, driven from a thread that has it
/// too. The generated dispatch's poll frame does not fit a test thread's
/// default stack (`ENGINE_THREAD_STACK_BYTES`).
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

#[test]
fn server_discover_answers_every_caller_the_same_account_neutral_catalog() -> TestResult {
    on_engine_stack(discover_is_the_same_for_every_caller)
}

async fn discover_is_the_same_for_every_caller() -> TestResult {
    let fixture = Fixture::new()?;
    let base_world = base_world_id().to_hex();

    // FIXTURE: the reader's handshake is actor-bound. Its own `initialize`
    // registers it as its holder at its caveat's world.
    let (status, reply) = fixture.initialize(Caller::Reader, ENDPOINTS[1], 1).await?;
    assert_eq!(status, 200, "FIXTURE: the reader initializes: {reply}");
    assert!(
        reply.get("error").is_none(),
        "FIXTURE: the gateway admits the narrowed core:read slip: {reply}"
    );
    assert_eq!(
        reply["result"]["actor"]["actor_ref"],
        fixture.reader_person.to_hex(),
        "FIXTURE: the reader initializes as its holder: {reply}"
    );
    assert_eq!(
        reply["result"]["actor"]["scope"]["world_ref"], base_world,
        "FIXTURE: the reader's initialize names its caveat's world: {reply}"
    );
    // What the prober's own handshake answers, for the record: it names no
    // caller.
    let (status, reply) = fixture.initialize(Caller::Prober, ENDPOINTS[0], 2).await?;
    eprintln!(
        "## PROBER-INITIALIZE status={status} error={}",
        reply["error"]["data"]["error_code"]
    );

    // Every caller, on both endpoints, gets the catalog, byte for byte.
    let mut replies = Vec::new();
    for path in ENDPOINTS {
        for caller in CALLERS {
            let (status, body) = fixture
                .rpc(
                    caller,
                    path,
                    DISCOVER_REQUEST_ID,
                    DISCOVER_METHOD,
                    json!({}),
                )
                .await?;
            let reply = parsed(&body);
            assert!(
                reply.get("error").is_none() && reply.get("result").is_some(),
                "server/discover answers the {caller:?} at {path} before any caller is resolved: {body}"
            );
            assert_eq!(status, 200, "the {caller:?} at {path}: {body}");
            replies.push((caller, path, body));
        }
    }
    let (_, _, first) = &replies[0];
    for (caller, path, body) in &replies {
        assert_eq!(
            body, first,
            "the {caller:?}'s discover reply at {path} is byte-identical to the prober's at /mcp"
        );
    }

    // It holds only the server's identity, the protocol versions it speaks,
    // its capabilities, its endpoints and a public cache hint.
    let reply = parsed(first);
    let result = &reply["result"];
    let keys: BTreeSet<&str> = result
        .as_object()
        .ok_or("the discover result is an object")?
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "cacheScope",
            "capabilities",
            "endpoints",
            "protocolVersions",
            "serverInfo",
            "ttlMs",
        ]),
        "the catalog holds the server's identity, protocol versions, capabilities, endpoints and cache hint alone: {first}"
    );
    assert_eq!(result["serverInfo"]["name"], MCP_SERVER_NAME, "{first}");
    assert!(
        result["serverInfo"]["version"]
            .as_str()
            .is_some_and(|version| !version.is_empty()),
        "the catalog names the server's build version: {first}"
    );
    assert!(
        result["protocolVersions"]
            .as_array()
            .is_some_and(|versions| versions.contains(&json!(MCP_PROTOCOL_VERSION))),
        "the catalog lists the protocol versions the server speaks: {first}"
    );
    assert_eq!(
        result["capabilities"]["tools"],
        json!({ "listChanged": false }),
        "{first}"
    );
    let paths: Vec<&str> = result["endpoints"]
        .as_array()
        .ok_or("the catalog lists its endpoints")?
        .iter()
        .filter_map(|endpoint| endpoint["path"].as_str())
        .collect();
    assert_eq!(
        paths, ENDPOINTS,
        "the catalog lists both endpoints: {first}"
    );
    assert_eq!(
        result["cacheScope"], "public",
        "the catalog is the one publicly cacheable result: {first}"
    );
    assert!(
        result["ttlMs"].as_u64().is_some_and(|ttl| ttl > 0),
        "a public catalog may be kept: {first}"
    );

    // Nothing account-bound: no vault, caller or world, by name or by id.
    let mut account_bound = vec![
        WORLD_NAME.to_owned(),
        fixture.world.to_hex(),
        base_world,
        fixture.owner.to_hex(),
        fixture.reader_person.to_hex(),
    ];
    if let Some(vault_id) = fixture.vault.authority_vault_id()? {
        account_bound.push(hex(&vault_id));
    }
    for named in &account_bound {
        assert!(
            !first.contains(named.as_str()),
            "the discover catalog names {named}: {first}"
        );
    }
    Ok(())
}
