#![cfg(oneiron_test_support)]
//! FIX 298 (#1564): a `tools/call` naming a canonical verb under the wrong
//! root is refused before any caller resolves.
//!
//! The name alone settles it, so resolving first could only lend the refusal
//! an effect: a live paired credential learned into the registry, an
//! actor-bound receipt, a wire count under the caller. The refusal keeps its
//! code, its sentence and its correction, but states no effective scope —
//! there is no scope yet to state — and answers even a credential that could
//! never resolve. A name with no one verb it could mean still resolves its
//! caller first and refuses as unknown under that scope.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test mcp_wrong_root_pre_resolution`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MCP_PATH: &str = "/mcp/tool-first";
const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
/// A retired plain-verb name whose leaf is one served verb: refused with its
/// correction (#1564).
const WRONG_ROOT_NAME: &str = "oneiron.ask";
/// A retired plain-verb name with no one verb it could mean: unknown.
const UNKNOWN_NAME: &str = "oneiron.nav";

/// A slip and the key its holder proves it with.
struct Holder {
    slip: CapabilitySlip,
    key: SigningKey,
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A rooted vault behind the MCP gateway, as
    /// `support/eval_authoring_fixture.rs` roots one: the keystore goes in
    /// before the server, whose construction roots the vault.
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("mcp-wrong-root-pre-resolution".into()),
                ..Default::default()
            },
        )?);
        let issuer = vault.load_host_slip_issuer()?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            root,
            _dir: dir,
        })
    }

    /// A distinct person's `core:read` slip, minted under the vault's logged
    /// issuer as pairing mints one (as `mcp_caveated_reader.rs` mints its
    /// reader): live, but never used, so the gateway holds no record of it.
    fn mint_reader(&self, seed: u8) -> TestResult<Holder> {
        let person = EntityId::now();
        self.vault.put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a distinct reader",
        )?;
        let bytes = [seed; 32];
        let key = SigningKey::from_bytes(&bytes);
        let mut claims = self.root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = bytes;
        claims.holder_ref = person.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
        let slip = self.vault.mint_capability_slip(&self.issuer, claims)?;
        Ok(Holder { slip, key })
    }

    /// One `tools/call` of `name` under `holder`'s slip and a fresh holder
    /// proof: the HTTP status and the reply.
    async fn call_as(&self, holder: &Holder, id: u64, name: &str) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = holder
            .key
            .sign(&holder.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        self.post(
            id,
            name,
            vec![
                (
                    "authorization",
                    format!("Bearer {}", holder.slip.to_token()?),
                ),
                ("x-oneiron-binding", binding.to_string()),
            ],
        )
        .await
    }

    /// One `tools/call` of `name` under a Bearer token with no holder proof.
    async fn call_bearer(&self, token: &str, id: u64, name: &str) -> TestResult<(u16, Value)> {
        self.post(id, name, vec![("authorization", format!("Bearer {token}"))])
            .await
    }

    async fn post(
        &self,
        id: u64,
        name: &str,
        headers: Vec<(&str, String)>,
    ) -> TestResult<(u16, Value)> {
        let mut request = Request::post(MCP_PATH)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", MCP_PROTOCOL_VERSION);
        for (key, value) in headers {
            request = request.header(key, value);
        }
        let request = request.body(Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": name, "arguments": {} },
            })
            .to_string(),
        ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let reply = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, reply))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn wrong_root_refusal_states_no_scope_and_keeps_its_correction() -> TestResult {
    on_engine_stack(wrong_root_has_no_scope)
}

async fn wrong_root_has_no_scope() -> TestResult {
    let fixture = Fixture::new()?;
    // A live slip the gateway has never seen, naming a canonical verb under
    // the wrong root. No caller resolves for it, so the refusal states no
    // scope; the code, the sentence and the correction are unchanged.
    let reader = fixture.mint_reader(0x61)?;
    let (status, reply) = fixture.call_as(&reader, 1, WRONG_ROOT_NAME).await?;
    assert_eq!(status, 200, "a refusal is still a 200 JSON-RPC error: {reply}");
    assert!(
        reply.get("result").is_none(),
        "the wrong root is refused: {reply}"
    );
    assert_eq!(reply["error"]["code"], json!(-32601), "{reply}");
    assert_eq!(
        reply["error"]["data"]["error_code"],
        json!("wrong_root"),
        "{reply}"
    );
    assert_eq!(
        reply["error"]["message"],
        json!("`oneiron.ask` is not an SDK verb; the verb is `ask`"),
        "{reply}"
    );
    assert_eq!(
        reply["error"]["data"]["attempted"],
        json!("oneiron.ask"),
        "{reply}"
    );
    assert_eq!(reply["error"]["data"]["replacement"], json!("ask"), "{reply}");
    assert_eq!(
        reply["error"]["data"]["schemaRef"],
        json!("oneiron:sdk/agent-verbs#ask"),
        "{reply}"
    );
    assert!(
        reply["error"]["data"].get("effective_scope").is_none(),
        "FIX 298: refused before any caller resolves, so with no scope to state: {reply}"
    );
    Ok(())
}

#[test]
fn wrong_root_refusal_answers_a_credential_that_cannot_resolve() -> TestResult {
    on_engine_stack(wrong_root_answers_before_auth)
}

async fn wrong_root_answers_before_auth() -> TestResult {
    let fixture = Fixture::new()?;
    // The check is static: even a Bearer token no caller could resolve gets
    // the wrong-root refusal, not an auth error.
    let (status, reply) = fixture.call_bearer("not-a-credential", 2, WRONG_ROOT_NAME).await?;
    assert_eq!(status, 200, "a refusal is still a 200 JSON-RPC error: {reply}");
    assert!(
        reply.get("result").is_none(),
        "the wrong root is refused: {reply}"
    );
    assert_eq!(
        reply["error"]["data"]["error_code"],
        json!("wrong_root"),
        "FIX 298: the static name check runs before actor resolution: {reply}"
    );
    assert!(
        reply["error"]["data"].get("effective_scope").is_none(),
        "no caller resolved, so no scope to state: {reply}"
    );
    Ok(())
}

#[test]
fn unknown_name_still_refuses_under_the_resolved_credential() -> TestResult {
    on_engine_stack(unknown_tool_stays_scoped)
}

async fn unknown_tool_stays_scoped() -> TestResult {
    let fixture = Fixture::new()?;
    // A name with no one verb it could mean is not a wrong root: its caller
    // still resolves first (learning this fresh slip), and the refusal
    // states the scope it was refused under.
    let reader = fixture.mint_reader(0x62)?;
    let (status, reply) = fixture.call_as(&reader, 3, UNKNOWN_NAME).await?;
    assert_eq!(status, 200, "a refusal is still a 200 JSON-RPC error: {reply}");
    assert!(
        reply.get("result").is_none(),
        "the retired name is refused: {reply}"
    );
    assert_eq!(
        reply["error"]["data"]["error_code"],
        json!("unknown_tool"),
        "{reply}"
    );
    assert!(
        reply["error"]["data"].get("effective_scope").is_some(),
        "an unknown name still resolves its caller first: {reply}"
    );
    Ok(())
}
