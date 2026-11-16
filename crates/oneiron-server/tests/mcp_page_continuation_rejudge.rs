#![cfg(oneiron_test_support)]
//! L1-05 (ARCH-0028 #mcp-continuation-open): an MCP page continuation is
//! judged again under its caller's CURRENT read, as a fresh call is. A
//! distinct person's `core:read` slip pages the gate ledger (`vault.receipts`)
//! one receipt at a time. Its result is derived from two owner claims: one
//! that names no relationship, and one in a relationship space the reader
//! reads under a live `RelationshipClaimsRead` Grant. Once the owner revokes
//! that Grant, page two of the earlier call is refused with the continuation
//! refusal, and the caller starts over from page one under the read it holds
//! now. With nothing changed, page two is served. A Grant revoked while page
//! one is made, after its producer read and before its mint, refuses page two
//! too (a door runs the revoke at that point), and so does a Grant that
//! expires there (the door steps the vault's manual clock to its end).
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test mcp_page_continuation_rejudge`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::test_doors::mcp_page_mint::before_next_page_mint;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const OCCURRED_AT: u64 = 1_769_947_200;
const OPEN_TEXT: &str = "continuation quartz open";
const SPACE_TEXT: &str = "continuation quartz in the space";
const MCP_PATH: &str = "/mcp/tool-first";
const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
const RECEIPTS_TOOL: &str = "vault.receipts";
const CURSOR_REFUSED: &str = "mcp_page_cursor_invalid";
/// How long the expiring Grant lives on the manual clock: inside one
/// authorization lease (5 s), so the step to its end renews nothing.
const GRANT_LIFETIME_SECS: u64 = 2;

/// A slip, the person it names and the key its holder proves it with.
struct Holder {
    person: EntityId,
    slip: CapabilitySlip,
    key: SigningKey,
}

/// A rooted vault behind the MCP gateway, a distinct reader holding a
/// `core:read` slip and a live Grant to read the claims of one relationship
/// space, and two owner claims: `open` (no relationship) and `in_space`.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    reader: Holder,
    grant: EntityId,
    open: EntityId,
    in_space: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::open(None, None)
    }

    /// `clock`: a manual vault clock, else the real one. `expires_at`: the
    /// reader's Grant's end, else none.
    fn open(clock: Option<&Arc<ManualClock>>, expires_at: Option<u64>) -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        if let Some(clock) = clock {
            config.store_clock = clock.bundle();
        }
        let vault = Arc::new(Vault::open(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let reader = mint_reader(&vault, &issuer, &root)?;
        let space = EntityId::now();
        vault.put_entity(
            &space,
            oneiron::registry::ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 1, end: 1 },
            1,
            b"a relationship space",
        )?;
        let grant = EntityId::now();
        vault.create_access_grant(
            &grant,
            &AccessGrant {
                principal_ref: reader.person,
                scope: AccessGrantScope::RelationshipClaims { space_ref: space },
                capability: AccessGrantCapability::RelationshipClaimsRead,
                authority_scope: Scope::top(),
                status: AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at,
                companion_bounds: None,
            },
        )?;
        let in_space = write_owner_claim(
            &vault,
            owner,
            &owner_proof,
            ClaimRelationships::Relationships(vec![space.to_hex()]),
            SPACE_TEXT,
        )?;
        let open = write_owner_claim(
            &vault,
            owner,
            &owner_proof,
            ClaimRelationships::All(AllRelationships::All),
            OPEN_TEXT,
        )?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("mcp-page-continuation-rejudge".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(server),
            vault,
            reader,
            grant,
            open,
            in_space,
            _dir: dir,
        })
    }

    /// One JSON-RPC request to the tool-first MCP endpoint, under the
    /// reader's slip and a fresh holder proof: the HTTP status and the reply.
    async fn rpc(&self, id: u64, method: &str, params: Value) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self
            .reader
            .key
            .sign(&self.reader.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::post(MCP_PATH)
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", self.reader.slip.to_token()?),
            )
            .header("x-oneiron-binding", binding.to_string())
            .header("mcp-protocol-version", MCP_PROTOCOL_VERSION)
            .body(Body::from(
                json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
                    .to_string(),
            ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let reply = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, reply))
    }

    /// Initializes the reader's connection and reads the schema version
    /// `vault.receipts` is called with.
    async fn connect(&self) -> TestResult<Value> {
        let (status, reply) = self
            .rpc(
                1,
                "initialize",
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "mcp-page-continuation-rejudge", "version": "1" },
                }),
            )
            .await?;
        assert_eq!(status, 200, "FIXTURE: the reader initializes: {reply}");
        assert!(
            reply.get("error").is_none(),
            "FIXTURE: the reader initializes: {reply}"
        );
        let (status, listed) = self.rpc(2, "tools/list", json!({})).await?;
        assert_eq!(status, 200, "{listed}");
        let version = listed["result"]["tools"]
            .as_array()
            .ok_or("tools/list lists tools")?
            .iter()
            .find(|tool| tool["name"] == RECEIPTS_TOOL)
            .map(|tool| tool["inputSchema"]["properties"]["schema_version"]["const"].clone())
            .ok_or("FIXTURE: the tool-first endpoint lists vault.receipts")?;
        Ok(version)
    }

    /// `vault.receipts` of the gate ledger's newest page, with `page` as
    /// the MCP page request when one is given.
    async fn receipts(
        &self,
        id: u64,
        version: &Value,
        page: Option<Value>,
    ) -> TestResult<(u16, Value)> {
        let mut arguments = json!({
            "schema_version": version,
            "consent": {
                "policy_ref": "policy:agent-session",
                "purpose": "read the gate ledger within the credential's read",
            },
            "arguments": { "spec": {} },
        });
        if let Some(page) = page {
            arguments["page"] = page;
        }
        self.rpc(
            id,
            "tools/call",
            json!({ "name": RECEIPTS_TOOL, "arguments": arguments }),
        )
        .await
    }

    /// The reader's whole receipts page, unpaged: the claims it names.
    async fn claims_read_now(&self, id: u64, version: &Value) -> TestResult<BTreeSet<String>> {
        let (status, reply) = self.receipts(id, version, None).await?;
        assert_eq!(status, 200, "{reply}");
        assert!(reply.get("error").is_none(), "an unpaged read: {reply}");
        Ok(claim_refs(&reply))
    }
}

/// A distinct person's `core:read` slip, minted under the vault's logged
/// issuer as pairing mints one, as mcp_caveated_reader.rs mints its reader.
fn mint_reader(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
) -> TestResult<Holder> {
    let person = EntityId::now();
    vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a distinct reader",
    )?;
    let key = SigningKey::from_bytes(&[0x62; 32]);
    let mut claims = root.claims.clone();
    claims.parent_id = None;
    claims.slip_id = [0x62; 32];
    claims.holder_ref = person.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope = Scope::top();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    let slip = vault.mint_capability_slip(issuer, claims)?;
    Ok(Holder { person, slip, key })
}

fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    relationships: ClaimRelationships,
    value: &str,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: vault.default_facet()?.to_hex(),
                scope_relationship_id: relationships,
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })?;
    Ok(id)
}

/// The claims a `vault.receipts` reply's receipts name.
fn claim_refs(reply: &Value) -> BTreeSet<String> {
    reply["result"]["structuredContent"]["output"]["receipts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|receipt| receipt["claim_ref"].as_str().map(str::to_owned))
        .collect()
}

/// How many receipts a `vault.receipts` reply's page holds.
fn receipt_count(reply: &Value) -> usize {
    reply["result"]["structuredContent"]["output"]["receipts"]
        .as_array()
        .map_or(0, Vec::len)
}

/// The continuation handle a paged reply carries.
fn next_cursor(reply: &Value) -> Option<String> {
    reply["result"]["structuredContent"]["meta"]["page"]["cursor"]
        .as_str()
        .map(str::to_owned)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The JSON-RPC error kind of `reply`, if it is an error.
fn error_kind(reply: &Value) -> Option<&str> {
    reply["error"]["data"]["error_code"].as_str()
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

/// Page one of the ledger, one receipt long, read while both claims are
/// readable: its continuation handle.
async fn page_one(fixture: &Fixture, version: &Value) -> TestResult<String> {
    let read = fixture.claims_read_now(3, version).await?;
    assert!(
        read.contains(&fixture.open.to_hex()) && read.contains(&fixture.in_space.to_hex()),
        "FIXTURE: under its live Grant the reader reads both claims' receipts: {read:?}"
    );
    let (status, first) = fixture
        .receipts(4, version, Some(json!({ "limit": 1 })))
        .await?;
    assert_eq!(status, 200, "{first}");
    assert!(first.get("error").is_none(), "page one is served: {first}");
    assert_eq!(
        receipt_count(&first),
        1,
        "page one holds one receipt: {first}"
    );
    let cursor =
        next_cursor(&first).ok_or_else(|| format!("FIXTURE: page one continues: {first}"))?;
    Ok(cursor)
}

#[test]
fn mcp_page_continuation_served_while_read_unchanged() -> TestResult {
    on_engine_stack(served_while_read_unchanged)
}

async fn served_while_read_unchanged() -> TestResult {
    let fixture = Fixture::new()?;
    let version = fixture.connect().await?;
    let generation = fixture.vault.authority_generation()?;
    let cursor = page_one(&fixture, &version).await?;
    assert_eq!(
        fixture.vault.authority_generation()?,
        generation,
        "a page one call commits nothing to the authority log, so its mint keeps only the rows its reader read"
    );
    let (status, second) = fixture
        .receipts(5, &version, Some(json!({ "limit": 1, "cursor": cursor })))
        .await?;
    assert_eq!(status, 200, "{second}");
    assert!(
        second.get("error").is_none(),
        "with the reader's read unchanged, page two is served: {second}"
    );
    assert_eq!(
        receipt_count(&second),
        1,
        "page two holds the next receipt: {second}"
    );
    Ok(())
}

#[test]
fn mcp_page_continuation_rejudged_under_current_read() -> TestResult {
    on_engine_stack(rejudged_under_current_read)
}

async fn rejudged_under_current_read() -> TestResult {
    let fixture = Fixture::new()?;
    let version = fixture.connect().await?;
    let cursor = page_one(&fixture, &version).await?;

    // The owner revokes the reader's Grant to the space. A fresh read no
    // longer names the claim in it, and still names the open one.
    fixture
        .vault
        .revoke_access_grant(&fixture.grant, fixture.vault.now_recorded_at())?;
    let read = fixture.claims_read_now(5, &version).await?;
    assert!(
        !read.contains(&fixture.in_space.to_hex()) && read.contains(&fixture.open.to_hex()),
        "FIXTURE: once its Grant is revoked, a fresh read drops the space's claim only: {read:?}"
    );

    // Page two of the earlier call was derived from the claim the reader may
    // no longer read: the continuation is refused, and names nothing of it.
    let (status, second) = fixture
        .receipts(6, &version, Some(json!({ "limit": 1, "cursor": cursor })))
        .await?;
    assert_eq!(status, 200, "{second}");
    assert_eq!(
        error_kind(&second),
        Some(CURSOR_REFUSED),
        "a continuation is judged again under the reader's current read: {second}"
    );
    let text = second.to_string();
    let in_space = fixture.in_space.to_hex();
    for withheld in [SPACE_TEXT, in_space.as_str()] {
        assert!(
            !text.contains(withheld),
            "the refusal names {withheld}: {text}"
        );
    }

    // The caller starts over from page one, under the read it holds now.
    let (status, again) = fixture
        .receipts(7, &version, Some(json!({ "limit": 1 })))
        .await?;
    assert_eq!(status, 200, "{again}");
    assert!(
        again.get("error").is_none(),
        "a fresh page one is served: {again}"
    );
    assert!(
        !claim_refs(&again).contains(&in_space),
        "a fresh page one reads under the current read: {again}"
    );
    Ok(())
}

#[test]
fn mcp_page_continuation_rejudged_after_a_revoke_during_page_one() -> TestResult {
    on_engine_stack(rejudged_after_a_revoke_during_page_one)
}

/// The owner revokes the reader's Grant while page one is made: after its
/// producer read both claims, before its mint judged which rows the reader
/// read. Which rows that read admitted is then unknown, so page two is judged
/// by every row page one was made from, and refused.
async fn rejudged_after_a_revoke_during_page_one() -> TestResult {
    let fixture = Fixture::new()?;
    let version = fixture.connect().await?;
    let read = fixture.claims_read_now(3, &version).await?;
    assert!(
        read.contains(&fixture.open.to_hex()) && read.contains(&fixture.in_space.to_hex()),
        "FIXTURE: under its live Grant the reader reads both claims' receipts: {read:?}"
    );
    let revoked = Arc::new(AtomicBool::new(false));
    {
        let vault = Arc::clone(&fixture.vault);
        let grant = fixture.grant;
        let revoked = Arc::clone(&revoked);
        before_next_page_mint(&fixture.vault, move || {
            vault
                .revoke_access_grant(&grant, vault.now_recorded_at())
                .expect("FIXTURE: the owner revokes the reader's Grant while page one is made");
            revoked.store(true, Ordering::SeqCst);
        });
    }
    let (status, first) = fixture
        .receipts(4, &version, Some(json!({ "limit": 1 })))
        .await?;
    assert_eq!(status, 200, "{first}");
    assert!(first.get("error").is_none(), "page one is served: {first}");
    assert!(
        revoked.load(Ordering::SeqCst),
        "FIXTURE: the Grant is revoked between page one's producer and its mint"
    );
    let cursor =
        next_cursor(&first).ok_or_else(|| format!("FIXTURE: page one continues: {first}"))?;
    let read = fixture.claims_read_now(5, &version).await?;
    assert!(
        !read.contains(&fixture.in_space.to_hex()) && read.contains(&fixture.open.to_hex()),
        "FIXTURE: once its Grant is revoked, a fresh read drops the space's claim only: {read:?}"
    );

    let (status, second) = fixture
        .receipts(6, &version, Some(json!({ "limit": 1, "cursor": cursor })))
        .await?;
    assert_eq!(status, 200, "{second}");
    assert_eq!(
        error_kind(&second),
        Some(CURSOR_REFUSED),
        "a page made across a revoke continues only under every row it was made from: {second}"
    );
    let text = second.to_string();
    let in_space = fixture.in_space.to_hex();
    for withheld in [SPACE_TEXT, in_space.as_str()] {
        assert!(
            !text.contains(withheld),
            "the refusal names {withheld}: {text}"
        );
    }
    Ok(())
}

#[test]
fn mcp_page_continuation_rejudged_after_a_grant_expires_during_page_one() -> TestResult {
    on_engine_stack(rejudged_after_a_grant_expires_during_page_one)
}

/// The reader's Grant expires while page one is made: the vault's manual
/// clock steps to its end after page one's producer read both claims, before
/// its mint judged which rows the reader read. An expiry is judged at each
/// read and writes nothing, so the authority generation stays where it was.
/// Which rows the producer's read admitted is still unknown at the mint, so
/// page two is judged by every row page one was made from, and refused.
async fn rejudged_after_a_grant_expires_during_page_one() -> TestResult {
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let clock = ManualClock::new(start);
    let expires_at = start + GRANT_LIFETIME_SECS;
    let fixture = Fixture::open(Some(&clock), Some(expires_at))?;
    let version = fixture.connect().await?;
    let read = fixture.claims_read_now(3, &version).await?;
    assert!(
        read.contains(&fixture.open.to_hex()) && read.contains(&fixture.in_space.to_hex()),
        "FIXTURE: before its Grant's end the reader reads both claims' receipts: {read:?}"
    );
    let expired = Arc::new(AtomicBool::new(false));
    {
        let clock = Arc::clone(&clock);
        let expired = Arc::clone(&expired);
        before_next_page_mint(&fixture.vault, move || {
            clock.set(expires_at);
            expired.store(true, Ordering::SeqCst);
        });
    }
    let generation = fixture.vault.authority_generation()?;
    let (status, first) = fixture
        .receipts(4, &version, Some(json!({ "limit": 1 })))
        .await?;
    assert_eq!(status, 200, "{first}");
    assert!(first.get("error").is_none(), "page one is served: {first}");
    assert!(
        expired.load(Ordering::SeqCst),
        "FIXTURE: the Grant's end comes between page one's producer and its mint"
    );
    assert_eq!(
        fixture.vault.authority_generation()?,
        generation,
        "FIXTURE: an expiry commits nothing to the authority log"
    );
    let cursor =
        next_cursor(&first).ok_or_else(|| format!("FIXTURE: page one continues: {first}"))?;
    let read = fixture.claims_read_now(5, &version).await?;
    assert!(
        !read.contains(&fixture.in_space.to_hex()) && read.contains(&fixture.open.to_hex()),
        "FIXTURE: past its Grant's end, a fresh read drops the space's claim only: {read:?}"
    );

    let (status, second) = fixture
        .receipts(6, &version, Some(json!({ "limit": 1, "cursor": cursor })))
        .await?;
    assert_eq!(status, 200, "{second}");
    assert_eq!(
        error_kind(&second),
        Some(CURSOR_REFUSED),
        "a page made across a Grant's expiry continues only under every row it was made from: {second}"
    );
    let text = second.to_string();
    let in_space = fixture.in_space.to_hex();
    for withheld in [SPACE_TEXT, in_space.as_str()] {
        assert!(
            !text.contains(withheld),
            "the refusal names {withheld}: {text}"
        );
    }
    Ok(())
}
