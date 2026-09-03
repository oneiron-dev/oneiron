// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1778 (CA-07) surface oracle.
//!
//! The claim this file exists to pin is PARITY: the HTTP routes and an
//! in-process `self.*` caller reach the same engine functions and receive the
//! same document. Every CRUD row below therefore runs one operation over HTTP
//! and the identical operation through `invoke_campaign_surface` against the
//! SAME vault, and compares the serialized replies — a transport that grew its
//! own campaign semantics would diverge here before it could reach a bot.
//!
//! Pack id is `oneiron-crm` throughout; the CRM kinds are registered from
//! `register_crm_pack`, so the oracle exercises the real dynamic-registration
//! path rather than a fixture byte.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use oneiron::campaign::surface::{
    CAMPAIGN_SELF_VERBS, CampaignSurfaceVerb, MEMBERSHIP_PAGE_MAX_LIMIT, SurfaceCall,
    invoke_campaign_surface,
};
use oneiron::campaign::{CRM_PACK_ID, register_crm_pack};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::{EdgeActorClass, EntityId, MemoryError, TimeRange, Vault, VaultConfig};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::mcp::{McpSurfaceMode, McpToolName, registered_surface};
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SECRET: &str = "campaign-surface-oracle-secret";
const CAMPAIGN_TYPE_BYTE: u8 = 107;
const SAVED_QUERY_TYPE_BYTE: u8 = 108;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    config
}

fn seeded_id(counter: u128) -> EntityId {
    let mut bytes = counter.to_be_bytes();
    bytes[0] = 0xca;
    EntityId::from_bytes(bytes).expect("seeded test id should be valid")
}

/// A vault with the CRM pack installed and one PERSON to act as the
/// authenticated principal.
///
/// Opened through the ordinary `Vault::open` — the same door the server uses —
/// rather than the engine's unseeded test opener, which lives behind a feature
/// this crate's dev-dependency does not enable. The surface's writes are entity
/// puts and CA-02 lifecycle calls, so the seeded default manifest is the
/// realistic setting rather than an obstacle.
fn oracle_vault() -> (tempfile::TempDir, Arc<Vault>, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
    let pack = register_crm_pack(&vault, CAMPAIGN_TYPE_BYTE, SAVED_QUERY_TYPE_BYTE).unwrap();
    assert_eq!(pack.campaign.pack, CRM_PACK_ID);
    assert_eq!(pack.saved_query.pack, CRM_PACK_ID);
    let principal = seeded_id(0x01);
    put_person(&vault, principal);
    (dir, Arc::new(vault), principal)
}

fn put_person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"campaign surface oracle person",
        )
        .unwrap();
}

/// Mints a v2 core token, the way `auth.rs` derives the MAC.
///
/// Spelled out rather than called into the crate: this is the black-box side,
/// so the KDF context and the `v2.<claims>.<mac-hex>` framing are wire facts the
/// oracle pins rather than borrows.
fn token_for(principal: EntityId, scopes: &str) -> String {
    let claims = format!("scope={scopes};principal_ref={}", principal.to_hex());
    let key = blake3::derive_key(
        "oneiron-server 2026-07 core-token-v2 mac",
        SECRET.as_bytes(),
    );
    let mac = blake3::keyed_hash(&key, claims.as_bytes());
    format!("v2.{claims}.{}", mac.to_hex())
}

fn owner_token(principal: EntityId) -> String {
    token_for(principal, "core:read,core:write")
}

async fn spawn_server(vault: Arc<Vault>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config = SyncServerConfig {
        auth_secret: Some(SECRET.to_owned()),
        ..Default::default()
    };
    let server = Arc::new(SyncServer::new(vault, config).unwrap());
    let app = build_app(server);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

/// One raw HTTP round trip, returning `(status, parsed body)`.
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> (u16, Value) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let auth = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let payload = body.map(serde_json::to_string).transpose().unwrap();
    let framing = payload.as_ref().map_or_else(String::new, |payload| {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        )
    });
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{auth}{framing}\r\n{}",
        payload.unwrap_or_default()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out waiting for HTTP response")
        .expect("failed reading HTTP response");
    let response = String::from_utf8(response).unwrap();
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no HTTP status in {:?}", response.lines().next()));
    let raw = response
        .split_once("\r\n\r\n")
        .map(|(_headers, body)| body)
        .expect("HTTP response should contain header/body delimiter");
    let parsed = serde_json::from_str(raw).unwrap_or(Value::Null);
    (status, parsed)
}

/// Dispatches one surface call in-process, exactly as the routers do.
fn call(vault: &Vault, actor: EntityId, verb: &str, body: Value) -> Result<Value, MemoryError> {
    let facade = vault.memory(actor, EdgeActorClass::Human);
    let reply = invoke_campaign_surface(
        &facade,
        SurfaceCall {
            verb: verb.to_owned(),
            body,
        },
    )?;
    Ok(serde_json::to_value(&reply).unwrap())
}

fn expect_call(vault: &Vault, actor: EntityId, verb: &str, body: Value) -> Value {
    call(vault, actor, verb, body).unwrap_or_else(|error| panic!("{verb} failed: {error}"))
}

/// Strips the fields that legitimately differ between two records created by
/// two separate calls: identity and wall-clock stamps.
fn normalized(mut reply: Value) -> Value {
    for volatile in ["campaign_ref", "query_ref", "created_at", "updated_at"] {
        if let Some(record) = reply.pointer_mut("/body/record")
            && let Some(object) = record.as_object_mut()
        {
            object.remove(volatile);
        }
        if let Some(object) = reply.pointer_mut("/body").and_then(Value::as_object_mut) {
            object.remove(volatile);
        }
    }
    reply
}

fn record_ref(reply: &Value, field: &str) -> String {
    reply
        .pointer(&format!("/body/{field}"))
        .or_else(|| reply.pointer(&format!("/body/record/{field}")))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("reply carries no {field}: {reply}"))
        .to_owned()
}

/// Every entity in the vault, by type and id. Two identical fingerprints mean
/// nothing was written between them.
fn vault_fingerprint(vault: &Vault) -> Vec<(u8, String)> {
    let mut rows = Vec::new();
    for entity_type in u8::MIN..=u8::MAX {
        for id in vault.entities_by_type(entity_type).unwrap_or_default() {
            rows.push((entity_type, id.to_hex()));
        }
    }
    rows.sort_unstable();
    rows
}

fn saved_query_body() -> Value {
    json!({
        "scope": { "worlds": [], "facets": ["sales"] },
        "filter": { "op": "claim", "predicate": "profile.seniority", "cmp": "eq", "value": "vp" },
        "matcher": {
            "kind": "hard",
            "expression": {
                "op": "claim",
                "predicate": "profile.headcount",
                "cmp": "gte",
                "value": 50
            }
        },
        "eval": { "mode": "manual", "max_entities_per_wake": 8, "max_judges_per_wake": 4 }
    })
}

// ---------------------------------------------------------------------------
// Verb vocabulary
// ---------------------------------------------------------------------------

/// Every advertised constant parses to exactly one verb and serializes back to
/// the identical string; nothing outside the closed list parses.
#[test]
fn campaign_surface_verb_round_trip() {
    assert_eq!(CAMPAIGN_SELF_VERBS.len(), CampaignSurfaceVerb::ALL.len());
    for name in CAMPAIGN_SELF_VERBS {
        let verb = CampaignSurfaceVerb::parse(name)
            .unwrap_or_else(|| panic!("{name} should parse to a surface verb"));
        assert_eq!(verb.as_str(), *name);
    }
    // One constant per variant, no aliasing.
    let mut names: Vec<&str> = CampaignSurfaceVerb::ALL
        .iter()
        .map(|verb| verb.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), CAMPAIGN_SELF_VERBS.len());

    // Prefix-confusable, suffix-extended, case-shifted, whitespace-padded, and
    // family-crossed names are all rejected: parsing is exact equality, not a
    // starts_with over a namespace.
    for rejected in [
        "self.campaign.creat",
        "self.campaign.create.extra",
        "self.campaign.creates",
        "Self.Campaign.Create",
        " self.campaign.create",
        "self.campaign.create ",
        "self.campaign",
        "self.saved_query",
        "self.savedquery.create",
        "self.campaign.delete",
        "self.saved_query.delete",
        "",
    ] {
        assert!(
            CampaignSurfaceVerb::parse(rejected).is_none(),
            "{rejected:?} must not parse"
        );
    }

    // Writes and reads are partitioned; membership is a read despite its name.
    assert!(CampaignSurfaceVerb::CampaignCreate.is_write());
    assert!(CampaignSurfaceVerb::SavedQueryArchive.is_write());
    assert!(!CampaignSurfaceVerb::CampaignMembers.is_write());
    assert!(!CampaignSurfaceVerb::SavedQueryMembers.is_write());
    assert_eq!(
        CampaignSurfaceVerb::ALL
            .iter()
            .filter(|verb| verb.is_write())
            .count(),
        6
    );
}

/// All ten verbs reach the engine through ONE door, with no transport in the
/// picture. This is the property a future MCP gateway arm inherits for free:
/// a dialect that builds a `SurfaceCall` gets the HTTP routes' exact behavior.
#[test]
fn campaign_surface_reaches_all_ten_verbs_through_one_engine_door() {
    let (_dir, vault, principal) = oracle_vault();

    let campaign = record_ref(
        &expect_call(
            &vault,
            principal,
            "self.campaign.create",
            json!({ "name": "door" }),
        ),
        "campaign_ref",
    );
    let query = record_ref(
        &expect_call(
            &vault,
            principal,
            "self.saved_query.create",
            saved_query_body(),
        ),
        "query_ref",
    );

    let bodies = [
        ("self.campaign.read", json!({ "campaign_ref": campaign })),
        (
            "self.campaign.update",
            json!({ "campaign_ref": campaign, "expected_definition_version": 1, "name": "door2" }),
        ),
        (
            "self.campaign.members",
            json!({ "campaign_ref": campaign, "limit": 5 }),
        ),
        (
            "self.campaign.archive",
            json!({ "campaign_ref": campaign, "expected_definition_version": 2 }),
        ),
        ("self.saved_query.read", json!({ "query_ref": query })),
        ("self.saved_query.members", json!({ "query_ref": query })),
    ];
    for (verb, body) in bodies {
        let reply = expect_call(&vault, principal, verb, body);
        assert_eq!(reply["verb"], Value::String(verb.to_owned()));
    }

    // An unadvertised verb is refused by the dispatcher itself, before any
    // vault access.
    let rejected = call(
        &vault,
        principal,
        "self.campaign.destroy",
        json!({ "campaign_ref": campaign }),
    )
    .expect_err("an unlisted verb must not dispatch");
    assert_eq!(rejected.code, oneiron::MEMORY_CODE_BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// CRUD parity
// ---------------------------------------------------------------------------

/// Create/read/update/archive over HTTP and over the facade land the same
/// domain state and return the same document.
#[tokio::test]
async fn campaign_http_crud_matches_facade() {
    let (_dir, vault, principal) = oracle_vault();
    let (addr, handle) = spawn_server(Arc::clone(&vault)).await;
    let token = owner_token(principal);

    // CREATE: same request over both transports, compared after normalizing
    // identity and wall-clock stamps.
    let create = json!({ "name": "spring outreach" });
    let (status, over_http) =
        request(addr, "POST", "/campaigns", Some(&token), Some(&create)).await;
    assert_eq!(status, 200, "{over_http}");
    let in_process = expect_call(&vault, principal, "self.campaign.create", create.clone());
    assert_eq!(
        normalized(over_http.clone()),
        normalized(in_process.clone())
    );
    assert_eq!(over_http["verb"], "self.campaign.create");
    assert_eq!(
        over_http["body"]["definition"]["owner_actor"],
        Value::String(principal.to_hex())
    );
    assert_eq!(over_http["body"]["definition"]["definition_version"], 1);
    assert_eq!(over_http["body"]["definition"]["lifecycle"], "active");

    // READ of the SAME record over both transports must be byte-identical —
    // no normalization, because nothing volatile differs.
    let http_ref = record_ref(&over_http, "campaign_ref");
    let (status, http_read) = request(
        addr,
        "GET",
        &format!("/campaigns/{http_ref}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, 200, "{http_read}");
    let facade_read = expect_call(
        &vault,
        principal,
        "self.campaign.read",
        json!({ "campaign_ref": http_ref }),
    );
    assert_eq!(http_read, facade_read);
    assert_eq!(http_read["body"]["found"], true);

    // UPDATE: HTTP moves the HTTP-created record, the facade moves its own.
    let update = json!({ "expected_definition_version": 1, "name": "spring outreach v2" });
    let (status, http_update) = request(
        addr,
        "PATCH",
        &format!("/campaigns/{http_ref}"),
        Some(&token),
        Some(&update),
    )
    .await;
    assert_eq!(status, 200, "{http_update}");
    let facade_ref = record_ref(&in_process, "campaign_ref");
    let mut facade_update_body = update.clone();
    facade_update_body["campaign_ref"] = Value::String(facade_ref.clone());
    let facade_update = expect_call(
        &vault,
        principal,
        "self.campaign.update",
        facade_update_body,
    );
    assert_eq!(normalized(http_update.clone()), normalized(facade_update));
    assert_eq!(http_update["body"]["definition"]["definition_version"], 2);
    assert_eq!(
        http_update["body"]["definition"]["name"],
        "spring outreach v2"
    );

    // ARCHIVE is a transition: the record stays readable and keeps its id.
    let archive = json!({ "expected_definition_version": 2 });
    let (status, http_archive) = request(
        addr,
        "POST",
        &format!("/campaigns/{http_ref}/archive"),
        Some(&token),
        Some(&archive),
    )
    .await;
    assert_eq!(status, 200, "{http_archive}");
    let mut facade_archive_body = archive.clone();
    facade_archive_body["campaign_ref"] = Value::String(facade_ref);
    let facade_archive = expect_call(
        &vault,
        principal,
        "self.campaign.archive",
        facade_archive_body,
    );
    assert_eq!(normalized(http_archive.clone()), normalized(facade_archive));
    assert_eq!(http_archive["body"]["definition"]["lifecycle"], "archived");
    assert_eq!(http_archive["body"]["campaign_ref"], http_ref);

    let after_archive = expect_call(
        &vault,
        principal,
        "self.campaign.read",
        json!({ "campaign_ref": http_ref }),
    );
    assert_eq!(after_archive["body"]["found"], true);
    assert_eq!(
        after_archive["body"]["record"]["definition"]["lifecycle"],
        "archived"
    );
    assert_eq!(
        after_archive["body"]["record"]["definition"]["definition_version"],
        3
    );

    handle.abort();
}

/// The saved-query half of the same parity oracle. Filter-AST and version
/// validation are CA-02's — the server neither reimplements nor relaxes them.
#[tokio::test]
async fn saved_query_http_crud_matches_facade() {
    let (_dir, vault, principal) = oracle_vault();
    let (addr, handle) = spawn_server(Arc::clone(&vault)).await;
    let token = owner_token(principal);

    let create = saved_query_body();
    let (status, over_http) =
        request(addr, "POST", "/saved-queries", Some(&token), Some(&create)).await;
    assert_eq!(status, 200, "{over_http}");
    let in_process = expect_call(&vault, principal, "self.saved_query.create", create.clone());
    assert_eq!(
        normalized(over_http.clone()),
        normalized(in_process.clone())
    );
    assert_eq!(
        over_http["body"]["definition"]["owner_actor"],
        Value::String(principal.to_hex())
    );
    assert_eq!(
        over_http["body"]["definition"]["lifecycle"]["state"],
        "active"
    );
    assert_eq!(over_http["body"]["definition"]["filter"]["op"], "claim");
    assert_eq!(over_http["body"]["definition"]["matcher"]["kind"], "hard");

    let http_ref = record_ref(&over_http, "query_ref");
    let (status, http_read) = request(
        addr,
        "GET",
        &format!("/saved-queries/{http_ref}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, 200, "{http_read}");
    assert_eq!(
        http_read,
        expect_call(
            &vault,
            principal,
            "self.saved_query.read",
            json!({ "query_ref": http_ref })
        )
    );

    // CA-02 owns filter validation: a ranked operator is refused identically on
    // both transports, and the surface adds no second opinion.
    let mut ranked = saved_query_body();
    ranked["filter"] = json!({ "op": "top_k", "k": 10 });
    ranked["expected_definition_version"] = json!(1);
    let (status, rejected) = request(
        addr,
        "PATCH",
        &format!("/saved-queries/{http_ref}"),
        Some(&token),
        Some(&ranked),
    )
    .await;
    assert_eq!(status, 400, "{rejected}");
    let mut in_process_ranked = ranked.clone();
    in_process_ranked["query_ref"] = Value::String(http_ref.clone());
    let in_process_reject = call(
        &vault,
        principal,
        "self.saved_query.update",
        in_process_ranked,
    )
    .expect_err("a ranked operator must be refused in-process too");
    assert_eq!(in_process_reject.code, oneiron::MEMORY_CODE_BAD_REQUEST);
    assert!(
        in_process_reject.message.contains("top_k"),
        "{}",
        in_process_reject.message
    );

    // A stale CAS is refused on both transports as one conflict outcome.
    let mut stale = saved_query_body();
    stale["expected_definition_version"] = json!(99);
    let (status, conflict) = request(
        addr,
        "PATCH",
        &format!("/saved-queries/{http_ref}"),
        Some(&token),
        Some(&stale),
    )
    .await;
    assert_eq!(status, 409, "{conflict}");
    let mut in_process_stale = stale.clone();
    in_process_stale["query_ref"] = Value::String(http_ref.clone());
    assert_eq!(
        call(
            &vault,
            principal,
            "self.saved_query.update",
            in_process_stale
        )
        .expect_err("stale CAS must be refused in-process too")
        .code,
        oneiron::MEMORY_CODE_INVALID_STATE
    );

    let mut update = saved_query_body();
    update["expected_definition_version"] = json!(1);
    update["eval"] =
        json!({ "mode": "wake", "max_entities_per_wake": 4, "max_judges_per_wake": 2 });
    let (status, http_update) = request(
        addr,
        "PATCH",
        &format!("/saved-queries/{http_ref}"),
        Some(&token),
        Some(&update),
    )
    .await;
    assert_eq!(status, 200, "{http_update}");
    assert_eq!(http_update["body"]["definition"]["definition_version"], 2);
    assert_eq!(http_update["body"]["definition"]["eval"]["mode"], "wake");

    let facade_ref = record_ref(&in_process, "query_ref");
    let mut facade_update = update.clone();
    facade_update["query_ref"] = Value::String(facade_ref.clone());
    assert_eq!(
        normalized(http_update),
        normalized(expect_call(
            &vault,
            principal,
            "self.saved_query.update",
            facade_update
        ))
    );

    let (status, http_archive) = request(
        addr,
        "POST",
        &format!("/saved-queries/{http_ref}/archive"),
        Some(&token),
        Some(&json!({ "expected_definition_version": 2 })),
    )
    .await;
    assert_eq!(status, 200, "{http_archive}");
    assert_eq!(
        http_archive["body"]["definition"]["lifecycle"]["state"],
        "archived"
    );
    assert_eq!(
        normalized(http_archive),
        normalized(expect_call(
            &vault,
            principal,
            "self.saved_query.archive",
            json!({ "query_ref": facade_ref, "expected_definition_version": 2 })
        ))
    );

    // Archive is not a delete: the record is still addressable afterwards.
    let (status, after) = request(
        addr,
        "GET",
        &format!("/saved-queries/{http_ref}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, 200, "{after}");
    assert_eq!(after["body"]["found"], true);

    handle.abort();
}

// ---------------------------------------------------------------------------
// Owner binding
// ---------------------------------------------------------------------------

/// A caller cannot select another actor as owner, by payload or by reading
/// someone else's records.
#[tokio::test]
async fn saved_query_owner_actor_is_authenticated_principal() {
    let (_dir, vault, principal) = oracle_vault();
    let other = seeded_id(0x02);
    put_person(&vault, other);
    let (addr, handle) = spawn_server(Arc::clone(&vault)).await;
    let token = owner_token(principal);

    // The payload names another owner in every spelling the surface could
    // plausibly have honored. None of them is read.
    let mut spoofed = saved_query_body();
    spoofed["owner_actor"] = Value::String(other.to_hex());
    spoofed["owner"] = Value::String(other.to_hex());
    spoofed["principal_ref"] = Value::String(other.to_hex());
    spoofed["definition"] = json!({ "owner_actor": other.to_hex() });
    let (status, created) =
        request(addr, "POST", "/saved-queries", Some(&token), Some(&spoofed)).await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(
        created["body"]["definition"]["owner_actor"],
        Value::String(principal.to_hex()),
        "owner_actor must come from the credential, never the payload"
    );

    // The same spoof through a campaign create.
    let (status, campaign) = request(
        addr,
        "POST",
        "/campaigns",
        Some(&token),
        Some(&json!({ "name": "spoof", "owner_actor": other.to_hex() })),
    )
    .await;
    assert_eq!(status, 200, "{campaign}");
    assert_eq!(
        campaign["body"]["definition"]["owner_actor"],
        Value::String(principal.to_hex())
    );

    // Ownership IS the read: a different principal does not see the record.
    let query_ref = record_ref(&created, "query_ref");
    let (status, foreign) = request(
        addr,
        "GET",
        &format!("/saved-queries/{query_ref}"),
        Some(&owner_token(other)),
        None,
    )
    .await;
    assert_eq!(status, 200, "{foreign}");
    assert_eq!(foreign["body"]["found"], false);
    assert_eq!(foreign["body"]["record"], Value::Null);

    // And cannot move it: absent-or-not-yours is one answer.
    let mut hijack = saved_query_body();
    hijack["expected_definition_version"] = json!(1);
    let (status, refused) = request(
        addr,
        "PATCH",
        &format!("/saved-queries/{query_ref}"),
        Some(&owner_token(other)),
        Some(&hijack),
    )
    .await;
    assert_eq!(status, 404, "{refused}");

    handle.abort();
}

/// Writes cannot bypass the actor-bound admission, and reads invent no
/// approval step of their own.
#[test]
fn campaign_surface_write_uses_memory_gate() {
    let (_dir, vault, principal) = oracle_vault();
    let ghost = seeded_id(0x0F); // a well-formed id the store never admitted

    // Every WRITE verb refuses an unadmitted actor, and refuses it as the gate
    // does: FORBIDDEN, not a bad request and not a not-found. The distinction
    // matters — a not-found would tell a caller to go create the record.
    let missing = seeded_id(0x11).to_hex();
    for (verb, body) in [
        ("self.campaign.create", json!({ "name": "ghost" })),
        (
            "self.campaign.update",
            json!({ "campaign_ref": missing, "expected_definition_version": 1, "name": "x" }),
        ),
        (
            "self.campaign.archive",
            json!({ "campaign_ref": missing, "expected_definition_version": 1 }),
        ),
        ("self.saved_query.create", saved_query_body()),
        ("self.saved_query.update", {
            // A COMPLETE body: payload parsing runs before the facade is
            // reached, so a malformed one would be refused as a bad request
            // and prove nothing about admission.
            let mut update = saved_query_body();
            update["query_ref"] = Value::String(missing.clone());
            update["expected_definition_version"] = json!(1);
            update
        }),
        (
            "self.saved_query.archive",
            json!({ "query_ref": missing, "expected_definition_version": 1 }),
        ),
    ] {
        let error = call(&vault, ghost, verb, body)
            .expect_err("an unadmitted actor must not reach a domain mutation");
        assert_eq!(
            error.code,
            oneiron::MEMORY_CODE_FORBIDDEN,
            "{verb} refused with {} instead of the gate's answer",
            error.code
        );
    }

    // The refusal is admission, not arithmetic: the write never reached the
    // domain, so nothing landed.
    assert_eq!(
        vault
            .entities_by_type(CAMPAIGN_TYPE_BYTE)
            .unwrap_or_default()
            .len(),
        0
    );
    assert_eq!(
        vault
            .entities_by_type(SAVED_QUERY_TYPE_BYTE)
            .unwrap_or_default()
            .len(),
        0
    );

    // READ verbs take the same binding check — a cohort is not enumerable from
    // an actor the store never admitted...
    for (verb, body) in [
        ("self.campaign.read", json!({ "campaign_ref": missing })),
        ("self.campaign.members", json!({ "campaign_ref": missing })),
        ("self.saved_query.read", json!({ "query_ref": missing })),
        ("self.saved_query.members", json!({ "query_ref": missing })),
    ] {
        assert_eq!(
            call(&vault, ghost, verb, body)
                .expect_err("an unadmitted actor must not read")
                .code,
            oneiron::MEMORY_CODE_FORBIDDEN,
            "{verb}"
        );
    }

    // ...and a LEGITIMATE read invents no approval step: it leaves the vault
    // byte-identical, with no pending-write or gate row behind it.
    let campaign = record_ref(
        &expect_call(
            &vault,
            principal,
            "self.campaign.create",
            json!({ "name": "gate" }),
        ),
        "campaign_ref",
    );
    let before = vault_fingerprint(&vault);
    for (verb, body) in [
        ("self.campaign.read", json!({ "campaign_ref": campaign })),
        ("self.campaign.members", json!({ "campaign_ref": campaign })),
    ] {
        let reply = expect_call(&vault, principal, verb, body);
        assert_eq!(reply["verb"], Value::String(verb.to_owned()));
    }
    assert_eq!(
        vault_fingerprint(&vault),
        before,
        "a read must not write anything, approval row included"
    );
    assert!(
        vault
            .memory(principal, EdgeActorClass::Human)
            .pending_writes(8)
            .unwrap()
            .is_empty(),
        "reads must not queue an approval"
    );
}

// ---------------------------------------------------------------------------
// Membership routes
// ---------------------------------------------------------------------------

/// The two `members` routes carry the engine's paging contract to HTTP without
/// adding one of their own.
///
/// The FOLD itself — cursor stability across a boundary, limit clamping,
/// bitemporal `at_epoch`, and cause preservation — is pinned in
/// `oneiron::campaign::surface`'s own tests, because seeding a cohort means
/// writing `campaign.member` claims and the default policy manifest declares no
/// axes for CRM predicates, so every such write is held at the gate's
/// criticality floor in a `Vault::open`ed vault. What HTTP owns is the wiring:
/// route shape, scope, query-string translation, and error mapping. That is
/// what this row proves.
#[tokio::test]
async fn campaign_membership_routes_carry_the_engine_paging_contract() {
    let (_dir, vault, principal) = oracle_vault();
    let (addr, handle) = spawn_server(Arc::clone(&vault)).await;
    let token = owner_token(principal);

    let campaign = record_ref(
        &expect_call(
            &vault,
            principal,
            "self.campaign.create",
            json!({ "name": "cohort" }),
        ),
        "campaign_ref",
    );
    let query = record_ref(
        &expect_call(
            &vault,
            principal,
            "self.saved_query.create",
            saved_query_body(),
        ),
        "query_ref",
    );

    for (path, verb) in [
        (
            format!("/campaigns/{campaign}/members"),
            "self.campaign.members",
        ),
        (
            format!("/saved-queries/{query}/members"),
            "self.saved_query.members",
        ),
    ] {
        // An empty cohort is a page, not an error, and it reports no successor.
        let (status, empty) = request(addr, "GET", &path, Some(&token), None).await;
        assert_eq!(status, 200, "{empty}");
        assert_eq!(empty["verb"], Value::String(verb.to_owned()));
        assert_eq!(empty["body"]["rows"], json!([]));
        assert_eq!(empty["body"]["next_cursor"], Value::Null);

        // The query string is translated into the surface body, so an HTTP
        // page and an in-process page are the same document.
        let (status, paged) = request(
            addr,
            "GET",
            &format!("{path}?limit=5&at_epoch=3"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, 200, "{paged}");
        let field = if verb.contains("saved_query") {
            "query_ref"
        } else {
            "campaign_ref"
        };
        let mut body = json!({ "limit": 5, "at_epoch": 3 });
        body[field] = Value::String(if field == "query_ref" {
            query.clone()
        } else {
            campaign.clone()
        });
        assert_eq!(paged, expect_call(&vault, principal, verb, body));

        // A limit above the engine's ceiling is clamped rather than refused.
        let (status, clamped) = request(
            addr,
            "GET",
            &format!(
                "{path}?limit={}",
                u64::from(MEMBERSHIP_PAGE_MAX_LIMIT) + 10_000
            ),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, 200, "{clamped}");

        // A malformed cursor is a typed rejection, not a silent page one.
        let (status, bad_cursor) = request(
            addr,
            "GET",
            &format!("{path}?cursor=nonsense"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, 400, "{bad_cursor}");

        // A non-hex resource id never reaches the vault.
        let malformed_path = path
            .replace(&campaign, "not-an-id")
            .replace(&query, "not-an-id");
        let (status, malformed) = request(addr, "GET", &malformed_path, Some(&token), None).await;
        assert_eq!(status, 400, "{malformed}");

        // Membership is a READ: a write-only credential does not reach it, and
        // the route never mutates.
        let before = vault_fingerprint(&vault);
        let (status, write_only) = request(
            addr,
            "GET",
            &path,
            Some(&token_for(principal, "core:write")),
            None,
        )
        .await;
        assert_eq!(status, 403, "{write_only}");
        let _ = request(addr, "GET", &path, Some(&token), None).await;
        assert_eq!(
            vault_fingerprint(&vault),
            before,
            "a membership read must not write anything"
        );
    }

    // The claim index is still empty: paging enrolled nobody.
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_CLAIM)
            .unwrap()
            .is_empty()
    );

    handle.abort();
}

// ---------------------------------------------------------------------------
// Error contract, server state, discovery, MCP catalog
// ---------------------------------------------------------------------------

/// Not-found, invalid payload, lifecycle conflict, and gate denial all land on
/// the existing API error contract rather than transport-specific semantics.
#[tokio::test]
async fn campaign_surface_error_parity() {
    let (_dir, vault, principal) = oracle_vault();
    let (addr, handle) = spawn_server(Arc::clone(&vault)).await;
    let token = owner_token(principal);
    let missing = seeded_id(0x70).to_hex();

    // NOT_FOUND: a write against an absent record.
    let (status, not_found) = request(
        addr,
        "PATCH",
        &format!("/campaigns/{missing}"),
        Some(&token),
        Some(&json!({ "expected_definition_version": 1, "name": "x" })),
    )
    .await;
    assert_eq!(status, 404, "{not_found}");
    assert_eq!(not_found["code"], "NOT_FOUND");
    assert_eq!(
        call(
            &vault,
            principal,
            "self.campaign.update",
            json!({ "campaign_ref": missing, "expected_definition_version": 1, "name": "x" })
        )
        .expect_err("must be not found")
        .code,
        oneiron::MEMORY_CODE_NOT_FOUND
    );

    // BAD_REQUEST: a payload the surface cannot parse.
    let (status, invalid) =
        request(addr, "POST", "/campaigns", Some(&token), Some(&json!({}))).await;
    assert_eq!(status, 400, "{invalid}");
    assert_eq!(invalid["code"], "BAD_REQUEST");
    let (status, blank) = request(
        addr,
        "POST",
        "/campaigns",
        Some(&token),
        Some(&json!({ "name": "   " })),
    )
    .await;
    assert_eq!(status, 400, "{blank}");

    // BAD_REQUEST: a malformed `scope`. An empty axis means UNRESTRICTED, so a
    // scope the surface cannot read must be refused rather than dropped — a
    // silently-widened query would target every world and facet.
    for malformed in [json!("sales"), json!(7), json!(["sales"])] {
        let mut widened = saved_query_body();
        widened["scope"] = malformed.clone();
        let (status, refused) =
            request(addr, "POST", "/saved-queries", Some(&token), Some(&widened)).await;
        assert_eq!(status, 400, "scope {malformed} was accepted: {refused}");
        assert_eq!(refused["code"], "BAD_REQUEST");
    }

    // INVALID_STATE: an archived record refuses a stale-version write, and the
    // surface never offers a hard delete to route around it.
    let created = expect_call(
        &vault,
        principal,
        "self.campaign.create",
        json!({ "name": "lifecycle" }),
    );
    let campaign_ref = record_ref(&created, "campaign_ref");
    let (status, archived) = request(
        addr,
        "POST",
        &format!("/campaigns/{campaign_ref}/archive"),
        Some(&token),
        Some(&json!({ "expected_definition_version": 1 })),
    )
    .await;
    assert_eq!(status, 200, "{archived}");
    let (status, replayed) = request(
        addr,
        "POST",
        &format!("/campaigns/{campaign_ref}/archive"),
        Some(&token),
        Some(&json!({ "expected_definition_version": 1 })),
    )
    .await;
    assert_eq!(status, 409, "{replayed}");
    assert_eq!(replayed["code"], "INVALID_STATE");
    let (status, deleted) = request(
        addr,
        "DELETE",
        &format!("/campaigns/{campaign_ref}"),
        Some(&token),
        None,
    )
    .await;
    assert_ne!(status, 200, "the surface exposes no hard delete: {deleted}");

    // FORBIDDEN: a credential whose principal the store never admitted.
    let (status, gated) = request(
        addr,
        "POST",
        "/campaigns",
        Some(&owner_token(seeded_id(0x71))),
        Some(&json!({ "name": "ghost" })),
    )
    .await;
    assert_eq!(status, 403, "{gated}");
    assert_eq!(gated["code"], "FORBIDDEN");

    // FORBIDDEN: an un-narrowed root secret owns no principal entity.
    let (status, rootless) = request(
        addr,
        "POST",
        "/campaigns",
        Some(SECRET),
        Some(&json!({ "name": "root" })),
    )
    .await;
    assert_eq!(status, 403, "{rootless}");

    // UNAUTHORIZED: no credential at all.
    let (status, anonymous) = request(
        addr,
        "GET",
        &format!("/campaigns/{campaign_ref}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, 401, "{anonymous}");

    // FORBIDDEN: a read-only token cannot write, and a write-only token cannot
    // read — the surface uses the existing core scopes, not new ones.
    let (status, scoped) = request(
        addr,
        "POST",
        "/campaigns",
        Some(&token_for(principal, "core:read")),
        Some(&json!({ "name": "read only" })),
    )
    .await;
    assert_eq!(status, 403, "{scoped}");

    handle.abort();
}

/// Discovery lists each `self.*` verb exactly once, derived from the engine's
/// closed list, with no Graph-FS prerequisite.
#[tokio::test]
async fn campaign_discovery_lists_self_verbs_once() {
    let (_dir, vault, _principal) = oracle_vault();
    let (addr, handle) = spawn_server(Arc::clone(&vault)).await;

    let (status, discovered) = request(addr, "GET", "/api/core/discover", Some(SECRET), None).await;
    assert_eq!(status, 200, "{discovered}");
    let capabilities: Vec<&str> = discovered["feature_flags"]["capabilities"]
        .as_array()
        .expect("discovery should advertise capabilities")
        .iter()
        .map(|token| token.as_str().expect("capability should be a string"))
        .collect();

    for verb in CAMPAIGN_SELF_VERBS {
        assert_eq!(
            capabilities.iter().filter(|token| *token == verb).count(),
            1,
            "{verb} must be advertised exactly once: {capabilities:?}"
        );
    }

    // The advertised set is the engine's closed list, not a hand-kept copy: no
    // `self.*` token exists that the dispatcher would refuse.
    for token in &capabilities {
        if token.starts_with("self.") {
            assert!(
                CampaignSurfaceVerb::parse(token).is_some(),
                "{token} is advertised but does not dispatch"
            );
        }
    }
    assert_eq!(
        capabilities
            .iter()
            .filter(|token| token.starts_with("self."))
            .count(),
        CAMPAIGN_SELF_VERBS.len()
    );

    // The MCP vocabulary advertised alongside them is the two REGISTERED
    // endpoints' tool sets, derived from the registrations `tools/list`
    // projects and `tools/call` resolves against, so every advertised name is
    // one its stated endpoint accepts.
    for mode in McpSurfaceMode::ALL {
        let surface = registered_surface(mode);
        assert!(
            !surface.tool_names().is_empty(),
            "the {} endpoint registers at least one tool",
            mode.as_str()
        );
        for name in surface.tool_names() {
            assert!(
                surface.resolve(name).is_some(),
                "{name} is advertised only because the {} endpoint accepts it",
                mode.as_str()
            );
            assert!(
                capabilities.contains(&format!("mcp.tool.{name}").as_str()),
                "discovery advertises the registered tool {name}"
            );
            let endpoint_token = format!("mcp.endpoint.{}.{name}", mode.as_str());
            assert!(
                capabilities.contains(&endpoint_token.as_str()),
                "discovery advertises {endpoint_token}"
            );
        }
    }

    // The batch's `oneiron.calendar` is part of the retired plain-verb catalog:
    // neither endpoint registers it, so discovery advertises none of those
    // seven names.
    for tool in McpToolName::all() {
        let retired = format!("mcp.tool.{}", tool.as_str());
        assert!(
            !capabilities.contains(&retired.as_str()),
            "{retired} is registered on no endpoint and must not be advertised"
        );
    }

    // The vault under test mounts no Graph-FS `/queries/` view, and every verb
    // is still advertised — discovery states no filesystem prerequisite.
    let body = serde_json::to_string(&discovered).unwrap();
    assert!(!body.contains("graph_fs"), "{body}");
    assert!(!body.contains("/queries/"), "{body}");

    // Health advertises the same vocabulary, from the same derivation.
    let (status, health) = request(addr, "GET", "/api/health", None, None).await;
    assert_eq!(status, 200, "{health}");
    assert_eq!(
        health["capabilities"]["capabilities"],
        discovered["feature_flags"]["capabilities"]
    );

    handle.abort();
}

/// CA-07 adds no MCP tool: the closed catalog keeps the batch-owned
/// `oneiron.calendar` and gains no campaign tool, op enum, or alias.
#[test]
fn campaign_adds_no_mcp_tool_name() {
    let names: Vec<&str> = McpToolName::all()
        .iter()
        .map(|tool| tool.as_str())
        .collect();
    assert!(
        names.contains(&"oneiron.calendar"),
        "the batch-owned calendar tool must stay in the catalog: {names:?}"
    );
    for name in &names {
        assert!(
            !name.contains("campaign") && !name.contains("saved_query"),
            "catalog grew a campaign tool: {name}"
        );
    }
    for absent in [
        "oneiron.campaign",
        "oneiron.saved_query",
        "oneiron.saved-queries",
    ] {
        assert!(
            McpToolName::from_name(absent).is_none(),
            "{absent} must not resolve to a tool"
        );
    }
    // No campaign operation discriminator either.
    for tool in McpToolName::all() {
        for op in tool.operations() {
            assert!(
                !op.contains("campaign") && !op.contains("saved_query"),
                "{} grew a campaign op: {op}",
                tool.as_str()
            );
        }
    }
}
