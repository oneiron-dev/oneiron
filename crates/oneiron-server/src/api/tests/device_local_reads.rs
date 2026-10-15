//! DEC-0005: "Rows in a device-local world never leave the device that holds
//! the flag." A caller off this device reads none of them on any read door; a
//! caller on it (loopback here) still reads them all. A proxy forwarding
//! header places even a loopback caller off the device.

use super::*;
use axum::extract::ConnectInfo;
use oneiron::{ClaimApprovalStatus, EntityId};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Where a request comes from: the peer its connection reports, and the
/// proxy forwarding header it carries, if any.
#[derive(Clone, Copy, Debug)]
struct Origin {
    peer: SocketAddr,
    forwarded: Option<(&'static str, &'static str)>,
}

const HERE: Origin = Origin {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40100),
    forwarded: None,
};
const AWAY: Origin = Origin {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 40100),
    forwarded: None,
};

struct Caller {
    server: Arc<SyncServer>,
    slip: oneiron::authority::CapabilitySlip,
    key: ed25519_dalek::SigningKey,
}

impl Caller {
    /// One request from `from`, as the listener records the connection.
    async fn call(
        &self,
        from: Origin,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.call_keyed(from, method, uri, body, None).await
    }

    /// [`Caller::call`] under an `Idempotency-Key`, if `key` names one.
    async fn call_keyed(
        &self,
        from: Origin,
        method: &str,
        uri: &str,
        body: Option<Value>,
        key: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json");
        if let Some((name, value)) = from.forwarded {
            request = request.header(name, value);
        }
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key);
        }
        let request = request
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .unwrap();
        let mut request = crate::test_credentials::bind_slip_request(
            &self.server,
            &self.slip,
            &self.key,
            request,
        );
        request.extensions_mut().insert(ConnectInfo(from.peer));
        let response = crate::build_app(Arc::clone(&self.server))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// A query or pack's whole answer, so an id anywhere in it (a result, an
    /// L2 base, a neighbor) counts as read.
    async fn answer(&self, from: Origin, uri: &str) -> String {
        let (status, body) = self
            .call(
                from,
                "POST",
                uri,
                Some(json!({"query": "orchid", "limit": 10, "view": "full"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        body.to_string()
    }

    async fn discover(&self, from: Origin) -> Value {
        let (status, body) = self.call(from, "GET", "/api/core/discover", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// A server over a vault with its embedded owner, the owner's credential, and
/// `grower`, the PERSON the claims are about: claims about the owner go to a
/// pack's L2 base instead of its results.
fn serve() -> (tempfile::TempDir, Arc<SyncServer>, Caller, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let server = Arc::new(
        SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                auth_secret: Some("device-local".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let grower = EntityId::now();
    server
        .vault
        .put_entity(
            &grower,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"grower",
        )
        .unwrap();
    let (slip, key) = crate::test_credentials::credential(
        &server,
        &format!("principal_ref={};actor_class=human", owner.to_hex()),
    );
    let caller = Caller {
        server: Arc::clone(&server),
        slip,
        key,
    };
    (dir, server, caller, grower)
}

/// Brings the text index up to every claim written so far.
fn index(server: &SyncServer) {
    server.vault.set_indexed_idle_delay_ms(0).unwrap();
    server
        .vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
}

fn put_world(vault: &oneiron::Vault) -> EntityId {
    let world = EntityId::now();
    vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    world
}

/// A CLAIM about `subject` under its own `predicate`, in `world` (base reality
/// for `None`), whose text answers "orchid".
fn put_orchid_claim(
    server: &SyncServer,
    subject: EntityId,
    predicate: &str,
    world: Option<EntityId>,
    text: &str,
) -> EntityId {
    put_claim_as(
        server,
        subject,
        predicate,
        world,
        text,
        ClaimApprovalStatus::Auto,
        101,
    )
}

/// [`put_orchid_claim`] at `approval`, learned at `learned_at`.
fn put_claim_as(
    server: &SyncServer,
    subject: EntityId,
    predicate: &str,
    world: Option<EntityId>,
    text: &str,
    approval: ClaimApprovalStatus,
    learned_at: u64,
) -> EntityId {
    let id = EntityId::now();
    let mut body = oneiron::ClaimBody::new(
        predicate,
        oneiron::ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        0.8,
        approval,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = world;
    server
        .vault
        .put_claim(
            &id,
            &body,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            learned_at,
        )
        .unwrap();
    server
        .vault
        .batch()
        .text(&id, &[("body", text)])
        .commit()
        .unwrap();
    id
}

#[tokio::test]
async fn a_caller_off_this_device_reads_no_device_local_world() {
    let (_dir, server, caller, grower) = serve();
    let kept_world = put_world(&server.vault);
    // A pack gives a world's claims at most half its claim budget, so the
    // portable claim is base reality's.
    let kept = put_orchid_claim(
        &server,
        grower,
        "test.orchid_kept",
        Some(kept_world),
        "orchid ledger kept",
    );
    let open = put_orchid_claim(
        &server,
        grower,
        "test.orchid_open",
        None,
        "orchid ledger open",
    );
    index(&server);
    let (here, away) = (HERE, AWAY);
    // A proxy on this device that marks the traffic it forwards.
    let proxied = Origin {
        forwarded: Some(("x-forwarded-for", "192.0.2.7")),
        ..here
    };

    // A reference the caller learned while the world was still portable.
    let (status, pack) = caller
        .call(
            here,
            "POST",
            "/v1/core/context-pack",
            Some(json!({"query": "orchid", "limit": 10, "view": "full"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{pack}");
    let row = pack["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == kept.to_hex())
        .unwrap_or_else(|| panic!("the pack holds the world's claim: {pack}"));
    let kept_ref = format!(
        "{}:{}",
        row["short_id"].as_str().unwrap(),
        row["content_hash"].as_str().unwrap()
    );
    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            kept_world,
            true,
        )
        .unwrap();

    for (from, on_device) in [(here, true), (away, false), (proxied, false)] {
        for uri in ["/v1/core/query", "/v1/core/context-pack"] {
            let answer = caller.answer(from, uri).await;
            assert!(
                answer.contains(&open.to_hex()),
                "{uri} from {from:?}: {answer}"
            );
            assert_eq!(
                answer.contains(&kept.to_hex()),
                on_device,
                "{uri} from {from:?}: {answer}"
            );
        }
        let (status, body) = caller
            .call(
                from,
                "POST",
                "/v1/core/hydrate",
                Some(json!({"ref": kept_ref, "view": "full"})),
            )
            .await;
        if on_device {
            assert_eq!((status, &body["status"]), (StatusCode::OK, &json!("live")));
        } else {
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        }
        for id in [kept, kept_world] {
            let (status, body) = caller
                .call(from, "GET", &format!("/api/entity/{}", id.to_hex()), None)
                .await;
            let expected = if on_device {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            };
            assert_eq!(status, expected, "/api/entity from {from:?}: {body}");
        }
        let (status, export) = caller
            .call(
                from,
                "POST",
                "/v1/core/facade/export",
                Some(json!({"format": "json"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{export}");
        let rendered = export["rendered"].as_str().unwrap();
        assert!(rendered.contains(&open.to_hex()));
        assert_eq!(
            rendered.contains(&kept.to_hex()),
            on_device,
            "export from {from:?}"
        );
        // The world's own row stays here. Its settings are signed into the
        // authority log, which every machine holds, so its id may be named
        // there.
        assert_eq!(
            exported_ids(&serde_json::from_str(rendered).unwrap()).contains(&kept_world.to_hex()),
            on_device,
            "export from {from:?}"
        );
    }

    // An erased claim keeps its world: its shell stays home too.
    assert!(server.vault.delete_entity(&kept).unwrap());
    for (from, on_device) in [(here, true), (away, false), (proxied, false)] {
        let (status, body) = caller
            .call(
                from,
                "POST",
                "/v1/core/hydrate",
                Some(json!({"ref": kept_ref, "view": "full"})),
            )
            .await;
        if on_device {
            assert_eq!(
                (status, &body["status"]),
                (StatusCode::OK, &json!("deleted"))
            );
        } else {
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        }
    }
}

/// Every count of withheld rows an answer carries.
/// Every row id an export document carries, in any section.
fn exported_ids(document: &Value) -> std::collections::BTreeSet<String> {
    let mut ids = std::collections::BTreeSet::new();
    let mut pending = vec![document];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(fields) => {
                if let Some(Value::String(id)) = fields.get("id") {
                    ids.insert(id.clone());
                }
                pending.extend(fields.values());
            }
            Value::Array(items) => pending.extend(items),
            _ => {}
        }
    }
    ids
}

fn suppression_counts(body: &Value) -> Vec<u64> {
    ["/stats/claims_suppressed", "/narrowing/suppressed_count"]
        .into_iter()
        .filter_map(|pointer| body.pointer(pointer).and_then(Value::as_u64))
        .collect()
}

/// Sol R1 F3: retrieval counts a claim its status gate holds back before any
/// scoped read sees the row. A caller off this device gets no such count for
/// a device-local claim; a caller on it still does.
#[tokio::test]
async fn a_caller_off_this_device_counts_no_device_local_claim() {
    let (_dir, server, caller, grower) = serve();
    let kept_world = put_world(&server.vault);
    // Proposed claims: the status gate holds each one back.
    for (predicate, world, text) in [
        ("test.orchid_kept", Some(kept_world), "orchid ledger kept"),
        ("test.orchid_open", None, "orchid ledger open"),
    ] {
        put_claim_as(
            &server,
            grower,
            predicate,
            world,
            text,
            ClaimApprovalStatus::Proposed,
            101,
        );
    }
    put_orchid_claim(
        &server,
        grower,
        "test.orchid_shown",
        None,
        "orchid ledger shown",
    );
    index(&server);
    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            kept_world,
            true,
        )
        .unwrap();

    for uri in ["/v1/core/query", "/v1/core/context-pack"] {
        let here: Value = serde_json::from_str(&caller.answer(HERE, uri).await).unwrap();
        let away: Value = serde_json::from_str(&caller.answer(AWAY, uri).await).unwrap();
        let (here, away) = (suppression_counts(&here), suppression_counts(&away));
        assert!(!away.is_empty(), "{uri}: no count");
        // The portable proposal still counts off this device.
        assert!(away.iter().all(|count| *count >= 1), "{uri}: {away:?}");
        assert_eq!(
            here.iter().map(|count| count - 1).collect::<Vec<_>>(),
            away,
            "{uri}: here {here:?}"
        );
    }
}

/// Sol R1 F4 and R2 F4: discovery and a board's session prefix count the
/// vault's rows and date its last activity, and discovery names its predicate
/// namespaces. A caller off this device learns none of that from a
/// device-local world.
#[tokio::test]
async fn discovery_off_this_device_counts_no_device_local_row() {
    let (_dir, server, caller, grower) = serve();
    let kept_world = put_world(&server.vault);
    // The newest row in the vault.
    let latest = 4_000_000_000;
    put_claim_as(
        &server,
        grower,
        "keptspace.orchid",
        Some(kept_world),
        "orchid ledger kept",
        ClaimApprovalStatus::Auto,
        latest,
    );
    put_orchid_claim(
        &server,
        grower,
        "openspace.orchid",
        None,
        "orchid ledger open",
    );
    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            kept_world,
            true,
        )
        .unwrap();

    let (here, away) = (caller.discover(HERE).await, caller.discover(AWAY).await);
    let count = |body: &Value, kind: u8| body["counts"][kind.to_string()].as_u64().unwrap_or(0);
    for kind in [
        oneiron::registry::ENTITY_TYPE_CLAIM,
        oneiron::registry::ENTITY_TYPE_WORLD,
    ] {
        assert_eq!(count(&here, kind), count(&away, kind) + 1, "type {kind}");
    }
    let namespaces = |body: &Value| body["predicate_namespaces"].to_string();
    assert!(namespaces(&here).contains("keptspace"), "{here}");
    assert!(!namespaces(&away).contains("keptspace"), "{away}");
    assert!(namespaces(&away).contains("openspace"), "{away}");
    assert_eq!(here["last_activity"], json!(latest));
    assert!(away["last_activity"].as_u64().unwrap() < latest, "{away}");

    let board = |from| {
        let caller = &caller;
        async move {
            let (status, body) = caller
                .call(from, "POST", "/v1/core/context-board", Some(json!({})))
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["session"].clone()
        }
    };
    // A board counts and dates nothing for any key (F16), here or away.
    let (here, away) = (board(HERE).await, board(AWAY).await);
    assert_eq!(here, away);
    assert_eq!(here["counts"], json!({}), "{here}");
    assert!(here["last_activity"].is_null(), "{here}");
}

/// Sol R2 F2 and F7: a pack off this device for a query only a device-local
/// claim answers reads as a pack for a query nothing answers: no candidate
/// of a device-local world enters the retrieval, so no empty reason, hint or
/// clamp count betrays one.
#[tokio::test]
async fn a_pack_off_this_device_reads_a_device_local_match_as_no_match() {
    let (_dir, server, caller, grower) = serve();
    let kept_world = put_world(&server.vault);
    put_claim_as(
        &server,
        grower,
        "test.marigold",
        Some(kept_world),
        "marigold ledger",
        ClaimApprovalStatus::Auto,
        101,
    );
    index(&server);
    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            kept_world,
            true,
        )
        .unwrap();

    let empty = |query: &'static str| {
        let caller = &caller;
        async move {
            let (status, body) = caller
                .call(
                    AWAY,
                    "POST",
                    "/v1/core/context-pack",
                    Some(json!({"query": query, "limit": 10, "view": "full"})),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["results"], json!([]), "{body}");
            (
                body["empty"]["reason"].clone(),
                body["empty"]["hint"].clone(),
                body["stats"]["claims_suppressed"].clone(),
                body["narrowing"]["suppressed_count"].clone(),
            )
        }
    };
    assert_eq!(empty("marigold").await, empty("zinnia").await);
}

/// Sol R2 F6: a keyed board retry replays its first success. A board that
/// told a session off this device how a claim it was served changed goes out
/// again on this device, but not off it once the claim's world is
/// device-local, though no document of the board names the claim.
#[tokio::test]
async fn a_keyed_board_retry_off_this_device_replays_no_device_local_row() {
    let (_dir, server, caller, grower) = serve();
    let world = put_world(&server.vault);
    let claim = put_orchid_claim(
        &server,
        grower,
        "test.orchid_retried",
        Some(world),
        "orchid ledger retried",
    );
    index(&server);
    let (status, read) = caller
        .call(
            AWAY,
            "POST",
            "/v1/core/query",
            Some(json!({"query": "orchid", "view": "standard", "session_id": "kept"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["items"][0]["id"], claim.to_hex(), "{read}");
    server.vault.retract_claim(&claim, 200).unwrap();
    let owner = server.vault.ensure_embedded_owner_actor().unwrap();
    let turn = EntityId::now();
    let author = rmp_serde::to_vec_named(&json!({ "actor": owner.to_hex() })).unwrap();
    server
        .vault
        .put_entity(
            &turn,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            &author,
        )
        .unwrap();
    let board = json!({"session": {"session_id": "kept"}, "turn": {"id": turn.to_hex()}});
    let keyed = |from| {
        let (caller, board) = (&caller, board.clone());
        async move {
            caller
                .call_keyed(
                    from,
                    "POST",
                    "/v1/core/context-board",
                    Some(board),
                    Some("kept-board"),
                )
                .await
        }
    };

    let (status, first) = keyed(AWAY).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(
        first["changed"][1],
        json!(format!("{}: retracted", claim.to_hex())),
        "{first}"
    );
    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let (status, refused) = keyed(AWAY).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert!(
        refused.to_string().contains("board_document_unreadable"),
        "{refused}"
    );
    let (status, replayed) = keyed(HERE).await;
    assert_eq!(status, StatusCode::OK, "{replayed}");
    assert_eq!(replayed, first);
}

/// Sol R5 F3: a keyed write replays its first success to a retry. Once the
/// claim its answer names is device-local, the replay goes out again on this
/// device but not off it, and the write is not repeated.
#[tokio::test]
async fn a_keyed_write_retried_off_this_device_replays_no_device_local_row() {
    let (_dir, server, caller, grower) = serve();
    let world = put_world(&server.vault);
    let claim = put_orchid_claim(
        &server,
        grower,
        "test.orchid_keyed",
        Some(world),
        "orchid ledger keyed",
    );
    // A keyed route: the facade's verbs carry no idempotency layer.
    let keyed = |from| {
        let caller = &caller;
        async move {
            caller
                .call_keyed(
                    from,
                    "POST",
                    "/v1/core/memory/verbs/retract",
                    Some(json!({"id": claim.to_hex()})),
                    Some("kept-claim"),
                )
                .await
        }
    };
    let (status, first) = keyed(HERE).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["id"], claim.to_hex(), "{first}");

    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let (status, refused) = keyed(AWAY).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert!(!refused.to_string().contains(&claim.to_hex()), "{refused}");
    let (status, replayed) = keyed(HERE).await;
    assert_eq!(status, StatusCode::OK, "{replayed}");
    assert_eq!(replayed, first);
}

/// Sol R2 F3 and R3 F3: a setup page is continued from the board it
/// retained, which told its connector, off this device, how a claim it was
/// served changed. Once the claim's world is device-local the cursor is
/// refused, never answered from that board: whether the flag was committed
/// before the continuation, or while it was under way.
#[tokio::test]
async fn a_setup_page_off_this_device_continues_no_board_naming_a_device_local_row() {
    let (_dir, server) = test_server_with_config(crate::config::SyncServerConfig {
        auth_secret: Some("device-local".into()),
        ..Default::default()
    });
    let actor = EntityId::now();
    for credential in ["kept-before", "kept-during"] {
        register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    }
    let world = put_world(&server.vault);
    let claim = put_orchid_claim(
        &server,
        actor,
        "test.orchid_paged",
        Some(world),
        "orchid ledger paged",
    );
    index(&server);
    let call = |credential: &'static str, path: &'static str, tool: &'static str, arguments| {
        let server = Arc::clone(&server);
        async move {
            let arguments = mcp_merge_args(mcp_endpoint_envelope(actor, "read_board"), arguments);
            let (status, body) = route_json(
                server,
                mcp_endpoint_call_request(path, credential, tool, tool, arguments),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }
    };
    // Two connectors each read the claim, and once it is retracted each
    // takes the first setup page, which reports it.
    let mut cursors = Vec::new();
    for credential in ["kept-before", "kept-during"] {
        let read = call(
            credential,
            MCP_TOOL_FIRST_PATH,
            "memory.query",
            json!({"arguments": {"request": {"query": "orchid", "view": "standard"}}}),
        )
        .await;
        assert_eq!(
            read["result"]["structuredContent"]["output"]["response"]["items"][0]["id"],
            claim.to_hex(),
            "{read}"
        );
    }
    server.vault.retract_claim(&claim, 200).unwrap();
    for credential in ["kept-before", "kept-during"] {
        let first = call(
            credential,
            "/mcp",
            "setup_oneiron",
            json!({"page": {"limit": 1}}),
        )
        .await;
        let first = &first["result"]["structuredContent"];
        assert!(
            first
                .to_string()
                .contains(&format!("{}: retracted", claim.to_hex())),
            "{first}"
        );
        cursors.push(first["meta"]["page"]["cursor"].as_str().unwrap().to_owned());
    }

    // Flagged while the second continuation is under way, past its cursor
    // check; the first continues once the flag is in.
    crate::api::mcp_gateway::release_hook::arm(world);
    for (credential, cursor) in ["kept-during", "kept-before"]
        .into_iter()
        .zip(cursors.into_iter().rev())
    {
        let refused = call(
            credential,
            "/mcp",
            "setup_oneiron",
            json!({"page": {"limit": 1, "cursor": cursor}}),
        )
        .await;
        assert!(refused.get("result").is_none(), "{credential}: {refused}");
        assert_mcp_structured_error(&refused, "mcp_page_cursor_invalid");
    }
}

/// A TASK sits in the world it was born in. Once that world is device-local,
/// no setup board or TASKS section off this device lists it, counts it or
/// reads less healthy for it (Sol R4 F3), and a continuation of a board that
/// listed it is refused. Clearing the flag lists it again.
#[tokio::test]
async fn a_task_born_in_a_device_local_world_reaches_no_board_off_this_device() {
    let (_dir, server) = test_server_with_config(crate::config::SyncServerConfig {
        auth_secret: Some("device-local".into()),
        ..Default::default()
    });
    let actor = EntityId::now();
    let world = put_world(&server.vault);
    register_mcp_actor(&server, "errand", actor, oneiron::EdgeActorClass::Human).await;
    let call = |path: &'static str, tool: &'static str, arguments: Value| {
        let server = Arc::clone(&server);
        async move {
            let arguments = mcp_merge_args(mcp_endpoint_envelope(actor, "read_board"), arguments);
            let (status, body) = route_json(
                server,
                mcp_endpoint_call_request(path, "errand", tool, tool, arguments),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }
    };
    let setup = |page: Value| call("/mcp", "setup_oneiron", page);
    let describe = || call(MCP_TOOL_FIRST_PATH, "describe", json!({"arguments": {}}));
    // What a reader learns of the TASKS section, beside its rows: its page
    // and its health.
    let shape = |reply: &Value| {
        let meta = &reply["result"]["structuredContent"]["meta"];
        (meta["page"].clone(), meta["retrieval_health"].clone())
    };
    let before = (shape(&setup(json!({})).await), shape(&describe().await));
    let task = server
        .vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .with_birth_position(oneiron::federation::record_scope::BirthPosition {
            world: Some(world),
            facet: None,
        })
        .tasks_create(&oneiron::task_verb::TaskCreateSpec::new(
            rmpv::Value::from("orchid errand"),
            None,
            None,
            None,
        ))
        .unwrap()
        .task_ref
        .unwrap()
        .to_hex();
    let first = setup(json!({"page": {"limit": 1}})).await;
    assert!(first["result"].to_string().contains(&task), "{first}");
    assert!(describe().await["result"].to_string().contains(&task));
    let cursor = first["result"]["structuredContent"]["meta"]["page"]["cursor"]
        .as_str()
        .unwrap()
        .to_owned();

    // Neither its row nor a count or health of a withheld row is left.
    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let refused = setup(json!({"page": {"limit": 1, "cursor": cursor}})).await;
    assert!(refused.get("result").is_none(), "{refused}");
    assert_mcp_structured_error(&refused, "mcp_page_cursor_invalid");
    let (fresh, described) = (setup(json!({})).await, describe().await);
    for reply in [&fresh, &described] {
        assert!(!reply.to_string().contains(&task), "{reply}");
    }
    assert_eq!((shape(&fresh), shape(&described)), before);

    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            false,
        )
        .unwrap();
    let back = setup(json!({})).await;
    assert!(back["result"].to_string().contains(&task), "{back}");
}

/// Sol R4 F4 and F7, R5 F1: an ask's calibration pairs are derived from its answer,
/// the unit that answer binds, and each outcome fact and what the fact is
/// about. Once one of those rows is device-local, no read off this device
/// forms the pair, and a continuation of a page that held one is refused,
/// though no pair spells the row. On this device the pairs still read.
#[tokio::test]
async fn outcomes_off_this_device_pair_no_device_local_row() {
    let (_dir, server) = test_server_with_config(crate::config::SyncServerConfig {
        auth_secret: Some("device-local".into()),
        ..Default::default()
    });
    let (owner, holder) = (EntityId::now(), EntityId::now());
    for (credential, actor) in [("outcomes", owner), ("holder", holder)] {
        register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    }
    let world = put_world(&server.vault);
    // The holder's answer binds the holder; the outcomes are about a claim
    // in W it is linked to.
    let about = put_orchid_claim(
        &server,
        holder,
        "test.orchid_outcome",
        Some(world),
        "orchid",
    );
    server
        .vault
        .put_edge(&holder, oneiron::EdgeKind::About, &about, 1.0)
        .unwrap();
    let (handle, answered) =
        oneiron::test_support::settle_outcome_ask(&server.vault, owner, holder, Some("about"))
            .unwrap();
    for offset in [30, 31] {
        let at = answered + offset;
        let body = oneiron::ClaimBody::new(
            "outcome.earned",
            oneiron::ClaimSubject::Entity(about),
            rmpv::Value::from("won"),
            1.0,
            ClaimApprovalStatus::Approved,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        let occurred = oneiron::TimeRange { start: at, end: at };
        server
            .vault
            .put_claim(&EntityId::now(), &body, occurred, at)
            .unwrap();
    }
    let here = server.vault.memory(owner, oneiron::EdgeActorClass::Human);
    assert_eq!(here.tasks_ask_outcomes(&handle).unwrap().len(), 2);
    let outcomes = |page: Value| {
        let server = Arc::clone(&server);
        async move {
            let arguments = mcp_merge_args(
                mcp_endpoint_envelope(owner, "read_board"),
                json!({"arguments": {"spec": {"group_ref": handle.group_ref.to_hex()}}, "page": page}),
            );
            let (status, body) = route_json(
                server,
                mcp_endpoint_call_request(
                    MCP_TOOL_FIRST_PATH,
                    "outcomes",
                    "tasks.outcomes",
                    "tasks.outcomes",
                    arguments,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }
    };
    let first = outcomes(json!({"limit": 1})).await;
    let page = &first["result"]["structuredContent"];
    assert_eq!(page["output"].as_array().map(Vec::len), Some(1), "{first}");
    assert!(!page.to_string().contains(&about.to_hex()), "{first}");
    let cursor = page["meta"]["page"]["cursor"].as_str().unwrap().to_owned();

    // Flagged while a fresh read waits after deriving its pairs (Sol R5 F1).
    crate::api::mcp_gateway::release_hook::arm(world);
    let changed = outcomes(json!({})).await;
    assert!(changed.get("result").is_none(), "{changed}");
    assert_mcp_structured_error(&changed, "mcp_result_changed");
    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let refused = outcomes(json!({"limit": 1, "cursor": cursor})).await;
    assert!(refused.get("result").is_none(), "{refused}");
    assert_mcp_structured_error(&refused, "mcp_page_cursor_invalid");
    let fresh = outcomes(json!({})).await;
    assert_eq!(
        fresh["result"]["structuredContent"]["output"],
        json!([]),
        "{fresh}"
    );
    assert_eq!(here.tasks_ask_outcomes(&handle).unwrap().len(), 2);
}

/// Astra F3: a direct `claim_upsert` receipt names the claim it wrote by
/// short ref alone, and that claim is the receipt's producer. Flagged after
/// the write and before the result is released, the claim's world keeps the
/// receipt on this device: the caller reads that its result changed. While
/// the world is portable the receipt goes out. Astra F1 on the direct tool
/// path: a verb's refusal naming that claim's ref then leaves off this device
/// as its code alone.
#[tokio::test]
async fn a_claim_receipt_off_this_device_names_no_claim_its_world_made_device_local() {
    let (_dir, server) = test_server_with_config(crate::config::SyncServerConfig {
        auth_secret: Some("device-local".into()),
        ..Default::default()
    });
    let actor = EntityId::now();
    register_mcp_actor(&server, "receipts", actor, oneiron::EdgeActorClass::Human).await;
    let world = put_world(&server.vault);
    let subject = EntityId::now();
    server
        .vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .unwrap();
    let upsert = |predicate: &str, id: Option<&str>| {
        let server = Arc::clone(&server);
        let arguments = mcp_merge_args(
            mcp_endpoint_envelope(actor, "write_memory"),
            json!({"arguments": {"spec": {
                "id": id,
                "predicate": predicate,
                "subject_ref": subject.to_hex(),
                "value": "orchid",
                "confidence": 1.0,
                "source": "user_stated",
                "world_ref": world.to_hex(),
            }}}),
        );
        async move {
            let request = mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                "receipts",
                "claim_upsert",
                "claim_upsert",
                arguments,
            );
            route_json(server, request).await.1
        }
    };
    let portable = upsert("test.orchid_portable", None).await;
    let reference = portable["result"]["structuredContent"]["output"]["claim_short_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{portable}"))
        .to_owned();
    assert!(
        oneiron::entity_id::parse_short_ref_syntax(&reference).is_ok(),
        "{portable}"
    );

    crate::api::mcp_gateway::release_hook::arm(world);
    let changed = upsert("test.orchid_kept", None).await;
    assert!(changed.get("result").is_none(), "{changed}");
    assert_mcp_structured_error(&changed, "mcp_result_changed");
    assert!(!changed.to_string().contains("claim_short_id"), "{changed}");

    let refused = upsert("test.orchid_echo", Some(&reference)).await;
    assert!(refused.get("result").is_none(), "{refused}");
    assert_mcp_structured_error(&refused, "facade_error");
    assert!(!refused.to_string().contains(&reference), "{refused}");
}

/// Sol R7 F1: a refusal states the scope its credential resolved to. Once
/// that scope's world is device-local, a refusal off this device states no
/// scope and names no world: it leaves as its code alone. While the world is
/// portable the refusal states its scope.
#[tokio::test]
async fn a_refusal_off_this_device_states_no_scope_a_device_local_world_narrows() {
    let (_dir, server) = test_server_with_config(crate::config::SyncServerConfig {
        auth_secret: Some("device-local".into()),
        ..Default::default()
    });
    let world = put_world(&server.vault);
    let actor = EntityId::now();
    let scope = crate::mcp::McpConnectorScope::scoped(Some(world), None);
    register_scoped_mcp_actor(&server, "narrowed", actor, scope.clone()).await;
    let subscribe = || {
        mcp_refusal(
            &server,
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                "narrowed",
                "narrowed-subscribe",
                "board.subscribe",
                mcp_merge_args(
                    mcp_scoped_envelope(actor, "read_board", &scope),
                    json!({"arguments": {"scopes": ["memories"]}}),
                ),
            ),
        )
    };
    let portable = subscribe().await;
    assert_mcp_structured_error(&portable, "mcp_scope_refused");
    assert_eq!(
        portable["error"]["data"]["effective_scope"]["world_ref"],
        json!(world.to_hex()),
        "{portable}"
    );

    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let kept = subscribe().await;
    assert!(
        kept["error"]["data"].get("effective_scope").is_none(),
        "{kept}"
    );
    assert!(!kept.to_string().contains(&world.to_hex()), "{kept}");
}

/// Wonder R8 F5: `initialize` states the scope its credential resolved to.
/// Once that scope's world is device-local, an `initialize` off this device
/// is refused and names no world. While the world is portable it states its
/// scope.
#[tokio::test]
async fn an_initialize_off_this_device_states_no_scope_a_device_local_world_narrows() {
    let (_dir, server) = test_server_with_config(crate::config::SyncServerConfig {
        auth_secret: Some("device-local".into()),
        ..Default::default()
    });
    let world = put_world(&server.vault);
    let actor = EntityId::now();
    let scope = crate::mcp::McpConnectorScope::scoped(Some(world), None);
    register_scoped_mcp_actor(&server, "narrowed", actor, scope).await;
    let initialize = || {
        let request = mcp_endpoint_request(
            "/mcp",
            "narrowed",
            json!({"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {}}),
        );
        route_json(Arc::clone(&server), request)
    };
    let (_, portable) = initialize().await;
    assert_eq!(
        portable["result"]["actor"]["scope"]["world_ref"],
        json!(world.to_hex()),
        "{portable}"
    );

    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let (_, kept) = initialize().await;
    assert!(kept.get("result").is_none(), "{kept}");
    assert_mcp_structured_error(&kept, "mcp_result_changed");
    assert!(!kept.to_string().contains(&world.to_hex()), "{kept}");
}

/// Sol R7 F2: a cancel receipt does not name the TASK it cancelled, yet it is
/// derived from that TASK. Flagged after the cancel and before the receipt is
/// released, the TASK's world keeps the receipt on this device: the caller
/// reads that its result changed. While the world is portable the receipt
/// goes out.
#[tokio::test]
async fn a_cancel_receipt_off_this_device_is_released_by_the_task_it_cancelled() {
    let (_dir, server) = test_server_with_config(crate::config::SyncServerConfig {
        auth_secret: Some("device-local".into()),
        ..Default::default()
    });
    let actor = EntityId::now();
    register_mcp_actor(&server, "cancels", actor, oneiron::EdgeActorClass::Human).await;
    let world = put_world(&server.vault);
    let task = || {
        server
            .vault
            .memory(actor, oneiron::EdgeActorClass::Human)
            .with_birth_position(oneiron::federation::record_scope::BirthPosition {
                world: Some(world),
                facet: None,
            })
            .tasks_create(&oneiron::task_verb::TaskCreateSpec::new(
                rmpv::Value::from("orchid errand"),
                None,
                None,
                None,
            ))
            .unwrap()
            .task_ref
            .unwrap()
    };
    let cancel = |task: EntityId| {
        let server = Arc::clone(&server);
        let arguments = mcp_merge_args(
            mcp_endpoint_envelope(actor, "write_tasks"),
            json!({"arguments": {"task_ref": task.to_hex()}}),
        );
        async move {
            let request = mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                "cancels",
                "cancel",
                "cancel",
                arguments,
            );
            route_json(server, request).await.1
        }
    };
    let portable = cancel(task()).await;
    assert!(
        portable["result"]["structuredContent"]["output"].is_object(),
        "{portable}"
    );

    let kept = task();
    crate::api::mcp_gateway::release_hook::arm(world);
    let changed = cancel(kept).await;
    assert!(changed.get("result").is_none(), "{changed}");
    assert_mcp_structured_error(&changed, "mcp_result_changed");
}

/// Sol R8 F6: under an estimate a native query reads one row past its page
/// and counts it, so that row is a producer of the result though the page
/// leaves it out. Flagged after the read and before the result is released,
/// its world keeps the result on this device: the caller reads that its
/// result changed. While the world is portable the page and its count go out.
#[tokio::test]
async fn a_query_off_this_device_is_released_by_the_row_it_counts_past_its_page() {
    let (_dir, server) = test_server_with_config(crate::config::SyncServerConfig {
        auth_secret: Some("device-local".into()),
        ..Default::default()
    });
    let actor = EntityId::now();
    register_mcp_actor(&server, "counts", actor, oneiron::EdgeActorClass::Human).await;
    let world = put_world(&server.vault);
    let shown = put_orchid_claim(
        &server,
        actor,
        "test.orchid_shown",
        None,
        "orchid orchid orchid",
    );
    put_orchid_claim(
        &server,
        actor,
        "test.orchid_counted",
        Some(world),
        "orchid ledger counted past the page",
    );
    index(&server);
    let query = || {
        let server = Arc::clone(&server);
        let arguments = mcp_merge_args(
            mcp_endpoint_envelope(actor, "read_board"),
            json!({"arguments": {"request": {
                "query": "orchid",
                "limit": 1,
                "countMode": "estimate",
            }}}),
        );
        async move {
            let request = mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                "counts",
                "counts",
                "memory.query",
                arguments,
            );
            route_json(server, request).await.1
        }
    };
    let portable = query().await;
    let response = &portable["result"]["structuredContent"]["output"]["response"];
    assert_eq!(response["items"][0]["id"], shown.to_hex(), "{portable}");
    assert_eq!(response["meta"]["total"], 2, "{portable}");

    crate::api::mcp_gateway::release_hook::arm(world);
    let changed = query().await;
    assert!(changed.get("result").is_none(), "{changed}");
    assert_mcp_structured_error(&changed, "mcp_result_changed");
}

/// Sol R3 F5: an agent's standing block is pinned to one world. Once that
/// world is device-local, a board off this device takes no block of it: the
/// agent reads as one with no standing block, and the world is never named.
#[tokio::test]
async fn a_board_off_this_device_opens_no_standing_block_of_a_device_local_world() {
    let (_dir, server) = test_server_with_config(crate::config::SyncServerConfig {
        auth_secret: Some("device-local".into()),
        ..Default::default()
    });
    let world = put_world(&server.vault);
    let owner_ref = server.vault.ensure_embedded_owner_actor().unwrap();
    let owner = server
        .vault
        .authenticate_owner(
            owner_ref,
            &owner_ref.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let [pinned, bare] = [EntityId::now(), EntityId::now()];
    for agent in [pinned, bare] {
        server
            .vault
            .put_entity(
                &agent,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"agent",
            )
            .unwrap();
    }
    server
        .vault
        .open_standing_block(&owner, pinned, world, "identity", 64)
        .unwrap();
    let board = |agent: EntityId| {
        let server = Arc::clone(&server);
        async move {
            route_json(
                server,
                core_request_with_authz(
                    "POST",
                    "/v1/core/context-board",
                    test_bearer(&format!(
                        "scope=core:read;principal_ref={};actor_class=agent",
                        agent.to_hex()
                    )),
                    Some(&json!({"standing": {"token_budget": 65_536}})),
                ),
            )
            .await
        }
    };
    let (status, open) = board(pinned).await;
    assert_eq!(status, StatusCode::OK, "{open}");
    assert_eq!(open["standing"]["world_ref"], world.to_hex(), "{open}");

    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let (status, kept) = board(pinned).await;
    assert!(!kept.to_string().contains(&world.to_hex()), "{kept}");
    let (bare_status, bare_body) = board(bare).await;
    assert_eq!(status, bare_status, "{kept} / {bare_body}");
    assert_eq!(kept["error"]["code"], bare_body["error"]["code"]);
}

/// Sol R3 F7: an owner's persona card is compiled from the claims about its
/// person. Off this device none a device-local world keeps enters it: the
/// preview and the export it consents to name neither the claim nor its text.
#[tokio::test]
async fn a_persona_card_off_this_device_holds_no_device_local_claim() {
    use super::owner_routes::{call, owner_recipe, person};
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let subject = person(&server, b"Ada");
    let world = put_world(&server.vault);
    let mut claims = Vec::new();
    for (predicate, text, world) in [
        ("profile.name", "Ada Lovelace", None),
        ("profile.hobby", "grows orchids at night", Some(world)),
    ] {
        let mut body = oneiron::ClaimBody::new(
            predicate,
            oneiron::ClaimSubject::Entity(subject),
            rmpv::Value::from(text),
            0.9,
            ClaimApprovalStatus::Approved,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.salience = Some(0.9);
        body.source = Some(oneiron::ClaimSource::UserStated);
        body.world = world;
        let id = EntityId::now();
        server
            .vault
            .put_claim(&id, &body, oneiron::TimeRange { start: 10, end: 10 }, 10)
            .unwrap();
        claims.push(id);
    }
    let kept = claims[1].to_hex();
    let path = format!("/v1/owner/persona?subject={}", subject.to_hex());
    let (status, preview) = call(&server, "GET", &path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert!(preview.to_string().contains("orchids"), "{preview}");

    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let (status, preview) = call(&server, "GET", &path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert!(preview.to_string().contains("Lovelace"), "{preview}");
    for withheld in ["orchids", kept.as_str()] {
        assert!(!preview.to_string().contains(withheld), "{preview}");
    }
    let request = json!({ "subject": subject.to_hex(), "stamp": preview["stamp"], "strike": [] });
    let (status, exported) = call(
        &server,
        "POST",
        "/v1/owner/persona/export",
        owner,
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{exported}");
    for withheld in ["orchids", kept.as_str()] {
        assert!(!exported.to_string().contains(withheld), "{exported}");
    }
}

/// Sol R3 F8: an agent run's waiting proposals are reviewed and resolved as
/// one bundle. Off this device a run holding a proposal a device-local world
/// keeps is no run of the owner's: it is not listed, and review and approval
/// answer as for a run that does not exist.
#[tokio::test]
async fn a_run_off_this_device_holding_a_device_local_proposal_reads_as_no_run() {
    use super::owner_routes::{call, owner_recipe};
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let world = put_world(&server.vault);
    let run = "device-local-run";
    let kept = server
        .vault
        .park_run_proposal_in_world_for_test(
            run,
            EntityId::now(),
            EntityId::now(),
            world,
            "orchid keeper",
        )
        .unwrap()
        .to_hex();
    let review_path = format!("/v1/owner/runs/review?run_id={run}");
    let (status, review) = call(&server, "GET", &review_path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    let decide = json!({ "run_id": run, "bundle_id": review["bundle_id"] });

    server
        .vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let (status, pending) = call(&server, "GET", "/v1/owner/runs", owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending, json!([]));
    let unknown = "/v1/owner/runs/review?run_id=no-such-run";
    let (absent, absent_body) = call(&server, "GET", unknown, owner.clone(), None).await;
    let (status, review) = call(&server, "GET", &review_path, owner.clone(), None).await;
    assert_eq!(status, absent, "{review} / {absent_body}");
    assert!(!review.to_string().contains(&kept), "{review}");
    let (status, approved) = call(
        &server,
        "POST",
        "/v1/owner/runs/approve",
        owner,
        Some(&decide),
    )
    .await;
    assert_eq!(status, absent, "{approved}");
    assert!(!approved.to_string().contains(&kept), "{approved}");
    assert_eq!(
        server
            .vault
            .get_claim(&EntityId::from_hex(&kept).unwrap())
            .unwrap()
            .unwrap()
            .approval,
        ClaimApprovalStatus::Proposed
    );
}
