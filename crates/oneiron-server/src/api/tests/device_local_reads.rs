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
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json");
        if let Some((name, value)) = from.forwarded {
            request = request.header(name, value);
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
        .set_world_device_only(kept_world, true)
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
        for id in [kept, kept_world] {
            assert_eq!(
                rendered.contains(&id.to_hex()),
                on_device,
                "export from {from:?}"
            );
        }
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
        .set_world_device_only(kept_world, true)
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

/// Sol R1 F4: discovery counts the vault's rows, dates its last activity and
/// names its predicate namespaces. A caller off this device learns none of
/// that from a device-local world.
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
        .set_world_device_only(kept_world, true)
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
}
