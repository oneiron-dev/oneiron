//! DEC-0005: "Rows in a device-local world never leave the device that holds
//! the flag." A caller off this device reads none of them on any read door; a
//! caller on it (loopback here) still reads them all.

use super::*;
use axum::extract::ConnectInfo;
use oneiron::EntityId;
use serde_json::json;
use std::net::SocketAddr;

struct Caller {
    server: Arc<SyncServer>,
    slip: oneiron::authority::CapabilitySlip,
    key: ed25519_dalek::SigningKey,
}

impl Caller {
    /// One request from `peer`, as the listener records the connection.
    async fn call(
        &self,
        peer: SocketAddr,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .unwrap();
        let mut request = crate::test_credentials::bind_slip_request(
            &self.server,
            &self.slip,
            &self.key,
            request,
        );
        request.extensions_mut().insert(ConnectInfo(peer));
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

    /// The ids a query or pack answered with, under `field`.
    async fn ids(&self, peer: SocketAddr, uri: &str, field: &str) -> Vec<String> {
        let (status, body) = self
            .call(
                peer,
                "POST",
                uri,
                Some(json!({"query": "orchid", "limit": 10, "view": "full"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        body[field]
            .as_array()
            .unwrap_or_else(|| panic!("{uri} answers {field}: {body}"))
            .iter()
            .filter_map(|item| item["id"].as_str().map(str::to_owned))
            .collect()
    }
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

#[tokio::test]
async fn a_caller_off_this_device_reads_no_device_local_world() {
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let kept_world = put_world(&vault);
    let open_world = put_world(&vault);
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
    let (kept, open) = (EntityId::now(), EntityId::now());
    seed_world_claim(&server, kept, owner, kept_world);
    seed_world_claim(&server, open, owner, open_world);
    server
        .vault
        .batch()
        .text(&kept, &[("body", "orchid ledger kept")])
        .text(&open, &[("body", "orchid ledger open")])
        .commit()
        .unwrap();
    server.vault.set_indexed_idle_delay_ms(0).unwrap();
    server
        .vault
        .refresh_staged_indexed_at_idle(u64::MAX)
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
    let here: SocketAddr = "127.0.0.1:40100".parse().unwrap();
    let away: SocketAddr = "192.0.2.7:40100".parse().unwrap();

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

    for (peer, on_device) in [(here, true), (away, false)] {
        for (uri, field) in [
            ("/v1/core/query", "items"),
            ("/v1/core/context-pack", "results"),
        ] {
            let ids = caller.ids(peer, uri, field).await;
            assert!(ids.contains(&open.to_hex()), "{uri} from {peer}: {ids:?}");
            assert_eq!(
                ids.contains(&kept.to_hex()),
                on_device,
                "{uri} from {peer}: {ids:?}"
            );
        }
        let (status, body) = caller
            .call(
                peer,
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
                .call(peer, "GET", &format!("/api/entity/{}", id.to_hex()), None)
                .await;
            let expected = if on_device {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            };
            assert_eq!(status, expected, "/api/entity from {peer}: {body}");
        }
        let (status, export) = caller
            .call(
                peer,
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
                "export from {peer}"
            );
        }
    }

    // An erased claim keeps its world: its shell stays home too.
    assert!(server.vault.delete_entity(&kept).unwrap());
    for (peer, on_device) in [(here, true), (away, false)] {
        let (status, body) = caller
            .call(
                peer,
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
