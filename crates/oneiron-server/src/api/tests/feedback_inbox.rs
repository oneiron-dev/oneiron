//! The open feedback inbox (ARCH-0056 #open-inbox, owner ruling 2026-10-16):
//! "if someone has an issue with oneiron or any feedback, it should be as
//! easy as possible to let us know". A GET link or a POST lands one note
//! with no key; past the flood cap a sender is shed, typed; a vault's own
//! send still waits for its owner (OF-420).

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use oneiron::feedback::{FeedbackCategory, FeedbackInboxNote, FeedbackInboxVia};

use super::owner_routes::{call, owner_recipe};
use super::owner_surfaces::{feedback_server, grant_feedback_sends};
use super::*;
use crate::config::FeedbackInboxConfig;

/// A server with its open inbox on, behind a host secret: no request here
/// holds a key.
fn inbox_server(notes_per_sender: u32) -> (tempfile::TempDir, Arc<SyncServer>) {
    test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        feedback_inbox: FeedbackInboxConfig {
            enabled: true,
            notes_per_sender,
            ..FeedbackInboxConfig::default()
        },
        ..Default::default()
    })
}

/// One keyless request from `peer`, through the app as `serve` mounts it.
async fn keyless(
    server: &Arc<SyncServer>,
    peer: &str,
    request: axum::http::request::Builder,
    body: &str,
) -> (StatusCode, HeaderMap, Value) {
    let peer: IpAddr = peer.parse().unwrap();
    let request = request
        .extension(ConnectInfo(SocketAddr::new(peer, 40_000)))
        .body(Body::from(body.to_owned()))
        .unwrap();
    let response = crate::build_app(server.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn link(query: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("GET")
        .uri(format!("/v1/feedback?{query}"))
}

fn post(content_type: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("POST")
        .uri("/v1/feedback")
        .header(CONTENT_TYPE, content_type)
}

fn notes(server: &SyncServer) -> Vec<FeedbackInboxNote> {
    server.vault().feedback_inbox(None, 1_000).unwrap()
}

/// Done-means: a plain GET link lands one note, and so does a POST (plain
/// text, a form or JSON), with no key. The reply carries nothing of the
/// vault; only the owner reads the notes back, in arrival order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_get_link_or_a_post_lands_one_note_with_no_key() {
    let (_dir, server) = inbox_server(20);
    let landed = json!({ "received": true });

    let (status, _, reply) = keyless(
        &server,
        "203.0.113.9",
        link("text=the%20export%20button%20hangs&category=bug&utm_source=x"),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    assert_eq!(reply, landed);
    let after_link = notes(&server);
    assert_eq!(after_link.len(), 1);
    assert_eq!(after_link[0].via, FeedbackInboxVia::Link);
    assert_eq!(after_link[0].text, "the export button hangs");
    assert_eq!(after_link[0].category, Some(FeedbackCategory::Bug));

    for (content_type, body, text) in [
        (
            "text/plain; charset=utf-8",
            "dark mode please",
            "dark mode please",
        ),
        (
            "application/x-www-form-urlencoded",
            "text=sync+is+slow&category=no-such-kind",
            "sync is slow",
        ),
        (
            "application/json",
            r#"{"text":"recall missed my note","category":"confusion"}"#,
            "recall missed my note",
        ),
    ] {
        let before = notes(&server).len();
        let (status, _, reply) = keyless(&server, "203.0.113.9", post(content_type), body).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{content_type}: {reply}");
        assert_eq!(reply, landed);
        let now = notes(&server);
        assert_eq!(now.len(), before + 1, "{content_type}");
        assert_eq!(now[before].via, FeedbackInboxVia::Post);
        assert_eq!(now[before].text, text);
    }

    // A note with no text lands nothing.
    let (status, _, _) = keyless(&server, "203.0.113.9", link("text=%20%20"), "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(notes(&server).len(), 4);

    // The notes are the owner's to read, and nobody else's.
    let read = Request::builder()
        .method("GET")
        .uri("/v1/owner/feedback/inbox");
    let (status, _, _) = keyless(&server, "203.0.113.9", read, "").await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "{status}"
    );
    let owner = owner_recipe(&server);
    let (status, page) = call(
        &server,
        "GET",
        "/v1/owner/feedback/inbox?after=1&limit=2",
        owner,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let seqs: Vec<_> = page
        .as_array()
        .unwrap()
        .iter()
        .map(|note| note["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, [2, 3]);
}

/// Done-means: past the flood cap an anonymous sender is shed with a typed
/// 429 and `retry-after`, and nothing lands. A forwarding header from a
/// proxy the server does not trust buys no fresh budget, nor does another
/// address in the same IPv6 /64; another sender still lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn past_the_flood_cap_an_anonymous_sender_is_shed_typed() {
    let (_dir, server) = inbox_server(2);
    for _ in 0..2 {
        let (status, _, reply) = keyless(&server, "203.0.113.9", link("text=hi"), "").await;
        assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    }
    for forwarded in [None, Some("198.51.100.1"), Some("192.0.2.77")] {
        let mut request = link("text=hi+again");
        if let Some(forwarded) = forwarded {
            request = request.header("x-forwarded-for", forwarded);
        }
        let (status, headers, reply) = keyless(&server, "203.0.113.9", request, "").await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "{forwarded:?}: {reply}"
        );
        assert_eq!(reply["details"]["state"], "feedback_inbox_flood", "{reply}");
        let retry: u64 = headers["retry-after"].to_str().unwrap().parse().unwrap();
        assert!((1..=3_600).contains(&retry), "{retry}");
    }
    assert_eq!(notes(&server).len(), 2);

    for peer in ["2001:db8::1", "2001:db8::2"] {
        let (status, _, _) = keyless(&server, peer, link("text=v6"), "").await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    let (status, _, _) = keyless(&server, "2001:db8::ffff", link("text=v6"), "").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let (status, _, _) = keyless(&server, "198.51.100.7", link("text=me+too"), "").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(notes(&server).len(), 5);
}

/// Done-means (OF-420 kept): a vault's own send lands in another server's
/// open inbox only as the bundle its owner approved. A note that would
/// carry vault text waits for the owner (refused until in-vault redaction),
/// a send the owner did not approve lands nothing, and the approved bundle
/// lands once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vault_send_reaches_the_open_inbox_only_as_its_owner_approved() {
    let (_inbox_dir, inbox) = inbox_server(20);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::build_app(inbox.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let (_dir, vault) = feedback_server(&format!("http://{address}/v1/feedback"));
    grant_feedback_sends(&vault);
    let owner = owner_recipe(&vault);

    let (status, refused) = call(
        &vault,
        "POST",
        "/v1/owner/feedback/preview",
        owner.clone(),
        Some(&json!({ "category": "bug", "note": "my diary says the export hangs" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");

    let (status, preview) = call(
        &vault,
        "POST",
        "/v1/owner/feedback/preview",
        owner.clone(),
        Some(&json!({ "category": "bug" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let send = |category: &str| {
        json!({
            "category": category,
            "digest": preview["digest"],
            "approval": preview["approval"],
            "previewed_at": preview["previewed_at"],
        })
    };
    let (status, unapproved) = call(
        &vault,
        "POST",
        "/v1/owner/feedback/send",
        owner.clone(),
        Some(&send("papercut")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{unapproved}");
    assert!(notes(&inbox).is_empty());

    let (status, sent) = call(
        &vault,
        "POST",
        "/v1/owner/feedback/send",
        owner,
        Some(&send("bug")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    assert_eq!(sent["outcome"], "delivered_to_channel", "{sent}");
    let landed = notes(&inbox);
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].via, FeedbackInboxVia::Bundle);
    assert_eq!(landed[0].category, Some(FeedbackCategory::Bug));
    assert_eq!(landed[0].text, "");
    let bundle = landed[0].bundle.as_ref().unwrap();
    assert_eq!(bundle.user_note, None);
    assert_eq!(preview["bundle"]["engine_version"], bundle.engine_version);
}
