//! The broker end to end, on a real Unix socket against the local TLS fake:
//! one send with the key, the reflected key stripped (N11's broker half), no
//! redirect followed (N5's), and nothing sent for a refused call or peer.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use crate::frame::{read_reply, write_call};
use crate::testing::{FakeProvider, FakeReply};
use crate::{
    BrokerClient, BrokerError, CallHeader, Failure, Isolation, Outcome, Refusal, SendPolicy,
    ServeConfig, Shape, serve,
};

/// A synthetic key. It must never come back out of the broker.
const SENTINEL: &str = "sk-test-sentinel-0000";
const BODY: &[u8] = br#"{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}"#;

struct Broker {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    uid: u32,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a broker that serves `client_uid` and trusts `roots`.
async fn broker(client_uid: Option<u32>, roots: &[&[u8]]) -> Broker {
    let dir = tempfile::tempdir().expect("dir");
    let uid = std::fs::metadata(dir.path()).expect("meta").uid();
    let socket = dir.path().join("broker.sock");
    let task = tokio::spawn(serve(ServeConfig {
        socket: socket.clone(),
        client_uid: client_uid.unwrap_or(uid),
        policy: SendPolicy {
            timeout: Duration::from_secs(20),
            extra_roots: roots.iter().map(|pem| pem.to_vec()).collect(),
        },
    }));
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Broker {
        _dir: dir,
        socket,
        uid,
        task,
    }
}

fn client(socket: &Path, uid: u32) -> BrokerClient {
    BrokerClient::new(
        socket.to_owned(),
        uid,
        Isolation::SameUser,
        Duration::from_secs(30),
    )
    .expect("client")
}

fn chat(origin: &str, body: &[u8]) -> CallHeader {
    CallHeader::new(
        "lease-1".to_owned(),
        Shape::OpenAiChat,
        origin.to_owned(),
        "/v1/chat/completions".to_owned(),
        vec![("content-type".to_owned(), "application/json".to_owned())],
        "gpt-x".to_owned(),
        body,
    )
}

fn key() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(SENTINEL.as_bytes().to_vec())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn one_call_is_one_send_with_the_key_and_the_answer_comes_back() {
    let fake = FakeProvider::start(FakeReply::json(
        200,
        &serde_json::json!({"usage": {"prompt_tokens": 3}}),
    ));
    let broker = broker(None, &[fake.ca_pem()]).await;
    let reply = client(&broker.socket, broker.uid)
        .connect()
        .await
        .expect("connect")
        .call(&chat(fake.origin(), BODY), BODY, key())
        .await
        .expect("call");
    let Outcome::Answered { status, .. } = reply.outcome else {
        panic!("not answered: {:?}", reply.outcome);
    };
    assert_eq!(status, 200);
    assert!(contains(&reply.body, b"prompt_tokens"));
    let seen = fake.seen();
    assert_eq!(seen.len(), 1, "exactly one send");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/v1/chat/completions");
    assert_eq!(seen[0].body, BODY, "the exact bytes the digest bound");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {SENTINEL}").as_str())
    );
    assert_eq!(seen[0].header("accept-encoding"), Some("identity"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_the_provider_echoes_never_leaves_the_broker() {
    let fake = FakeProvider::start(FakeReply::json(401, &serde_json::json!({})));
    fake.respond_with(|request| {
        let auth = request
            .header("authorization")
            .unwrap_or_default()
            .to_owned();
        let key = auth.trim_start_matches("Bearer ").to_owned();
        let body = serde_json::json!({
            "error": format!("invalid key {key}"),
            "auth": auth,
            "b64": base64::engine::general_purpose::STANDARD.encode(&auth),
            "url": key.replace('-', "%2D"),
        });
        FakeReply {
            status: 401,
            headers: vec![("x-echo".to_owned(), auth), (key, "named".to_owned())],
            body: body.to_string().into_bytes(),
        }
    });
    let broker = broker(None, &[fake.ca_pem()]).await;
    let reply = client(&broker.socket, broker.uid)
        .connect()
        .await
        .expect("connect")
        .call(&chat(fake.origin(), BODY), BODY, key())
        .await
        .expect("call");
    let Outcome::Answered { status, headers } = reply.outcome else {
        panic!("not answered");
    };
    assert_eq!(status, 401);
    assert_eq!(fake.seen().len(), 1);
    let encoded = base64::engine::general_purpose::STANDARD.encode(SENTINEL);
    for text in std::iter::once(reply.body.to_vec()).chain(
        headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}").into_bytes()),
    ) {
        assert!(
            !contains(&text, SENTINEL.as_bytes()),
            "{}",
            String::from_utf8_lossy(&text)
        );
        assert!(!contains(&text, encoded.trim_end_matches('=').as_bytes()));
    }
    assert!(
        headers
            .iter()
            .any(|(name, value)| name == "x-echo" && value == "[redacted]")
    );
    assert!(contains(&reply.body, b"invalid key [redacted]"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_is_answered_and_never_followed() {
    let elsewhere = FakeProvider::start(FakeReply::json(200, &serde_json::json!({})));
    let fake = FakeProvider::start(FakeReply {
        status: 307,
        headers: vec![(
            "location".to_owned(),
            format!("{}/v1/chat/completions", elsewhere.origin()),
        )],
        body: Vec::new(),
    });
    let broker = broker(None, &[fake.ca_pem(), elsewhere.ca_pem()]).await;
    let reply = client(&broker.socket, broker.uid)
        .connect()
        .await
        .expect("connect")
        .call(&chat(fake.origin(), BODY), BODY, key())
        .await
        .expect("call");
    assert!(matches!(
        reply.outcome,
        Outcome::Answered { status: 307, .. }
    ));
    assert_eq!(fake.seen().len(), 1);
    assert_eq!(
        elsewhere.connections(),
        0,
        "no second send, with or without auth"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_broker_rechecks_a_call_and_sends_nothing_for_a_bad_one() {
    let fake = FakeProvider::start(FakeReply::json(200, &serde_json::json!({})));
    let broker = broker(None, &[fake.ca_pem()]).await;
    let other = br#"{"model":"gpt-x","messages":[{"role":"user","content":"more"}]}"#;
    let route = br#"{"model":"gpt-x","route":"fallback"}"#;
    let cases: [(CallHeader, &[u8], Refusal); 3] = [
        // The permit bound one request; another one is sent with its digest.
        (chat(fake.origin(), BODY), other, Refusal::Digest),
        (chat(fake.origin(), route), route, Refusal::RouteOverride),
        (chat("https://127.0.0.1:1", BODY), BODY, Refusal::Connect),
    ];
    for (call, body, refusal) in cases {
        // Straight onto the socket, past the daemon's own check.
        let mut stream = UnixStream::connect(&broker.socket).await.expect("connect");
        write_call(&mut stream, &call, body, SENTINEL.as_bytes())
            .await
            .expect("write");
        let (reply, reply_body) = read_reply(&mut stream).await.expect("reply");
        assert_eq!(reply.outcome, Outcome::Refused { reason: refusal });
        assert!(reply_body.is_empty());
    }
    assert!(fake.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_untrusted_certificate_or_an_encoded_reply_returns_nothing() {
    let fake = FakeProvider::start(FakeReply::json(200, &serde_json::json!({})));
    let untrusting = broker(None, &[]).await;
    let reply = client(&untrusting.socket, untrusting.uid)
        .connect()
        .await
        .expect("connect")
        .call(&chat(fake.origin(), BODY), BODY, key())
        .await
        .expect("call");
    assert_eq!(
        reply.outcome,
        Outcome::Refused {
            reason: Refusal::Connect
        }
    );
    assert!(
        fake.seen().is_empty(),
        "the TLS check fails before the request"
    );

    fake.respond_with(|_| FakeReply {
        status: 200,
        headers: vec![("content-encoding".to_owned(), "gzip".to_owned())],
        body: SENTINEL.as_bytes().to_vec(),
    });
    let broker = broker(None, &[fake.ca_pem()]).await;
    let reply = client(&broker.socket, broker.uid)
        .connect()
        .await
        .expect("connect")
        .call(&chat(fake.origin(), BODY), BODY, key())
        .await
        .expect("call");
    assert_eq!(
        reply.outcome,
        Outcome::Failed {
            reason: Failure::ReplyEncoded
        }
    );
    assert!(reply.body.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_named_peers_talk() {
    let fake = FakeProvider::start(FakeReply::json(200, &serde_json::json!({})));
    let ours = broker(None, &[fake.ca_pem()]).await;
    // A separate-user broker may not share the daemon's uid, and a broker on
    // another uid than the configured one is refused before anything is
    // written.
    let shared = BrokerClient::new(
        ours.socket.clone(),
        ours.uid,
        Isolation::SeparateUser,
        Duration::from_secs(5),
    );
    assert_eq!(shared.err(), Some(BrokerError::Peer));

    // The broker closes on a peer that is not the daemon's uid, unread.
    let elsewhere = broker(Some(ours.uid.wrapping_add(1)), &[fake.ca_pem()]).await;
    let mut stream = UnixStream::connect(&elsewhere.socket)
        .await
        .expect("connect");
    let _ = write_call(
        &mut stream,
        &chat(fake.origin(), BODY),
        BODY,
        SENTINEL.as_bytes(),
    )
    .await;
    assert!(read_reply(&mut stream).await.is_err());
    assert!(fake.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coding_in_any_value_of_either_header_returns_nothing() {
    let fake = FakeProvider::start(FakeReply::json(200, &serde_json::json!({})));
    let broker = broker(None, &[fake.ca_pem()]).await;
    let codings: [&[(&str, &str)]; 3] = [
        // The first value alone says nothing is encoded.
        &[("content-encoding", "identity"), ("content-encoding", "gzip")],
        &[("content-encoding", "identity, br")],
        // A transfer coding the HTTP stack leaves on the bytes.
        &[("transfer-encoding", "gzip, chunked")],
    ];
    for headers in codings {
        let named: Vec<(String, String)> = headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        let sent = named.clone();
        fake.respond_with(move |_| FakeReply {
            status: 200,
            headers: sent.clone(),
            body: SENTINEL.as_bytes().to_vec(),
        });
        let reply = client(&broker.socket, broker.uid)
            .connect()
            .await
            .expect("connect")
            .call(&chat(fake.origin(), BODY), BODY, key())
            .await
            .expect("call");
        assert_eq!(
            reply.outcome,
            Outcome::Failed {
                reason: Failure::ReplyEncoded
            },
            "{named:?}"
        );
        assert!(reply.body.is_empty(), "{named:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_with_a_byte_outside_visible_ascii_is_never_sent() {
    // The strip forms are read over visible ASCII, so a key they could not
    // find in a reply is refused before the send.
    let fake = FakeProvider::start(FakeReply::json(200, &serde_json::json!({})));
    let broker = broker(None, &[fake.ca_pem()]).await;
    for key in [&b"sk-test-\xe9t\xe9"[..], b"sk-test sentinel"] {
        let reply = client(&broker.socket, broker.uid)
            .connect()
            .await
            .expect("connect")
            .call(
                &chat(fake.origin(), BODY),
                BODY,
                Zeroizing::new(key.to_vec()),
            )
            .await
            .expect("call");
        assert_eq!(
            reply.outcome,
            Outcome::Refused {
                reason: Refusal::Secret
            }
        );
    }
    assert!(fake.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_broker_never_takes_a_live_socket() {
    let fake = FakeProvider::start(FakeReply::json(200, &serde_json::json!({})));
    let live = broker(None, &[fake.ca_pem()]).await;
    let second = tokio::time::timeout(
        Duration::from_secs(5),
        serve(ServeConfig {
            socket: live.socket.clone(),
            client_uid: live.uid,
            policy: SendPolicy {
                timeout: Duration::from_secs(20),
                extra_roots: vec![fake.ca_pem().to_vec()],
            },
        }),
    )
    .await
    .expect("refused at once, not served");
    assert_eq!(
        second.err().map(|error| error.kind()),
        Some(std::io::ErrorKind::AddrInUse)
    );
    // The first broker still holds its socket and answers.
    let reply = client(&live.socket, live.uid)
        .connect()
        .await
        .expect("connect")
        .call(&chat(fake.origin(), BODY), BODY, key())
        .await
        .expect("call");
    assert!(matches!(reply.outcome, Outcome::Answered { status: 200, .. }));
}
