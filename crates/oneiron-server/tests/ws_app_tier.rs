#![allow(clippy::unwrap_used)]
//! New app-tier socket tests. The upgrade always uses owner credentials;
//! principal-bearing slips are presented only inside auth.bind.

use futures_util::{SinkExt, StreamExt};
use oneiron::sync::transport::{
    APP_TIER_PROTOCOL_VERSION_VERSION, LEGACY_SELECTOR_PROTOCOL_VERSION, TAG_PROTOCOL_HELLO,
    TAG_RPC, TAG_SUB, TAG_VERSION_VECTOR,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
const SECRET: &str = "ws-app-tier-test-owner";
const PRINCIPAL: &str = "11111111111111111111111111111111";

struct Fixture {
    task: tokio::task::JoinHandle<()>,
    url: String,
    _dir: tempfile::TempDir,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some(SECRET.to_owned()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, build_app(server)).await.unwrap();
    });
    Fixture {
        task,
        url,
        _dir: dir,
    }
}

fn token(claims: &str) -> String {
    let key = blake3::derive_key(
        "oneiron-server 2026-07 core-token-v2 mac",
        SECRET.as_bytes(),
    );
    let mac = blake3::keyed_hash(&key, claims.as_bytes());
    format!("v2.{claims}.{}", mac.to_hex())
}

async fn connect(fixture: &Fixture, version: u8) -> Socket {
    let mut request = fixture.url.as_str().into_client_request().unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {SECRET}").parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    socket
        .send(Message::Binary(vec![TAG_PROTOCOL_HELLO, version].into()))
        .await
        .unwrap();
    let root = next(&mut socket).await;
    assert!(matches!(root, Message::Binary(ref data) if data[0] == 0));
    socket
}

async fn next(socket: &mut Socket) -> Message {
    tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

/// The version-8 app envelope the server speaks: TAG + MessagePack
/// `{type, id, seq, last, payload}`. Requests are terminal at seq zero; RPC
/// results arrive as `rpc.res` chunks whose payloads concatenate into one
/// MessagePack value.
#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    #[serde(rename = "type")]
    kind: String,
    id: u64,
    seq: u64,
    last: bool,
    payload: T,
}

async fn send(socket: &mut Socket, tag: u8, mut value: Value) {
    let object = value.as_object_mut().unwrap();
    let id = object
        .remove("requestId")
        .or_else(|| object.remove("subscriptionId"))
        .and_then(|id| id.as_u64())
        .unwrap();
    let kind = if tag == TAG_RPC {
        "rpc.req".to_owned()
    } else {
        object
            .remove("method")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    };
    let envelope = Envelope {
        kind,
        id,
        seq: 0,
        last: true,
        payload: value,
    };
    let mut data = vec![tag];
    envelope
        .serialize(&mut rmp_serde::Serializer::new(&mut data).with_struct_map())
        .unwrap();
    socket.send(Message::Binary(data.into())).await.unwrap();
}

/// Reassemble one `rpc.res` reply from its chunk frames into the
/// `{requestId, result, last}` shape the assertions pin.
async fn rpc_reply(socket: &mut Socket) -> Value {
    let mut data = Vec::new();
    let mut next_seq = 0;
    loop {
        let frame = match next(socket).await {
            Message::Binary(frame) => frame,
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected bind response, got {other:?}"),
        };
        assert_eq!(frame[0], TAG_RPC);
        let envelope: Envelope<serde_bytes::ByteBuf> = rmp_serde::from_slice(&frame[1..]).unwrap();
        assert_eq!(envelope.kind, "rpc.res");
        assert_eq!(envelope.seq, next_seq);
        next_seq += 1;
        data.extend_from_slice(&envelope.payload);
        if envelope.last {
            let result: Value = rmp_serde::from_slice(&data).unwrap();
            return json!({"requestId": envelope.id, "result": result, "last": true});
        }
    }
}

async fn close_code(socket: &mut Socket) -> u16 {
    loop {
        match next(socket).await {
            Message::Close(Some(close)) => return close.code.into(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected close, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn old_version_syncs_but_app_tag_closes_4007_before_json_decode() {
    let fixture = fixture().await;
    const { assert!(LEGACY_SELECTOR_PROTOCOL_VERSION < APP_TIER_PROTOCOL_VERSION_VERSION) };
    let mut socket = connect(&fixture, APP_TIER_PROTOCOL_VERSION_VERSION - 1).await;
    let mut vv = vec![TAG_VERSION_VECTOR];
    vv.extend_from_slice(&loro::VersionVector::default().encode());
    socket.send(Message::Binary(vv.into())).await.unwrap();
    assert!(matches!(next(&mut socket).await, Message::Binary(ref data) if data[0] == 0));
    socket
        .send(Message::Binary(vec![TAG_RPC, 255].into()))
        .await
        .unwrap();
    assert_eq!(close_code(&mut socket).await, 4007);
}

#[tokio::test]
async fn rpc_and_sub_without_bind_close_4008() {
    let fixture = fixture().await;
    for tag in [TAG_RPC, TAG_SUB] {
        let mut socket = connect(&fixture, APP_TIER_PROTOCOL_VERSION_VERSION).await;
        send(
            &mut socket,
            tag,
            json!({"requestId":1,"method":"hydrate","params":{"refs":[]}}),
        )
        .await;
        assert_eq!(close_code(&mut socket).await, 4008);
    }
}

#[tokio::test]
async fn bind_requires_a_mac_verified_slip_then_returns_terminal_reply() {
    let fixture = fixture().await;
    let valid = token(&format!("scope=core:read;principal_ref={PRINCIPAL}"));
    let unknown = token(&format!(
        "scope=core:read;principal_ref={PRINCIPAL};unknown=x"
    ));
    for invalid in [
        SECRET,
        "ws-app-tier-test-owner;scope=core:read",
        "v2.scope=core:read.bad",
        &unknown,
    ] {
        let mut socket = connect(&fixture, APP_TIER_PROTOCOL_VERSION_VERSION).await;
        send(
            &mut socket,
            TAG_RPC,
            json!({"requestId":1,"method":"auth.bind","params":{"token":invalid}}),
        )
        .await;
        assert_eq!(close_code(&mut socket).await, 4008);
    }
    let mut socket = connect(&fixture, APP_TIER_PROTOCOL_VERSION_VERSION).await;
    send(
        &mut socket,
        TAG_RPC,
        json!({"requestId":5,"method":"auth.bind","params":{"token":valid}}),
    )
    .await;
    assert_eq!(
        rpc_reply(&mut socket).await,
        json!({"requestId":5,"result":null,"last":true})
    );
}

#[tokio::test]
async fn a_principal_slip_never_crosses_the_owner_upgrade_gate() {
    let fixture = fixture().await;
    let mut request = fixture.url.as_str().into_client_request().unwrap();
    let slip = token(&format!("scope=core:read;principal_ref={PRINCIPAL}"));
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {slip}").parse().unwrap());
    let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
    assert!(
        matches!(error, tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == 401)
    );
}
