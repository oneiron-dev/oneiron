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
    server:Arc<SyncServer>,
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
    let app=build_app(server.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Fixture {
        task,
        url,
        _dir: dir,server,
    }
}

struct Credential {slip:oneiron::authority::CapabilitySlip,holder:ed25519_dalek::SigningKey}
fn credential(fixture:&Fixture)->Credential {
    let vault=fixture.server.vault();
    let principal=oneiron::EntityId::from_hex(PRINCIPAL).unwrap();
    if vault.get_entity_type(&principal).unwrap().is_none() {vault.put_entity(&principal,oneiron::ENTITY_TYPE_PERSON,oneiron::TimeRange{start:1,end:1},1,b"app principal").unwrap();}
    let issuer=oneiron::authority::HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let mut claims=vault.ensure_host_root_slip(&issuer).unwrap().claims;
    claims.slip_id=*blake3::hash(oneiron::EntityId::now().as_bytes()).as_bytes();
    claims.holder_ref=PRINCIPAL.into();claims.actor_class=Some("human".into());
    claims.scope.verbs=oneiron::federation::ScopeAxis::Some(std::collections::BTreeSet::from(["read".into()]));
    let holder=ed25519_dalek::SigningKey::from_bytes(&[93;32]);
    claims.binding_key=holder.verifying_key().to_bytes();
    let slip=vault.mint_capability_slip(&issuer,claims).unwrap();
    Credential{slip,holder}
}
fn now()->u64 {std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()}
fn bind_payload(credential:&Credential,timestamp:u64)->Value {
    use ed25519_dalek::Signer;
    let nonce=oneiron::EntityId::now().to_hex();let challenge=format!("oneiron-request:{timestamp}:{nonce}");
    let signature:String=credential.holder.sign(&credential.slip.binding_transcript(challenge.as_bytes()).unwrap()).to_bytes().iter().map(|b|format!("{b:02x}")).collect();
    json!({"token":credential.slip.to_token().unwrap(),"binding":{"timestamp":timestamp,"nonce":nonce,"signature":signature}})
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
    let valid=credential(&fixture);
    let mut forged_json=serde_json::to_value(&valid.slip).unwrap();
    forged_json["mac"][0]=json!(forged_json["mac"][0].as_u64().unwrap() ^ 1);
    let forged:oneiron::authority::CapabilitySlip=serde_json::from_value(forged_json).unwrap();
    let forged_credential=Credential{slip:forged,holder:valid.holder.clone()};
    let forged_params=bind_payload(&forged_credential,now());
    let wrong_holder=Credential{slip:valid.slip.clone(),holder:ed25519_dalek::SigningKey::from_bytes(&[94;32])};
    let mut bad_frame=bind_payload(&valid,now());bad_frame["token"]=json!("v2.invalid.bad");
    let mut unknown=bind_payload(&valid,now());unknown["unknown"]=json!("x");
    let revoked=credential(&fixture);
    fixture.server.vault().revoke_capability_slip(&oneiron::authority::HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap(),revoked.slip.claims.slip_id).unwrap();
    for invalid in [forged_params,bind_payload(&wrong_holder,now()),bad_frame,unknown,bind_payload(&valid,now().saturating_sub(120)),json!({"token":valid.slip.to_token().unwrap()}),bind_payload(&revoked,now())] {
        let mut socket=connect(&fixture,APP_TIER_PROTOCOL_VERSION_VERSION).await;
        send(&mut socket,TAG_RPC,json!({"requestId":1,"method":"auth.bind","params":invalid})).await;
        assert_eq!(close_code(&mut socket).await,4008);
    }
    let mut socket = connect(&fixture, APP_TIER_PROTOCOL_VERSION_VERSION).await;
    send(
        &mut socket,
        TAG_RPC,
        json!({"requestId":5,"method":"auth.bind","params":bind_payload(&valid,now())}),
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
    let credential=credential(&fixture);
    let payload=bind_payload(&credential,now());
    let slip=payload["token"].as_str().unwrap();
    request.headers_mut().insert("x-oneiron-binding",payload["binding"].to_string().parse().unwrap());
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {slip}").parse().unwrap());
    let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
    assert!(
        matches!(error, tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == 401)
    );
}
