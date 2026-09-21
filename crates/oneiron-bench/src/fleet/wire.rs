//! Real app-tier WebSocket client using the shipped server protocol version.
use futures_util::{SinkExt, StreamExt};
use oneiron::sync::transport::{PROTOCOL_VERSION, TAG_PROTOCOL_HELLO, TAG_RPC};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

use super::Result;

type Socket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// Reserve one kernel-selected client port per listener group. Siblings reuse
/// only that owned port and connect to distinct destinations. macOS otherwise
/// exhausts its ephemeral range even across several destination listeners.
pub(super) fn client_sockets(
    agents: usize,
    listeners: usize,
) -> Result<Vec<tokio::net::TcpSocket>> {
    let mut sockets = Vec::with_capacity(agents);
    let mut group_address = None;
    for index in 0..agents {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        #[cfg(unix)]
        socket.set_reuseport(true)?;
        let address = if index % listeners == 0 {
            "127.0.0.1:0".parse()?
        } else {
            group_address.ok_or("missing reserved client port")?
        };
        socket.bind(address).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("fleet client bind {index} at {address}: {error}"),
            )
        })?;
        group_address = Some(socket.local_addr()?);
        sockets.push(socket);
    }
    Ok(sockets)
}

pub(super) struct Agent {
    pub index: usize,
    pub token: String,
    pub expected_message: String,
    socket: Socket,
    timeout: Duration,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    #[serde(rename = "type")]
    kind: String,
    id: u64,
    seq: u64,
    last: bool,
    payload: T,
}

pub(super) fn token(secret: &str, actor: &str) -> String {
    // Same public v2 wire grammar and MAC domain used by the shipped mint CLI.
    let claims = format!("scope=core:read,core:write;principal_ref={actor};actor_class=agent");
    let key = blake3::derive_key(
        "oneiron-server 2026-07 core-token-v2 mac",
        secret.as_bytes(),
    );
    format!(
        "v2.{claims}.{}",
        blake3::keyed_hash(&key, claims.as_bytes()).to_hex()
    )
}

impl Agent {
    pub(super) async fn connect(
        index: usize,
        url: &str,
        address: std::net::SocketAddr,
        tcp: tokio::net::TcpSocket,
        secret: &str,
        token: String,
        timeout: Duration,
    ) -> Result<Self> {
        tokio::time::timeout(timeout, async {
            let mut request = url.into_client_request()?;
            request
                .headers_mut()
                .insert("authorization", format!("Bearer {secret}").parse()?);
            let tcp = tcp.connect(address).await.map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("fleet client connect {index} to {address}: {error}"),
                )
            })?;
            let (mut socket, _) = tokio_tungstenite::client_async(request, tcp).await?;
            socket
                .send(Message::Binary(
                    vec![TAG_PROTOCOL_HELLO, PROTOCOL_VERSION].into(),
                ))
                .await?;
            match socket
                .next()
                .await
                .ok_or("socket closed before protocol hello")??
            {
                Message::Binary(bytes) if bytes.first() == Some(&0) => {}
                _ => return Err("server did not acknowledge current protocol hello".into()),
            }
            let mut agent = Self {
                index,
                token,
                expected_message: String::new(),
                socket,
                timeout,
            };
            let bound = agent
                .rpc_inner(0, "auth.bind", json!({"token":agent.token}))
                .await?;
            if !bound.is_null() {
                return Err("auth.bind did not return null".into());
            }
            Ok(agent)
        })
        .await?
    }

    pub(super) async fn recall(&mut self, round: usize, query: &str) -> Result<()> {
        let pack = tokio::time::timeout(
            self.timeout,
            self.rpc_inner(
                round as u64 + 1,
                "recall",
                json!({"query":query,"effort":"light","limit":10}),
            ),
        )
        .await??;
        let items = pack["items"]
            .as_array()
            .ok_or("recall did not return items")?;
        if !items
            .iter()
            .any(|item| item["short_id"].as_str() == Some(self.expected_message.as_str()))
        {
            return Err(
                format!("agent {} recall omitted its committed message", self.index).into(),
            );
        }
        Ok(())
    }

    pub(super) async fn ping(&mut self, phase: u8) -> Result<()> {
        let mut nonce = (self.index as u64).to_be_bytes().to_vec();
        nonce.push(phase);
        tokio::time::timeout(self.timeout, async {
            self.socket
                .send(Message::Ping(nonce.clone().into()))
                .await?;
            loop {
                match self.socket.next().await.ok_or("held socket closed")?? {
                    Message::Pong(bytes) if bytes.as_ref() == nonce.as_slice() => return Ok(()),
                    Message::Ping(bytes) => self.socket.send(Message::Pong(bytes)).await?,
                    Message::Binary(_) | Message::Pong(_) => {}
                    _ => return Err("held socket closed or sent unexpected message".into()),
                }
            }
        })
        .await?
    }

    async fn rpc_inner(&mut self, id: u64, method: &str, params: Value) -> Result<Value> {
        let request = Envelope {
            kind: "rpc.req".into(),
            id,
            seq: 0,
            last: true,
            payload: json!({"method":method,"params":params}),
        };
        let mut bytes = vec![TAG_RPC];
        bytes.extend(rmp_serde::to_vec_named(&request)?);
        self.socket.send(Message::Binary(bytes.into())).await?;
        let mut collected = Vec::new();
        let mut seq = 0;
        loop {
            let message = self.socket.next().await.ok_or("RPC socket closed")??;
            match message {
                Message::Binary(bytes) if bytes.first() == Some(&TAG_RPC) => {
                    let header: Envelope<serde::de::IgnoredAny> =
                        rmp_serde::from_slice(&bytes[1..])?;
                    if header.id != id || header.seq != seq || header.kind != "rpc.res" {
                        return Err(format!(
                            "unexpected RPC reply: type={} id={} seq={}",
                            header.kind, header.id, header.seq
                        )
                        .into());
                    }
                    let chunk: Envelope<serde_bytes::ByteBuf> = rmp_serde::from_slice(&bytes[1..])?;
                    if chunk.payload.len() > 64 * 1024
                        || collected.len() + chunk.payload.len() > 32 * 1024 * 1024
                    {
                        return Err("oversized RPC result".into());
                    }
                    collected.extend_from_slice(&chunk.payload);
                    if chunk.last {
                        return Ok(rmp_serde::from_slice(&collected)?);
                    }
                    seq += 1;
                }
                Message::Binary(_) | Message::Pong(_) => {}
                Message::Ping(bytes) => self.socket.send(Message::Pong(bytes)).await?,
                _ => return Err("RPC socket closed or sent unexpected message".into()),
            }
        }
    }
}
