//! Lag never closes a socket (rule 5): a socket that fell behind the shared
//! fan-out is told again what it may have missed, catches up through its own
//! client, and keeps receiving.

use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use futures_util::{SinkExt, StreamExt};
use loro::{ExportMode, VersionVector};
use oneiron::sync::transport::{self, document_sub_tags, window_sub_tags};
use oneiron::sync::{SyncClient, SyncClientConfig, SyncResidenceMode, WindowKey, WindowManager};
use oneiron::{EntityId, Vault, VaultConfig};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const SECRET: &str = "lag-resync-fixture-root";

/// A home serving sockets.
struct Home {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    task: tokio::task::JoinHandle<()>,
    url: String,
}

impl Drop for Home {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Home {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
        let server = Arc::new(
            SyncServer::new(
                vault,
                SyncServerConfig {
                    auth_secret: Some(SECRET.into()),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let task = tokio::spawn({
            let server = server.clone();
            async move {
                axum::serve(listener, crate::build_app(server))
                    .await
                    .unwrap();
            }
        });
        Self {
            _dir: dir,
            server,
            task,
            url,
        }
    }

    async fn socket(&self, jti: &str, hello: Vec<u8>) -> Socket {
        let mut request = self.url.as_str().into_client_request().unwrap();
        crate::test_credentials::bind_ws_request(&self.server, &mut request, &format!("jti={jti}"));
        let mut socket = tokio_tungstenite::connect_async(request).await.unwrap().0;
        send(&mut socket, hello).await;
        socket
    }

    /// One new PERSON row in `key`, as the UPDATE that relays it.
    async fn change(&self, key: &WindowKey, at: u64) -> Change {
        let doc = self.server.get_or_create_window(key).await.unwrap();
        let base = doc.oplog_vv();
        let edit = doc.fork();
        let id = EntityId::now();
        let mut row = vec![oneiron::registry::ENTITY_TYPE_PERSON];
        for _ in 0..3 {
            row.extend_from_slice(&at.to_be_bytes());
        }
        row.extend_from_slice(b"placeholder person");
        edit.get_map("entities")
            .insert(&id.to_hex(), row.as_slice())
            .unwrap();
        edit.commit();
        let update = edit.export(ExportMode::updates(&base)).unwrap();
        let frame = transport::encode_window_sync(key.as_str(), window_sub_tags::UPDATE, &update)
            .into_result()
            .unwrap();
        Change { frame, id, update }
    }

    /// Lands `change` in the home's live window and fans it out, then fans
    /// out more frames than the channel holds, with no await in between: a
    /// socket that has not read it yet loses it to lag.
    async fn change_lost_to_lag(&self, key: &WindowKey, change: &Change) {
        let doc = self.server.get_or_create_window(key).await.unwrap();
        doc.import(&change.update).unwrap();
        crate::broadcast::broadcast(&self.server.broadcast_tx, 0, change.frame.clone()).unwrap();
        for _ in 0..1_024 {
            let filler = vec![transport::TAG_EPHEMERAL, 0];
            let _ = crate::broadcast::broadcast(&self.server.broadcast_tx, 0, filler);
        }
    }
}

struct Change {
    frame: Vec<u8>,
    id: EntityId,
    update: Vec<u8>,
}

async fn send(socket: &mut Socket, frame: Vec<u8>) {
    socket.send(Message::Binary(frame.into())).await.unwrap();
}

/// Window frames a socket received until it went quiet, and the close code
/// if the server closed it.
#[derive(Default)]
struct Heard {
    frames: BTreeMap<String, Vec<Vec<u8>>>,
    close: Option<u16>,
}

impl Heard {
    fn tags(&self, key: &WindowKey) -> Vec<u8> {
        self.frames
            .get(key.as_str())
            .into_iter()
            .flatten()
            .map(|frame| transport::decode_window_sync(&frame[1..]).unwrap().1)
            .collect()
    }

    /// Whether an UPDATE for `key` brought `change`.
    fn pushed(&self, key: &WindowKey, change: &Change) -> bool {
        self.frames
            .get(key.as_str())
            .into_iter()
            .flatten()
            .any(|frame| {
                let (_, tag, payload) = transport::decode_window_sync(&frame[1..]).unwrap();
                tag == window_sub_tags::UPDATE
                    && (payload == change.update.as_slice() || carries(payload, change.id))
            })
    }
}

async fn listen(socket: &mut Socket, quiet: Duration) -> Heard {
    let mut heard = Heard::default();
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let message = match tokio::time::timeout(quiet, socket.next()).await {
                Ok(Some(Ok(message))) => message,
                Ok(None | Some(Err(_))) => {
                    heard.close = Some(1006);
                    return;
                }
                Err(_) => return,
            };
            match message {
                Message::Close(frame) => {
                    heard.close = Some(frame.map_or(0, |frame| u16::from(frame.code)));
                    return;
                }
                Message::Binary(frame) if frame.first() == Some(&transport::TAG_WINDOW_SYNC) => {
                    let (key, _, _) = transport::decode_window_sync(&frame[1..]).unwrap();
                    heard
                        .frames
                        .entry(key.to_owned())
                        .or_default()
                        .push(frame.to_vec());
                }
                _ => {}
            }
        }
    })
    .await;
    heard
}

fn carries(bytes: &[u8], id: EntityId) -> bool {
    let doc = loro::LoroDoc::new();
    doc.import(bytes).is_ok() && doc.get_map("entities").get(&id.to_hex()).is_some()
}

/// Bug repro (rule 5, census row 14): an owner socket that fell behind the
/// fan-out was closed (a full-window socket at its first lag, any socket at
/// its third), and the change it missed was lost to it until it reconnected.
/// Done-means, for both owner lanes: the socket stays open, is told again,
/// catches up through its own client on the change it missed, and the next
/// change is pushed to it.
#[tokio::test]
async fn a_lagging_owner_socket_is_resynced_and_keeps_receiving() {
    for (lane, hello, told) in [
        (
            "v11",
            transport::encode_chunk_full_window_protocol_hello(),
            window_sub_tags::VV_REQUEST,
        ),
        (
            "v13",
            transport::encode_replacement_full_window_protocol_hello(),
            window_sub_tags::WINDOW_INVALIDATE,
        ),
    ] {
        let home = Home::start().await;
        let at = 1_577_836_800 + 14 * 86_400;
        let key = WindowKey::from_timestamp(at);
        home.server.get_or_create_window(&key).await.unwrap();
        let mut owner = home.socket(&format!("lag-{lane}"), hello.clone()).await;
        let request = transport::encode_window_sync(
            key.as_str(),
            window_sub_tags::VV_REQUEST,
            &VersionVector::new().encode(),
        )
        .into_result()
        .unwrap();
        send(&mut owner, request).await;
        let subscribed = listen(&mut owner, Duration::from_secs(2)).await;
        assert_eq!(subscribed.close, None, "{lane}: not subscribed");

        // Three lags in a row: once closed any socket.
        let mut missed = Vec::new();
        for _ in 0..3 {
            let change = home.change(&key, at).await;
            home.change_lost_to_lag(&key, &change).await;
            missed.push(change);
            let heard = listen(&mut owner, Duration::from_secs(2)).await;
            assert_eq!(
                heard.close, None,
                "{lane}: the home closed a lagging socket"
            );
            assert!(
                heard.tags(&key).contains(&told),
                "{lane}: the lagging socket was not told: {:?}",
                heard.tags(&key)
            );
            if missed.len() == 3 {
                // The device's own client answers what the home sent.
                let device_dir = tempfile::tempdir().unwrap();
                let device =
                    Arc::new(Vault::open(device_dir.path(), VaultConfig::device()).unwrap());
                let manager = Arc::new(WindowManager::new(
                    device,
                    Arc::new(oneiron::sync::bridge::Materializer::new()),
                    "device",
                ));
                let (mut client, _events) = SyncClient::new(
                    manager,
                    SyncClientConfig {
                        residence_mode: SyncResidenceMode::All,
                        ..Default::default()
                    },
                )
                .unwrap();
                let mut answers = Vec::new();
                for frame in heard.frames.get(key.as_str()).into_iter().flatten() {
                    answers.extend(client.handle_server_message(frame).unwrap());
                }
                assert!(!answers.is_empty(), "{lane}: the client let the notice go");
                for answer in answers {
                    send(&mut owner, answer).await;
                }
            }
        }
        let caught_up = listen(&mut owner, Duration::from_secs(3)).await;
        assert_eq!(caught_up.close, None);
        for change in &missed {
            assert!(
                caught_up.pushed(&key, change),
                "{lane}: a change lost to lag never arrived: {:?}",
                caught_up.tags(&key)
            );
        }

        let mut writer = home.socket(&format!("lag-writer-{lane}"), hello).await;
        let next = home.change(&key, at).await;
        send(&mut writer, next.frame.clone()).await;
        let heard = listen(&mut owner, Duration::from_secs(3)).await;
        assert!(
            heard.pushed(&key, &next),
            "{lane}: the next change was not pushed"
        );
    }
}
