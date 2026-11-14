//! A device's live socket follows the owner's pick as it changes (Engine
//! ruling WORLDSET-1, Fri 13 Nov 03:02: "renegotiate at once ... on pick
//! change"; ARCH-0023b #partial-sync). The device runs its real
//! `SyncConnection` against a fake home on a loopback port: one listener
//! answers the sync socket (root image, NOTE bind, promotion grants) and the
//! residence RPC socket (bind, thin index, a refusal for every other call).
//!
//! The pick changes while the first negotiation reads its thin index, after
//! that negotiation's frames went out: the loop renegotiates once it starts,
//! and the next socket asks the home for the picked world's window alone.
//! An empty pick on the live socket renegotiates again, and the next socket
//! asks for no world window.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use oneiron::EntityId;
use oneiron::authority::HostSlipIssuer;
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::transport::{
    self, LEASE_STATUS_GRANTED, TAG_LEASE_REQUEST, TAG_RPC, TAG_VERSION_VECTOR, TAG_WINDOW_SYNC,
    window_sub_tags,
};
use oneiron::sync::{
    SyncClientConfig, SyncEvent, SyncResidenceMode, SyncSelector, SyncSelectorWorld, SyncStatus,
    WindowKey,
};
use rmpv::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

use super::device_world_follow::{Device, FIXTURE_HOST_SECRET, now_secs, root_frame};

/// The request id of every NOTE session bind.
const BIND_ID: u64 = 4_294_967_295;
/// How long the test waits for each step of the run.
const STEP_WAIT: Duration = Duration::from_secs(20);

/// What the fake home saw, in the order it saw it.
#[derive(Debug)]
enum HomeEvent {
    /// A sync socket opened: its number, counted from 1.
    SyncOpened(usize),
    /// A sync socket asked about a world window.
    WorldAsked {
        connection: usize,
        window: String,
        sub_tag: u8,
    },
    /// The first thin index read, held until the test lets it go.
    IndexHeld,
}

#[derive(Clone, Copy)]
enum Role {
    /// The device's sync socket, by its number.
    Sync(usize),
    /// A residence RPC socket.
    Residence,
    /// Any other socket: the test reads nothing of it.
    Other,
}

/// One residence RPC request as the fake home reads it.
struct RpcRequest {
    id: u64,
    method: String,
    window: String,
}

struct FakeHome {
    /// The root image every sync socket gets for its root vector.
    root: Vec<u8>,
    events: mpsc::UnboundedSender<HomeEvent>,
    sync_sockets: AtomicUsize,
    /// Released by the test; taken by the first thin index read.
    held_index: Mutex<Option<oneshot::Receiver<()>>>,
}

impl FakeHome {
    /// Listens on a loopback port and answers every socket until the run
    /// ends: the endpoint, what the home sees, and the release of the first
    /// thin index read.
    async fn start(
        root: Vec<u8>,
    ) -> (
        String,
        mpsc::UnboundedReceiver<HomeEvent>,
        oneshot::Sender<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let url = format!(
            "ws://{}/ws",
            listener.local_addr().expect("listener address")
        );
        let (events, seen) = mpsc::unbounded_channel();
        let (release, held) = oneshot::channel();
        let home = Arc::new(Self {
            root,
            events,
            sync_sockets: AtomicUsize::new(0),
            held_index: Mutex::new(Some(held)),
        });
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(Arc::clone(&home).serve(stream));
            }
        });
        (url, seen, release)
    }

    async fn serve(self: Arc<Self>, stream: tokio::net::TcpStream) {
        let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
            return;
        };
        let mut role = None;
        while let Some(Ok(message)) = socket.next().await {
            let Message::Binary(frame) = message else {
                continue;
            };
            let replies = match *role.get_or_insert_with(|| self.role_of(&frame)) {
                Role::Sync(connection) => self.answer_sync(connection, &frame),
                Role::Residence => self.answer_residence(&frame).await,
                Role::Other => Vec::new(),
            };
            for reply in replies {
                if socket.send(Message::Binary(reply.into())).await.is_err() {
                    return;
                }
            }
        }
    }

    /// A socket's first frame says what it is: the residence hello opens an
    /// RPC socket, the opened-item replacement hello the device's sync socket.
    fn role_of(&self, first: &[u8]) -> Role {
        if first == transport::encode_residence_protocol_hello().as_slice() {
            return Role::Residence;
        }
        if first != transport::encode_replacement_residence_protocol_hello().as_slice() {
            return Role::Other;
        }
        let connection = self.sync_sockets.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.events.send(HomeEvent::SyncOpened(connection));
        Role::Sync(connection)
    }

    fn answer_sync(&self, connection: usize, frame: &[u8]) -> Vec<Vec<u8>> {
        match frame.first().copied() {
            Some(TAG_RPC) => match rpc_request(frame) {
                Some(request) if request.id == BIND_ID => vec![bind_reply()],
                _ => Vec::new(),
            },
            Some(TAG_LEASE_REQUEST) => match transport::decode_lease_request(&frame[1..]) {
                Ok((client, _, _)) => vec![transport::encode_lease_granted(
                    LEASE_STATUS_GRANTED,
                    client,
                    1,
                )],
                Err(_) => Vec::new(),
            },
            Some(TAG_VERSION_VECTOR) => vec![self.root.clone()],
            Some(TAG_WINDOW_SYNC) => {
                let Ok((window, sub_tag, _)) = transport::decode_window_sync(&frame[1..]) else {
                    return Vec::new();
                };
                if WindowKey::try_new(window).is_some_and(|key| key.world().is_some()) {
                    let _ = self.events.send(HomeEvent::WorldAsked {
                        connection,
                        window: window.to_owned(),
                        sub_tag,
                    });
                }
                if matches!(
                    sub_tag,
                    window_sub_tags::PROMOTION_REQUEST | window_sub_tags::FOLLOW_REQUEST
                ) {
                    vec![
                        transport::encode_window_sync(
                            window,
                            window_sub_tags::PROMOTION_GRANTED,
                            &[],
                        )
                        .into_result()
                        .expect("grant frame"),
                    ]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    async fn answer_residence(&self, frame: &[u8]) -> Vec<Vec<u8>> {
        let Some(request) = rpc_request(frame) else {
            return Vec::new();
        };
        if request.id == BIND_ID {
            return vec![bind_reply()];
        }
        if request.method != "residence.index" {
            return vec![rpc_envelope(
                "rpc.err",
                request.id,
                Value::Map(vec![(Value::from("code"), Value::from("UNSUPPORTED"))]),
            )];
        }
        let held = self.held_index.lock().expect("held index").take();
        if let Some(held) = held {
            let _ = self.events.send(HomeEvent::IndexHeld);
            let _ = held.await;
        }
        let page = serde_json::json!({
            "window": request.window,
            "items": [],
            "nextCursor": null,
            "revision": "0".repeat(64),
        });
        vec![rpc_envelope(
            "rpc.res",
            request.id,
            Value::Binary(rmp_serde::to_vec_named(&page).expect("encode the index page")),
        )]
    }
}

fn rpc_request(frame: &[u8]) -> Option<RpcRequest> {
    if frame.first() != Some(&TAG_RPC) {
        return None;
    }
    let envelope: serde_json::Value = rmp_serde::from_slice(&frame[1..]).ok()?;
    Some(RpcRequest {
        id: envelope["id"].as_u64()?,
        method: envelope["payload"]["method"].as_str()?.to_owned(),
        window: envelope["payload"]["params"]["window"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    })
}

/// One reply envelope, as the home writes it.
fn rpc_envelope(kind: &str, id: u64, payload: Value) -> Vec<u8> {
    let fields = vec![
        (Value::from("type"), Value::from(kind)),
        (Value::from("id"), Value::from(id)),
        (Value::from("seq"), Value::from(0_u64)),
        (Value::from("last"), Value::from(true)),
        (Value::from("payload"), payload),
    ];
    let mut frame = vec![TAG_RPC];
    rmpv::encode::write_value(&mut frame, &Value::Map(fields)).expect("encode the reply");
    frame
}

/// The home's answer to a NOTE session bind: no stamp.
fn bind_reply() -> Vec<u8> {
    rpc_envelope("rpc.res", BIND_ID, Value::Binary(vec![0xc0]))
}

/// The device's NOTE session: a slip of this host's mint, bound to the key
/// the device holds.
fn note_session(device: &Device) -> NoteSyncSession {
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST_SECRET).expect("fixture host issuer");
    let key = SigningKey::from_bytes(&[0x5a; 32]);
    let mut claims = device
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("host root")
        .claims;
    claims.slip_id = [0x5b; 32];
    claims.holder_ref = "device-world-follow-holder".to_owned();
    claims.binding_key = key.verifying_key().to_bytes();
    let slip = device
        .vault
        .mint_capability_slip(&issuer, claims)
        .expect("the device's NOTE slip");
    NoteSyncSession::new(slip.to_token().expect("slip token"), key)
}

/// What the home and the device's run reported so far.
struct Watch {
    home: mpsc::UnboundedReceiver<HomeEvent>,
    sync: mpsc::UnboundedReceiver<SyncEvent>,
    home_seen: Vec<HomeEvent>,
    sync_seen: Vec<SyncEvent>,
}

impl Watch {
    /// Reads both reports until `done` holds of them; fails after
    /// [`STEP_WAIT`] naming `what` and all both reported.
    async fn until(&mut self, what: &str, done: impl Fn(&[HomeEvent], &[SyncEvent]) -> bool) {
        let deadline = tokio::time::Instant::now() + STEP_WAIT;
        while !done(&self.home_seen, &self.sync_seen) {
            tokio::select! {
                Some(event) = self.home.recv() => self.home_seen.push(event),
                Some(event) = self.sync.recv() => self.sync_seen.push(event),
                () = tokio::time::sleep_until(deadline) => panic!(
                    "{what}\nthe home saw: {:#?}\nthe device reported: {:#?}",
                    self.home_seen, self.sync_seen
                ),
            }
        }
    }
}

/// How many negotiations reached `Synced`.
fn synced(events: &[SyncEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, SyncEvent::StatusChanged(SyncStatus::Synced)))
        .count()
}

fn opened(events: &[HomeEvent], connection: usize) -> bool {
    events
        .iter()
        .any(|event| matches!(event, HomeEvent::SyncOpened(opened) if *opened == connection))
}

/// The world windows sync socket `connection` asked about, with each ask's
/// sub tag, in order.
fn world_asks(events: &[HomeEvent], connection: usize) -> Vec<(String, u8)> {
    events
        .iter()
        .filter_map(|event| match event {
            HomeEvent::WorldAsked {
                connection: asked_on,
                window,
                sub_tag,
            } if *asked_on == connection => Some((window.clone(), *sub_tag)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_pick_change_renegotiates_live() {
    let run = std::thread::Builder::new()
        .name("a_pick_change_renegotiates_live".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(pick_change_renegotiates_live());
        })
        .expect("test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

async fn pick_change_renegotiates_live() {
    let device = Device::open();
    let at = now_secs();
    let founder = WindowKey::for_world(at, device.founder);
    let (url, home, release_index) =
        FakeHome::start(root_frame(at, &[device.founder, device.granted])).await;
    let connection = SyncConnection::new(
        device.manager(),
        ConnectionConfig {
            client_config: SyncClientConfig {
                server_url: url,
                residence_mode: SyncResidenceMode::Opened,
                residence_selector: Some(SyncSelector::new(
                    EntityId::now(),
                    EntityId::now(),
                    SyncSelectorWorld::All,
                    Vec::new(),
                    Vec::new(),
                )),
                note_session: Some(note_session(&device)),
                ..SyncClientConfig::default()
            },
            auto_reconnect: false,
        },
    )
    .expect("the device's connection");
    let (shutdown, shutdown_rx) = oneshot::channel();
    let (sync_tx, sync) = mpsc::unbounded_channel();
    let run = connection.run_observed(shutdown_rx, move |event| {
        let _ = sync_tx.send(event);
    });
    let mut watch = Watch {
        home,
        sync,
        home_seen: Vec::new(),
        sync_seen: Vec::new(),
    };
    let script = async {
        // The first negotiation follows no world. The owner picks the
        // founder world while it reads its thin index, after its frames
        // went out.
        watch
            .until("the first negotiation reads its thin index", |home, _| {
                home.iter()
                    .any(|event| matches!(event, HomeEvent::IndexHeld))
            })
            .await;
        assert_eq!(
            world_asks(&watch.home_seen, 1),
            Vec::<(String, u8)>::new(),
            "precondition: with nothing picked the first socket asks for no world window",
        );
        connection
            .set_followed_worlds([device.founder].into_iter().collect())
            .expect("the owner's pick");
        release_index.send(()).expect("the held index read");

        // The loop renegotiates at once: a second socket asks the home to
        // grant the picked world's window, and not the readable world
        // nobody picked.
        watch
            .until(
                "the pick renegotiates: a second socket syncs and asks for the picked world",
                |home, sync| {
                    synced(sync) >= 2
                        && world_asks(home, 2).contains(&(
                            founder.as_str().to_owned(),
                            window_sub_tags::FOLLOW_REQUEST,
                        ))
                },
            )
            .await;
        let second: BTreeSet<String> = world_asks(&watch.home_seen, 2)
            .into_iter()
            .map(|(window, _)| window)
            .collect();
        assert_eq!(
            second,
            BTreeSet::from([founder.as_str().to_owned()]),
            "the second socket asks about the picked world's window alone",
        );

        // An empty pick on the live socket renegotiates again; the next
        // socket asks for no world window.
        connection
            .set_followed_worlds(BTreeSet::new())
            .expect("the owner's empty pick");
        watch
            .until(
                "the empty pick renegotiates: a third socket syncs",
                |home, sync| opened(home, 3) && synced(sync) >= 3,
            )
            .await;
        assert_eq!(
            world_asks(&watch.home_seen, 3),
            Vec::<(String, u8)>::new(),
            "after the empty pick the third socket asks for no world window",
        );
        shutdown.send(()).expect("the run is still live");
    };
    let (ran, ()) = tokio::join!(run, script);
    ran.expect("the run ends at shutdown");
}

/// FOLLOWED-WINDOW-FULL-RESYNC: a followed world's window carries a
/// full-resync marker (`fr:w:`). The device re-bootstraps it over the follow
/// the home granted on this connection: it asks the home for the window's
/// replacement. Before, each connect failed with "opened-item full-resync
/// requires explicit sync-all recovery", since only a window this device
/// promoted (`rp:w:`) could recover.
#[test]
fn a_marked_followed_window_rebootstraps_over_its_follow() {
    let run = std::thread::Builder::new()
        .name("a_marked_followed_window_rebootstraps_over_its_follow".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(marked_followed_window_rebootstraps_over_its_follow());
        })
        .expect("test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

async fn marked_followed_window_rebootstraps_over_its_follow() {
    let device = Device::open();
    let at = now_secs();
    let founder = WindowKey::for_world(at, device.founder);
    let (url, home, release_index) = FakeHome::start(root_frame(at, &[device.founder])).await;
    release_index.send(()).expect("the index read is not held");
    device
        .vault
        .sync_state_put(&format!("fr:w:{founder}"), &[1])
        .expect("the followed window's full-resync marker");
    let connection = SyncConnection::new(
        device.manager(),
        ConnectionConfig {
            client_config: SyncClientConfig {
                server_url: url,
                residence_mode: SyncResidenceMode::Opened,
                residence_selector: Some(SyncSelector::new(
                    EntityId::now(),
                    EntityId::now(),
                    SyncSelectorWorld::All,
                    Vec::new(),
                    Vec::new(),
                )),
                note_session: Some(note_session(&device)),
                ..SyncClientConfig::default()
            },
            auto_reconnect: false,
        },
    )
    .expect("the device's connection");
    connection
        .set_followed_worlds([device.founder].into_iter().collect())
        .expect("the owner's pick");
    let (shutdown, shutdown_rx) = oneshot::channel();
    let (sync_tx, sync) = mpsc::unbounded_channel();
    let run = connection.run_observed(shutdown_rx, move |event| {
        let _ = sync_tx.send(event);
    });
    let mut watch = Watch {
        home,
        sync,
        home_seen: Vec::new(),
        sync_seen: Vec::new(),
    };
    let script = async {
        watch
            .until(
                "the device asks the home for the marked followed window's replacement",
                |home, _| {
                    world_asks(home, 1).contains(&(
                        founder.as_str().to_owned(),
                        window_sub_tags::REPLACEMENT_REQUEST,
                    ))
                },
            )
            .await;
        assert!(
            world_asks(&watch.home_seen, 1)
                .contains(&(founder.as_str().to_owned(), window_sub_tags::FOLLOW_REQUEST,)),
            "the window was asked as a follow first",
        );
        // The fake home answers no replacement; the run may have ended.
        let _ = shutdown.send(());
    };
    let (_ran, ()) = tokio::join!(run, script);
}
