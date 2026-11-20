//! The home and device of the L7-41 burst tests (`device_burst_response`,
//! `device_burst_replay`): a home on a clock the test moves, whose owner set
//! the baseline of the device's writes to the operations of one trickle
//! update a second, and the device's window, which writes TURN rows.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use loro::{ExportMode, LoroDoc};
use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::sync::WindowKey;
use oneiron::sync::federation_burst::{
    BurstPeer, DevicePeer, FederationBurstBaseline, FederationBurstOutcome, FederationBurstPolicy,
    FederationBurstReceipt,
};
use oneiron::sync::transport::{self, window_sub_tags};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub(crate) type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const SECRET: &str = "device-burst-secret";
/// The month window the rows land in: 2026-03-15 00:00 UTC.
pub(crate) const WINDOW: &str = "2026-03";
const T0: u64 = 1_773_532_800;
/// Rows in one burst: far over a baseline of one trickle update a second,
/// at any size of a fresh home.
pub(crate) const BURST_ROWS: usize = 300;
/// A device's window: it writes TURN rows of the window's month.
pub(crate) struct Device {
    _dir: tempfile::TempDir,
    vault: Vault,
    doc: LoroDoc,
    key: WindowKey,
}

impl Device {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        Self {
            _dir: dir,
            vault,
            doc: LoroDoc::new(),
            key: WindowKey::try_new(WINDOW).unwrap(),
        }
    }

    /// One update adding `rows` new TURN rows to the window, and their ids.
    pub(crate) fn rows_update(&self, rows: usize) -> (Vec<u8>, Vec<EntityId>) {
        let before = self.doc.oplog_vv();
        let ids = (0..rows).map(|_| EntityId::now()).collect::<Vec<_>>();
        for id in &ids {
            self.vault
                .put_entity(
                    id,
                    oneiron::registry::ENTITY_TYPE_TURN,
                    TimeRange { start: T0, end: T0 },
                    T0,
                    &turn_body(),
                )
                .unwrap();
        }
        let _mirrored =
            oneiron::sync::window::reverse_rematerialize(&self.vault, &self.doc, &self.key)
                .unwrap();
        self.doc.commit();
        (self.doc.export(ExportMode::updates(&before)).unwrap(), ids)
    }
}

fn turn_body() -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("role"), rmpv::Value::from("user"))]),
    )
    .unwrap();
    body
}

/// The operations an update carries, as the home's burst core counts them.
pub(crate) fn operations(update: &[u8]) -> u64 {
    let meta = LoroDoc::decode_import_blob_meta(update, true).unwrap();
    u64::try_from(meta.partial_end_vv.distance_between(&meta.partial_start_vv)).unwrap()
}

/// The home: its vault on a clock the test moves, its owner, and its server.
pub(crate) struct Home {
    _dir: tempfile::TempDir,
    pub(crate) clock: Arc<ManualClock>,
    pub(crate) now: u64,
    pub(crate) vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    pub(crate) server: Arc<SyncServer>,
    addr: SocketAddr,
    serve: tokio::task::JoinHandle<()>,
}

impl Drop for Home {
    fn drop(&mut self) {
        self.serve.abort();
    }
}

impl Home {
    /// A home whose owner set the baseline of `device`'s writes to
    /// `writes_per_sec`; a burst over it is deferred.
    pub(crate) async fn new(device: DevicePeer, writes_per_sec: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let now = oneiron_vault_contract::now_ts();
        let clock = ManualClock::new(now);
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
        let owner_id = vault.ensure_embedded_owner_actor().unwrap();
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .unwrap();
        vault
            .set_federation_burst_policy(
                &owner,
                BurstPeer::Device(&device),
                FederationBurstPolicy {
                    baseline: Some(FederationBurstBaseline {
                        name: "one trickle a second".into(),
                        writes_per_sec: f64::from(u32::try_from(writes_per_sec).unwrap()),
                        structural_streak: 1.0,
                    }),
                    unusual_rate: FederationBurstOutcome::Defer,
                    unusual_streak: FederationBurstOutcome::IsolateAndPropose,
                },
            )
            .unwrap();
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(SECRET.to_owned()),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let app = build_app(Arc::clone(&server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serve = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            _dir: dir,
            clock,
            now,
            vault,
            owner,
            server,
            addr,
            serve,
        }
    }

    /// A host-root socket on the legacy full-window lane (as
    /// `tests/window_sync_ask_drain.rs` connects), past its root snapshot. It
    /// proves no machine and binds no app credential, so its writes count
    /// against the one baseline of such sockets, [`DevicePeer::Unproven`].
    pub(crate) async fn connect_root(&self) -> WsStream {
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        let slip = self.vault.ensure_host_root_slip(&issuer).unwrap();
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = issuer
            .binding_proof(&slip, challenge.as_bytes())
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let binding =
            serde_json::json!({"timestamp":timestamp,"nonce":nonce,"signature":signature});
        let mut request = format!("ws://{}/ws", self.addr)
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {}", slip.to_token().unwrap())
                .parse()
                .unwrap(),
        );
        request
            .headers_mut()
            .insert("x-oneiron-binding", binding.to_string().parse().unwrap());
        let (mut ws, _response) = tokio_tungstenite::connect_async(request).await.unwrap();
        ws.send(Message::Binary(
            transport::encode_legacy_full_window_protocol_hello().into(),
        ))
        .await
        .unwrap();
        let _ = next_binary(&mut ws, Duration::from_secs(10)).await;
        ws
    }

    /// The owner's view of the batch `batch_ref` of `device`.
    pub(crate) fn receipt(&self, device: DevicePeer, batch_ref: &str) -> FederationBurstReceipt {
        self.vault
            .federation_burst_disposition_as_owner(
                &self.owner,
                BurstPeer::Device(&device),
                batch_ref,
            )
            .unwrap()
    }

    /// How many of `rows` the home holds.
    pub(crate) fn held_rows(&self, rows: &[EntityId]) -> usize {
        rows.iter()
            .filter(|row| self.vault.get_entity_type(row).unwrap().is_some())
            .count()
    }
}

/// The next binary frame within `wait`, or `None`.
async fn next_binary(ws: &mut WsStream, wait: Duration) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next()).await.ok()?;
        match msg
            .expect("WebSocket stream ended unexpectedly")
            .expect("WebSocket error")
        {
            Message::Binary(data) => return Some(data.to_vec()),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected WebSocket message: {other:?}"),
        }
    }
}

/// Sends `update` to the window, in its pad-free envelope (FIX 7107).
pub(crate) async fn send_update(ws: &mut WsStream, update: &[u8]) {
    let envelope = transport::WindowPadEnvelope {
        kind: transport::WindowPadKind::Update,
        form: transport::WindowPadForm::PadFree,
        queue_seq: None,
        payload: update.to_vec(),
        refs: Vec::new(),
        sidecar: None,
    };
    for frame in envelope
        .encode_frames(WINDOW, window_sub_tags::UPDATE)
        .unwrap()
    {
        ws.send(Message::Binary(frame.into())).await.unwrap();
    }
}

/// Whether the home answers the window with its version within five
/// seconds: the witness of an update it held, which a landed update on this
/// lane never gets.
pub(crate) async fn held_answer(ws: &mut WsStream) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let wait = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(frame) = next_binary(ws, wait).await else {
            return false;
        };
        if let Some((&tag, rest)) = frame.split_first()
            && tag == transport::TAG_WINDOW_SYNC
            && let Ok((key, sub_tag, _)) = transport::decode_window_sync(rest)
            && key == WINDOW
            && sub_tag == window_sub_tags::VV_RESPONSE
        {
            return true;
        }
    }
}

/// Polls `probe` for up to five seconds.
pub(crate) async fn eventually(mut probe: impl FnMut() -> bool) -> bool {
    for _ in 0..250 {
        if probe() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}
