//! The automatic producer of the bodies a confirmed staged import still owes
//! (FIX 12408).
//!
//! The owner attaches a host-registered producer to a receipt
//! ([`SyncClient::attach_staged_vault_import_body_source`]): the source home
//! that serves the artifact's window to this vault. The steady loop then
//! runs one pass at a time. A pass opens a short-lived socket to that home,
//! off the loop, which proves the producer's slip on the upgrade and binds
//! its actor; this client then asks the home to authorize the artifact's
//! window under the producer's grant selector. The home answers with the copy
//! that selector admits, and serves the bodies of that copy's rows on this
//! socket alone. The copy only authorizes the transfer: it is never
//! imported.
//!
//! This client asks there for each body the work owes in the artifact's own
//! window, one at a time, through the usual body session on the receipt's
//! federated lane. A body lands at the receipt's tier through the usual
//! landing door, under the confirmation's lock, and only while the work
//! still owes it under the same attachment: a cancellation, an erase, or a
//! new attachment stops the pass. Its birth releases the stamps the receipt
//! held for its row, and the text the part carried for that row is kept.
//! A pass ends when nothing it can fetch is owed, when its source refuses
//! or defers, when its socket goes, or when no body data comes for a while;
//! what it did not land stays owed for the next pass, a supplied delivery,
//! or a cancellation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use super::base::SyncClient;
use super::federated::map_federated_admission_err;
use super::staged_bodies::confirmed_receipt;
use super::types::StagedImportBodySource;
use crate::EntityId;
use crate::batch::export::{
    StagedImportBodyWork, StagedWindowPart, attached_staged_import_body_work,
    decode_staged_import_parts, staged_import_body_work, vault_import_staged_content,
};
use crate::sync::asset_body::session::{
    ASSET_BODY_FRAMES_PER_POLL, AssetBodyLane, AssetBodySession, with_manager_peer,
};
use crate::sync::selector::{
    CarriedText, encode_selector_vv_request, keep_carried_born_with, release_staged_landed_stamps,
    revalidate_admitted_facet_stamps, revalidate_admitted_federated_claims,
};
use crate::sync::transport::{self, MAX_DECODED_PAYLOAD_BYTES, TransportError, window_sub_tags};
use crate::sync::types::WindowKey;

/// How long after a pass begins the next may begin.
const STAGED_BODY_PULL_RETRY: Duration = Duration::from_secs(30);

/// How long a pass waits with no bind, no copy, and no Data the current
/// attempt takes in order, before it ends.
const STAGED_BODY_PULL_IDLE: Duration = Duration::from_secs(60);

/// How long the socket to a producer may take to open.
const STAGED_BODY_SOURCE_CONNECT: Duration = Duration::from_secs(20);

/// The frames a pass's socket holds for this client before its producer
/// waits.
const STAGED_BODY_INBOUND_FRAMES: usize = 64;

/// The client's passes over the work producers are attached to.
#[derive(Default)]
pub(super) struct StagedBodyPulls {
    active: Option<StagedBodyPull>,
    /// When the next pass may begin; `None` at once.
    next: Option<Instant>,
    /// The receipt the last pass served: the next begins after it, so a
    /// receipt whose producer fails never holds the others back.
    last: Option<[u8; 32]>,
}

impl StagedBodyPulls {
    /// Lets the next pass begin at once.
    pub(super) fn wake(&mut self) {
        self.next = None;
    }
}

/// One pass over one receipt's owed bodies.
struct StagedBodyPull {
    receipt_id: [u8; 32],
    /// The producer the pass fetches from, and the work's generation when
    /// it began.
    source: [u8; 32],
    generation: u64,
    lane: AssetBodyLane,
    /// The admitted part in the artifact's own window, as the receipt's
    /// digest pins it.
    part: StagedWindowPart,
    /// The rows of that part whose bodies the work owed when it began.
    owed: Vec<EntityId>,
    /// Behind a mutex only to keep the client `Sync`; the client's own
    /// `&mut` takes it.
    session: Mutex<AssetBodySession>,
    /// The selector request, sent once the home acknowledges the bind.
    selector_request: Option<Vec<u8>>,
    /// The home served the selector's copy of the window: its bodies may be
    /// asked for.
    admitted: bool,
    idle_until: Instant,
    done: bool,
}

/// A pass the steady loop opens a socket for: the producer, and the frames
/// the socket opens with.
pub(crate) struct StagedBodyPullStart {
    source: StagedImportBodySource,
    opening: Vec<Vec<u8>>,
}

impl SyncClient {
    /// Begins the next pass that is due, over the first receipt after the
    /// last one served whose work has a registered producer attached and
    /// still owes a body in the artifact's own window. `None` when no pass
    /// is due or none can begin.
    ///
    /// # Errors
    ///
    /// Storage errors reading the work.
    pub(in crate::sync) fn begin_staged_body_pull(
        &mut self,
        now: Instant,
    ) -> std::result::Result<Option<StagedBodyPullStart>, TransportError> {
        let pulls = &self.staged_body_pulls;
        if pulls.active.is_some()
            || pulls.next.is_some_and(|next| next > now)
            || self.config.staged_import_body_sources.is_empty()
        {
            return Ok(None);
        }
        self.staged_body_pulls.next = Some(now + STAGED_BODY_PULL_RETRY);
        let last = self.staged_body_pulls.last;
        let (after, before): (Vec<_>, Vec<_>) = attached_staged_import_body_work(&self.vault)
            .map_err(map_federated_admission_err)?
            .into_iter()
            .partition(|(id, _)| last.is_some_and(|last| *id > last));
        for (receipt_id, work) in after.into_iter().chain(before) {
            match self.plan_staged_body_pull(receipt_id, &work, now) {
                Ok(Some(start)) => {
                    self.staged_body_pulls.last = Some(receipt_id);
                    return Ok(Some(start));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "staged import body pull not begun");
                }
            }
        }
        Ok(None)
    }

    /// The pass over `receipt_id`'s `work`, when its producer is registered
    /// for the receipt's source and today's policy still admits the part
    /// whose bodies it owes.
    fn plan_staged_body_pull(
        &mut self,
        receipt_id: [u8; 32],
        work: &StagedImportBodyWork,
        now: Instant,
    ) -> std::result::Result<Option<StagedBodyPullStart>, TransportError> {
        let Some(source) = work.source.and_then(|id| {
            self.config
                .staged_import_body_sources
                .iter()
                .find(|source| source.id == id)
        }) else {
            return Ok(None);
        };
        let Ok(receipt) = confirmed_receipt(&self.vault, &receipt_id) else {
            return Ok(None);
        };
        if source.serves != receipt.source {
            return Ok(None);
        }
        let Some(window) = WindowKey::try_new(&receipt.window_key) else {
            return Ok(None);
        };
        // Only the part in the artifact's own window: its rows, ASSETs
        // among them, are the source's under their own ids there. A body
        // owed in a part routed elsewhere stays for a supplied delivery.
        let owed: Vec<EntityId> = work
            .owed
            .iter()
            .filter(|body| body.window == window.as_str())
            .filter_map(|body| EntityId::from_bytes(body.entity).ok())
            .collect();
        if owed.is_empty() {
            return Ok(None);
        }
        let content = vault_import_staged_content(&self.vault, &receipt_id)
            .map_err(map_federated_admission_err)?
            .ok_or(TransportError::Storage(
                "staged import content missing".into(),
            ))?;
        if receipt.admitted_update_digest != Some(*blake3::hash(&content).as_bytes()) {
            return Err(TransportError::InvalidPayload(
                "admitted update digest mismatch",
            ));
        }
        let Some(part) = decode_staged_import_parts(&content)
            .map_err(map_federated_admission_err)?
            .into_iter()
            .find(|part| part.key == window)
        else {
            return Ok(None);
        };
        // Today's policy for the admitted part, as the confirmation checked
        // it: a part it now refuses fetches nothing.
        revalidate_admitted_federated_claims(&self.vault, &window, &part.update, receipt.role)
            .and_then(|()| revalidate_admitted_facet_stamps(&window, &part.update))
            .map_err(map_federated_admission_err)?;
        let selector = encode_selector_vv_request(&source.selector, &[])
            .map_err(|_| TransportError::InvalidPayload("sync selector request encode failed"))?;
        let selector_request = transport::encode_window_sync(
            window.as_str(),
            window_sub_tags::SELECTOR_VV_REQUEST,
            &selector,
        )
        .into_result()?;
        let opening = vec![
            transport::encode_protocol_hello(),
            super::note_session::bind_frame(&source.note_session)?,
        ];
        let source = source.clone();
        self.ensure_window(window.as_str())?;
        self.staged_body_pulls.active = Some(StagedBodyPull {
            receipt_id,
            source: source.id,
            generation: work.generation,
            lane: AssetBodyLane::FederationReceive { role: receipt.role },
            part,
            owed,
            session: Mutex::default(),
            selector_request: Some(selector_request),
            admitted: false,
            idle_until: now + STAGED_BODY_PULL_IDLE,
            done: false,
        });
        Ok(Some(StagedBodyPullStart { source, opening }))
    }

    /// Takes one frame the pass's producer sent, and answers the frames to
    /// send it. A refusal ends the pass ([`Self::staged_body_pull_done`]).
    pub(in crate::sync) fn handle_staged_body_frame(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        match self.staged_body_frame(frame) {
            Ok(out) => out,
            Err(error) => {
                tracing::warn!(%error, "staged import body pull stopped");
                if let Some(pull) = &mut self.staged_body_pulls.active {
                    pull.done = true;
                }
                Vec::new()
            }
        }
    }

    fn staged_body_frame(
        &mut self,
        frame: &[u8],
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        let Some((&tag, payload)) = frame.split_first() else {
            return Ok(Vec::new());
        };
        let Some(pull) = self.staged_body_pulls.active.as_mut() else {
            return Ok(Vec::new());
        };
        if pull.done {
            return Ok(Vec::new());
        }
        match tag {
            transport::TAG_RPC if pull.selector_request.is_some() => {
                super::note_session::accept_bind_reply(payload)?;
                pull.idle_until = Instant::now() + STAGED_BODY_PULL_IDLE;
                Ok(pull.selector_request.take().into_iter().collect())
            }
            transport::TAG_WINDOW_SYNC => {
                let (key, sub_tag, _) = transport::decode_window_sync(payload)?;
                if key != pull.part.key.as_str() {
                    return Ok(Vec::new());
                }
                match sub_tag {
                    window_sub_tags::UPDATE if !pull.admitted => {
                        pull.admitted = true;
                        pull.idle_until = Instant::now() + STAGED_BODY_PULL_IDLE;
                        self.owe_staged_pull_bodies()?;
                        Ok(self.poll_staged_body_pull(Instant::now()))
                    }
                    // The home defers the selector's copy: this pass ends,
                    // and the next asks again.
                    window_sub_tags::SELECTOR_DEFERRED => {
                        pull.done = true;
                        Ok(Vec::new())
                    }
                    _ => Ok(Vec::new()),
                }
            }
            transport::TAG_ASSET_BODY_WANT..=transport::TAG_ASSET_BODY_RECEIPT if pull.admitted => {
                self.staged_body_transfer_frame(tag, payload)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Owes the pass's bodies in its session as the digest-pinned admitted
    /// part names them, never as the live window does: the session asks for
    /// a body, and its landing takes it, only while the live window still
    /// binds that same body, so a newer copy that replaced it is never
    /// fetched or landed under this receipt.
    fn owe_staged_pull_bodies(&mut self) -> std::result::Result<(), TransportError> {
        let Some(key) = self
            .staged_body_pulls
            .active
            .as_ref()
            .map(|pull| pull.part.key.clone())
        else {
            return Ok(());
        };
        // The session reads the live window through the manager's loaded
        // windows.
        self.ensure_window(key.as_str())?;
        let Some(pull) = self.staged_body_pulls.active.as_mut() else {
            return Ok(());
        };
        let admitted = crate::sync::schema::create_window_doc("federation-staged-bodies", &key);
        admitted
            .import(&pull.part.update)
            .map_err(|_| TransportError::InvalidPayload("admitted body references unreadable"))?;
        let session = pull
            .session
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let owed = &pull.owed;
        with_manager_peer(&self.manager, pull.lane, None, |peer| {
            session.note_rows(peer, &key, &admitted, owed)
        })
    }

    /// The frames the pass sends its producer now: the next Want once no
    /// body comes in. A pass whose session owes nothing more is done.
    pub(in crate::sync) fn poll_staged_body_pull(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let Some(pull) = self.staged_body_pulls.active.as_mut() else {
            return Vec::new();
        };
        if !pull.admitted || pull.done {
            return Vec::new();
        }
        let session = pull
            .session
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let out = with_manager_peer(&self.manager, pull.lane, None, |peer| {
            session.poll(
                peer,
                now,
                ASSET_BODY_FRAMES_PER_POLL,
                MAX_DECODED_PAYLOAD_BYTES,
            )
        })
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "staged import body poll failed");
            Vec::new()
        });
        if pull
            .session
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .settled()
        {
            pull.done = true;
        }
        out
    }

    /// One body frame from the producer. An End lands its body: under the
    /// confirmation's lock, and only while the work still owes under this
    /// pass's attachment; the stamps its birth frees are released and the
    /// part's text for its row kept before the lock goes.
    fn staged_body_transfer_frame(
        &mut self,
        tag: u8,
        payload: &[u8],
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        let vault = Arc::clone(&self.vault);
        let _guard = if tag == transport::TAG_ASSET_BODY_END {
            let guard = vault
                .store
                .staged_import_confirm_lock
                .lock()
                .map_err(|_| TransportError::Storage("staged import lock poisoned".into()))?;
            if !self.staged_pull_still_owed()? {
                if let Some(pull) = &mut self.staged_body_pulls.active {
                    pull.done = true;
                }
                return Ok(Vec::new());
            }
            Some(guard)
        } else {
            None
        };
        let Some(pull) = self.staged_body_pulls.active.as_mut() else {
            return Ok(Vec::new());
        };
        let session = pull
            .session
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let before = session.receiving_bytes();
        let (mut out, births, advanced) =
            with_manager_peer(&self.manager, pull.lane, None, |peer| {
                let out = session.handle_frame(peer, tag, payload)?;
                // Only Data the current attempt took in order keeps the pass
                // alive; any other frame leaves its idle deadline as it was.
                let advanced = tag == transport::TAG_ASSET_BODY_DATA
                    && before.is_some_and(|before| {
                        session
                            .receiving_bytes()
                            .is_some_and(|after| after > before)
                    });
                Ok::<_, TransportError>((out, session.take_federated_births(), advanced))
            })?;
        if advanced {
            pull.idle_until = Instant::now() + STAGED_BODY_PULL_IDLE;
        }
        if !births.is_empty() {
            self.finish_staged_pull_births(&births)?;
        }
        out.extend(self.poll_staged_body_pull(Instant::now()));
        Ok(out)
    }

    /// Whether the pass's receipt is still confirmed and its work still owes
    /// under the attachment the pass began with.
    fn staged_pull_still_owed(&self) -> std::result::Result<bool, TransportError> {
        let Some(pull) = &self.staged_body_pulls.active else {
            return Ok(false);
        };
        if confirmed_receipt(&self.vault, &pull.receipt_id).is_err() {
            return Ok(false);
        }
        Ok(staged_import_body_work(&self.vault, &pull.receipt_id)
            .map_err(map_federated_admission_err)?
            .is_some_and(|work| {
                work.source == Some(pull.source) && work.generation == pull.generation
            }))
    }

    /// Releases the stamps the receipt held for each row a landed body
    /// birthed in the pass's part, and keeps the text the part carried for
    /// it. The caller holds the confirmation's lock.
    fn finish_staged_pull_births(
        &mut self,
        births: &[(WindowKey, EntityId)],
    ) -> std::result::Result<(), TransportError> {
        let Some(pull) = &self.staged_body_pulls.active else {
            return Ok(());
        };
        let receipt_id = pull.receipt_id;
        let key = pull.part.key.clone();
        let admitted = crate::sync::schema::create_window_doc("federation-staged-bodies", &key);
        admitted
            .import(&pull.part.update)
            .map_err(|_| TransportError::InvalidPayload("admitted body references unreadable"))?;
        let entities = admitted.get_map("entities");
        let born: Vec<(EntityId, Vec<u8>)> = births
            .iter()
            .filter(|(window, _)| *window == key)
            .filter_map(|(_, id)| {
                crate::sync::loro_support::map_get_bytes(&entities, &id.to_hex())
                    .map(|carrier| (*id, carrier))
            })
            .collect();
        let carried: Vec<CarriedText> = pull
            .part
            .born_with
            .iter()
            .filter(|(id, _, _)| born.iter().any(|(row, _)| row == id))
            .cloned()
            .collect();
        for (row, carrier) in born {
            let released =
                release_staged_landed_stamps(&self.vault, &key, &receipt_id, (row, carrier))
                    .map_err(map_federated_admission_err)?;
            self.import_released_stamps(key.as_str(), released)?;
        }
        keep_carried_born_with(&self.vault, &carried).map_err(map_federated_admission_err)
    }

    /// Whether the pass is over: nothing it can fetch is owed, its producer
    /// refused or deferred, or no body data came for a while.
    pub(in crate::sync) fn staged_body_pull_done(&self, now: Instant) -> bool {
        self.staged_body_pulls
            .active
            .as_ref()
            .is_some_and(|pull| pull.done || pull.idle_until <= now)
    }

    /// Ends the pass, its socket gone or going: the work settles what came
    /// here, by this pass or any other lane, and keeps owing the rest.
    pub(in crate::sync) fn end_staged_body_pull(&mut self) {
        let Some(pull) = self.staged_body_pulls.active.take() else {
            return;
        };
        let vault = Arc::clone(&self.vault);
        let Ok(_guard) = vault.store.staged_import_confirm_lock.lock() else {
            return;
        };
        let settled = confirmed_receipt(&self.vault, &pull.receipt_id)
            .and_then(|receipt| self.deliver_staged_bodies_locked(&receipt, &HashMap::new()));
        if let Err(error) = settled {
            tracing::warn!(%error, "staged import body pull not settled");
        }
    }
}

/// The socket of one pass, run off the steady loop: it carries the frames
/// the client sends, and hands the client the frames the producer sends.
pub(crate) struct StagedBodyPump {
    task: tokio::task::JoinHandle<()>,
    outbound: mpsc::UnboundedSender<Vec<u8>>,
    inbound: mpsc::Receiver<Vec<u8>>,
}

impl StagedBodyPump {
    /// Opens `start`'s socket on its own task.
    pub(crate) fn spawn(vault: Arc<crate::Vault>, start: StagedBodyPullStart) -> Self {
        let (outbound, outbound_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound) = mpsc::channel(STAGED_BODY_INBOUND_FRAMES);
        let task = tokio::spawn(async move {
            if let Err(error) =
                pump_staged_body_source(&vault, start, outbound_rx, inbound_tx).await
            {
                tracing::warn!(%error, "staged import body source socket ended");
            }
        });
        Self {
            task,
            outbound,
            inbound,
        }
    }

    /// Queues `frames` for the producer; a socket already gone drops them.
    pub(crate) fn send(&self, frames: Vec<Vec<u8>>) {
        for frame in frames {
            if self.outbound.send(frame).is_err() {
                return;
            }
        }
    }

    /// The next frame the producer sent; `None` once the socket is gone.
    pub(crate) async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }

    /// Closes the socket and waits for its task.
    pub(crate) async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for StagedBodyPump {
    /// A run that returns early drops its pump without [`Self::stop`]: the
    /// task ends with it, a socket write it waits in included, instead of
    /// running on detached.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Runs one pass's socket to its producer until either side ends it.
async fn pump_staged_body_source(
    vault: &crate::Vault,
    start: StagedBodyPullStart,
    mut outbound: mpsc::UnboundedReceiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
) -> std::result::Result<(), String> {
    let StagedBodyPullStart { source, opening } = start;
    // FIX 8862: the producer's slip and bind leave only for a TLS endpoint,
    // a numeric loopback one, or over its private carrier.
    if !super::endpoint::admits_credentials(&source.server_url, source.mesh_dialer.is_some()) {
        return Err("staged import body source endpoint refuses credentials".to_owned());
    }
    let mut request = source
        .server_url
        .as_str()
        .into_client_request()
        .map_err(|error| error.to_string())?;
    source
        .transport_credential
        .sign_upgrade(vault, vault.store.clock.wall_now(), &mut request)
        .map_err(str::to_owned)?;
    let (socket, _) = tokio::time::timeout(
        STAGED_BODY_SOURCE_CONNECT,
        crate::sync::carrier::connect_sync_socket(request, source.mesh_dialer.as_deref()),
    )
    .await
    .map_err(|_| "staged import body source connect timed out".to_owned())?
    .map_err(|error| error.to_string())?;
    let (mut write, mut read) = socket.split();
    for frame in opening {
        write
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|error| error.to_string())?;
    }
    loop {
        tokio::select! {
            frame = outbound.recv() => match frame {
                Some(frame) => write
                    .send(Message::Binary(frame.into()))
                    .await
                    .map_err(|error| error.to_string())?,
                None => {
                    let _ = write.send(Message::Close(None)).await;
                    return Ok(());
                }
            },
            message = read.next() => match message {
                Some(Ok(Message::Binary(bytes))) => {
                    if inbound.send(bytes.to_vec()).await.is_err() {
                        return Ok(());
                    }
                }
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error.to_string()),
            },
        }
    }
}
