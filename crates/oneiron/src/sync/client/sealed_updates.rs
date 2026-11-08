//! A machine's side of the sealed world-update relay (DEC-0005 fix 8:
//! "A my-machines world on it still syncs. The cloud relays its sealed
//! updates between the owner's machines and cannot read them"; CLIP-SYNC = A,
//! FIX 12586), on its home's live socket.
//!
//! A world-window update this machine withholds from a home that may not read
//! the world goes sealed under that world's key into the outbox, when the
//! world is read on the owner's machines with sealed copies on the cloud and on
//! them. Once a home offers sealed updates on a connection, the outbox goes to
//! it, and the home stores and relays each update to the owner's other
//! machines. This machine takes every update after its cursor, opens those of
//! the worlds it reads, and imports each through its own-device window import.
//! A message past one part comes in parts, joined and checked whole against
//! its digest before it is taken. An update whose history this machine lacks
//! makes it ask the world's other readers for the window's snapshot, which it
//! installs as a window replacement that keeps its own writes. Anything the
//! relay cannot carry still rides the daily sealed bundle.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use futures_util::{Sink, SinkExt};
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

use super::SyncClient;
use crate::EntityId;
use crate::authority::{EffectiveRead, EffectiveWorldPrivacy, PeerMachine, SealedCopies};
use crate::sync::SyncEvent;
use crate::sync::residence::{
    SealedUpdateEpoch, SealedUpdateId, drop_sealed_update_outbox, put_sealed_update_cursor,
    put_sealed_update_outbox, sealed_update_cursor, sealed_update_outbox,
};
use crate::sync::transport::{
    MAX_DECODED_PAYLOAD_BYTES, SealedUpdateFrame, TAG_SEALED_UPDATE, TransportError,
    decode_sealed_update_frame, encode_sealed_update_frame,
};
use crate::sync::types::WindowKey;
use crate::sync::window::{ReplacementByteBound, Withhold, export_window_replacement_for};
use crate::world_keys::{
    OpenedWorldUpdate, SEALED_UPDATE_PART_BYTES, SealedUpdateKind, WorldKey, open_world_update,
    seal_world_message,
};

/// How long this connection reuses the world keys it opened for sealed
/// updates before it opens them again.
const KEY_CACHE: Duration = Duration::from_secs(60);
/// How soon an update no cached key opens makes this connection open its
/// keys again, for a key minted since.
const KEY_REFRESH_FLOOR: Duration = Duration::from_secs(1);
/// How often a connection asks its home again for what it may have missed,
/// and offers again the outbox updates the home has not said it stored.
const SINCE_EVERY: Duration = Duration::from_secs(300);
/// How long a catch-up may go unanswered before a gap may ask again.
const CATCH_UP_PATIENCE: Duration = Duration::from_secs(60);
/// The most outbox parts one send offers.
const OUTBOX_SEND_BATCH: usize = 64;
/// The most sealed bytes one send offers, past its first part.
const OUTBOX_SEND_BYTES: usize = 16 * 1024 * 1024;
/// How long a window's snapshot want waits for an answer before an update
/// that still lacks its history may ask again.
const WANT_PATIENCE: Duration = Duration::from_secs(300);
/// The most bytes of unfinished multipart messages this machine holds at
/// once; a part past it drops its message (Engine call CLIP-SYNC relay
/// multipart bound, CALLS.md).
const SEALED_ASSEMBLY_MAX_BYTES: usize = 1024 * 1024 * 1024;
/// How long an unfinished multipart message waits for its other parts.
const SEALED_ASSEMBLY_PATIENCE: Duration = Duration::from_secs(600);

// A part, its envelope and its frame's own fields fit one frame.
const _: () = assert!(SEALED_UPDATE_PART_BYTES + 4096 <= MAX_DECODED_PAYLOAD_BYTES);

/// This connection's place in the relay: whether and under which epoch its
/// home offered, what it sent, a catch-up in flight, and the world keys it
/// opened, started again at every connect; and, kept across connects, the
/// snapshots this machine asked for and the multipart messages it is joining.
#[derive(Default)]
pub(super) struct SealedUpdateSession {
    offered: Option<SealedUpdateEpoch>,
    sent: HashSet<SealedUpdateId>,
    catching_up: Option<Instant>,
    last_since: Option<Instant>,
    keys: Option<(Instant, Vec<WorldKey>)>,
    /// Windows whose snapshot this machine asked the world's other readers
    /// for, and when.
    wanted: HashMap<String, Instant>,
    /// Multipart messages this machine holds some parts of.
    parted: HashMap<PartedMessage, PartAssembly>,
}

impl SealedUpdateSession {
    /// Starts a connection's place again, keeping the snapshot wants and the
    /// messages being joined: a part the last connection took has passed the
    /// cursor, so it comes no second time.
    pub(super) fn restart(&mut self) {
        *self = Self {
            wanted: std::mem::take(&mut self.wanted),
            parted: std::mem::take(&mut self.parted),
            ..Self::default()
        };
    }
}

/// One multipart message: its kind, window and digest.
type PartedMessage = (SealedUpdateKind, String, [u8; 32]);

/// The parts of one message this machine holds.
struct PartAssembly {
    count: u32,
    chunks: BTreeMap<u32, Zeroizing<Vec<u8>>>,
    bytes: usize,
    started: Instant,
}

/// One whole message the relay carried, joined from its parts.
struct SealedMessage {
    world: EntityId,
    kind: SealedUpdateKind,
    window_key: String,
    bytes: Zeroizing<Vec<u8>>,
}

/// Whether `privacy` sends a world's updates sealed through a home that may
/// not read it: read on the owner's machines, with sealed copies on the cloud
/// and on them (CLIP-SYNC = A). A world read on one machine, or whose sealed
/// copies stay off the cloud, never goes through the relay (Engine call
/// CLIP-SYNC relay eligibility, CALLS.md).
#[must_use]
pub(crate) fn world_relays_sealed(privacy: &EffectiveWorldPrivacy) -> bool {
    privacy.read == EffectiveRead::MyMachines && privacy.sealed == SealedCopies::CloudAndMyMachines
}

fn frame(frame: &SealedUpdateFrame<'_>) -> Vec<u8> {
    encode_sealed_update_frame(frame)
}

impl SyncClient {
    /// The withheld-update hook: `update` of `window_key`, which this machine
    /// keeps from its home, goes sealed into the outbox when its world relays
    /// sealed and this machine has met a home that takes sealed updates. Any
    /// other update is left to the daily sealed bundle, as before. A fault is
    /// logged, never the caller's.
    pub(crate) fn relay_withheld_update(&self, window_key: &str, update: &[u8]) {
        if self.config.federation_peer.is_some() {
            return;
        }
        if let Err(error) = self.keep_sealed_update(window_key, update) {
            tracing::warn!(%error, "sealed world update not kept for the relay");
        }
    }

    fn keep_sealed_update(&self, window_key: &str, update: &[u8]) -> crate::error::Result<()> {
        let Some(world) = WindowKey::try_new(window_key).and_then(|key| key.world()) else {
            return Ok(());
        };
        if sealed_update_cursor(&self.vault)?.is_none() {
            return Ok(());
        }
        self.keep_sealed_message(world, SealedUpdateKind::Update, window_key, update)
    }

    /// Seals one message of `kind` for `window_key` of `world` into the
    /// outbox, while the world relays sealed.
    fn keep_sealed_message(
        &self,
        world: EntityId,
        kind: SealedUpdateKind,
        window_key: &str,
        bytes: &[u8],
    ) -> crate::error::Result<()> {
        if !world_relays_sealed(&self.vault.world_privacy(world)?) {
            return Ok(());
        }
        let key = self.vault.world_key(world)?;
        let vault_id = self.vault.sealed_update_vault_id()?;
        for part in seal_world_message(&vault_id, &key, kind, window_key, bytes)? {
            put_sealed_update_outbox(&self.vault, &part.id, world, &part.sealed)?;
        }
        Ok(())
    }

    /// One sealed update frame from the home, the bytes after its tag: the
    /// frames to send back.
    ///
    /// # Errors
    /// [`TransportError::UnknownTag`] on a federation lane; a frame that does
    /// not decode, or one only a machine sends; [`TransportError::Storage`]
    /// where the cursor or the outbox could not be read or written.
    pub(super) fn handle_sealed_update_frame(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        if self.config.federation_peer.is_some() {
            return Err(TransportError::UnknownTag(TAG_SEALED_UPDATE));
        }
        let storage = |error: crate::error::Error| TransportError::Storage(error.to_string());
        let cursor = sealed_update_cursor(&self.vault).map_err(storage)?;
        match decode_sealed_update_frame(payload)? {
            SealedUpdateFrame::Offer { epoch, .. } => {
                if cursor.is_none_or(|(held, _)| held != epoch) {
                    put_sealed_update_cursor(&self.vault, &epoch, 0).map_err(storage)?;
                }
                // The catch-up and the outbox go at the steady loop's first
                // housekeeping tick, never inside the connect's first burst.
                self.sealed_updates.restart();
                self.sealed_updates.offered = Some(epoch);
                Ok(Vec::new())
            }
            SealedUpdateFrame::Entry { epoch, seq, sealed } => {
                let Some((held, last)) = cursor else {
                    return Ok(Vec::new());
                };
                if held == epoch && Some(seq) == last.checked_add(1) {
                    let answers = self.take_sealed_update(sealed);
                    put_sealed_update_cursor(&self.vault, &epoch, seq).map_err(storage)?;
                    return Ok(answers);
                }
                // A live update past a gap, or under another epoch: ask for
                // what lies between, once per catch-up.
                let asking = self
                    .sealed_updates
                    .catching_up
                    .is_none_or(|at| at.elapsed() > CATCH_UP_PATIENCE);
                if (held != epoch || seq > last) && asking {
                    self.sealed_updates.catching_up = Some(Instant::now());
                    return Ok(vec![frame(&SealedUpdateFrame::Since {
                        epoch: held,
                        after: last,
                    })]);
                }
                Ok(Vec::new())
            }
            SealedUpdateFrame::PageEntry { epoch, seq, sealed } => {
                let last = match cursor {
                    Some((held, last)) if held == epoch => last,
                    _ => 0,
                };
                let mut answers = Vec::new();
                if seq > last {
                    answers = self.take_sealed_update(sealed);
                    put_sealed_update_cursor(&self.vault, &epoch, seq).map_err(storage)?;
                }
                Ok(answers)
            }
            SealedUpdateFrame::CaughtUp {
                epoch,
                through,
                more,
            } => {
                let behind = match cursor {
                    Some((held, last)) if held == epoch => through > last,
                    _ => true,
                };
                if behind {
                    put_sealed_update_cursor(&self.vault, &epoch, through).map_err(storage)?;
                }
                if more {
                    self.sealed_updates.catching_up = Some(Instant::now());
                    return Ok(vec![frame(&SealedUpdateFrame::Since {
                        epoch,
                        after: through,
                    })]);
                }
                self.sealed_updates.catching_up = None;
                Ok(Vec::new())
            }
            SealedUpdateFrame::Stored { id, epoch, seq } => {
                drop_sealed_update_outbox(&self.vault, &id).map_err(storage)?;
                self.sealed_updates.sent.remove(&id);
                // The home pushes this machine's own update to the others
                // only: the cursor passes it here, so the next live update
                // is not a gap.
                if let Some((held, last)) = cursor
                    && held == epoch
                    && Some(seq) == last.checked_add(1)
                {
                    put_sealed_update_cursor(&self.vault, &epoch, seq).map_err(storage)?;
                }
                Ok(Vec::new())
            }
            SealedUpdateFrame::Since { .. } | SealedUpdateFrame::Put { .. } => Err(
                TransportError::InvalidPayload("a machine's sealed update frame from the home"),
            ),
        }
    }

    /// Opens `sealed` under a key of a world this machine reads and takes
    /// its message once whole; a part of a world it does not read is passed
    /// over. A fault is logged: the daily sealed bundle still carries the
    /// world, and an update that still lacks its history asks again. Returns
    /// what answers a sealed window update deferred here that its import let
    /// in (FIX 10474), for the home on this connection.
    fn take_sealed_update(&mut self, sealed: &[u8]) -> Vec<Vec<u8>> {
        let mut answers = Vec::new();
        if let Err(error) = self.import_sealed_update(sealed, &mut answers) {
            tracing::warn!(%error, "sealed world update not taken");
        }
        answers
    }

    fn import_sealed_update(
        &mut self,
        sealed: &[u8],
        answers: &mut Vec<Vec<u8>>,
    ) -> Result<(), String> {
        let vault_id = self
            .vault
            .sealed_update_vault_id()
            .map_err(|error| error.to_string())?;
        let mut opened = open_world_update(&vault_id, self.sealed_update_keys(KEY_CACHE)?, sealed)
            .map_err(|error| error.to_string())?;
        if opened.is_none() {
            opened = open_world_update(
                &vault_id,
                self.sealed_update_keys(KEY_REFRESH_FLOOR)?,
                sealed,
            )
            .map_err(|error| error.to_string())?;
        }
        let Some(opened) = opened else {
            return Ok(());
        };
        if WindowKey::try_new(&opened.window_key).and_then(|key| key.world())
            != Some(opened.world())
        {
            return Err("a sealed update's window is not its key's world".to_owned());
        }
        let Some(message) = self.join_sealed_part(opened)? else {
            return Ok(());
        };
        let SealedMessage {
            world,
            kind,
            window_key,
            bytes,
        } = message;
        let window_key = window_key.as_str();
        match kind {
            // A want this machine made itself, back from the home's page, is
            // left for the world's other readers.
            SealedUpdateKind::Want if self.sealed_updates.wanted.contains_key(window_key) => Ok(()),
            SealedUpdateKind::Want => self.answer_sealed_want(world, window_key),
            SealedUpdateKind::Snapshot => self.install_sealed_snapshot(window_key, &bytes),
            SealedUpdateKind::Update => {
                // An update whose history this machine lacks waits for a
                // reader's snapshot instead: imported out of order it would
                // stay pending and hold back the window's later updates.
                if !self.sealed_update_ready(window_key, &bytes)? {
                    self.want_sealed_snapshot(world, window_key);
                    return Ok(());
                }
                self.import_sealed_window(window_key, &bytes, answers)
                    .inspect_err(|_| self.want_sealed_snapshot(world, window_key))
            }
        }
    }

    /// Joins `part` with the other parts of its message: the whole message
    /// once every part is here and the parts hash to its digest, `None` while
    /// some are missing. A message whose parts disagree on their count, or
    /// that would take this machine past [`SEALED_ASSEMBLY_MAX_BYTES`] of
    /// unfinished messages, is dropped.
    fn join_sealed_part(
        &mut self,
        part: OpenedWorldUpdate,
    ) -> Result<Option<SealedMessage>, String> {
        let world = part.world();
        let OpenedWorldUpdate {
            kind,
            window_key,
            digest,
            index,
            count,
            chunk,
            ..
        } = part;
        let whole = |bytes: Zeroizing<Vec<u8>>, window_key: String| {
            if blake3::hash(&bytes).as_bytes() != &digest {
                return Err("a sealed message does not hash to its digest".to_owned());
            }
            Ok(Some(SealedMessage {
                world,
                kind,
                window_key,
                bytes,
            }))
        };
        if count == 1 {
            return whole(chunk, window_key);
        }
        let parted = &mut self.sealed_updates.parted;
        parted.retain(|_, held| held.started.elapsed() < SEALED_ASSEMBLY_PATIENCE);
        let held: usize = parted.values().map(|held| held.bytes).sum();
        let message = (kind, window_key, digest);
        let assembly = parted
            .entry(message.clone())
            .or_insert_with(|| PartAssembly {
                count,
                chunks: BTreeMap::new(),
                bytes: 0,
                started: Instant::now(),
            });
        if assembly.chunks.contains_key(&index) {
            return Ok(None);
        }
        let refused = if assembly.count != count {
            Some("a sealed message's parts disagree on their count")
        } else if held + chunk.len() > SEALED_ASSEMBLY_MAX_BYTES {
            Some("a sealed message past the bound of unfinished messages")
        } else {
            assembly.bytes += chunk.len();
            assembly.chunks.insert(index, chunk);
            None
        };
        if let Some(reason) = refused {
            parted.remove(&message);
            return Err(reason.to_owned());
        }
        if parted
            .get(&message)
            .is_none_or(|assembly| assembly.chunks.len() < count as usize)
        {
            return Ok(None);
        }
        let Some(assembly) = parted.remove(&message) else {
            return Ok(None);
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(assembly.bytes));
        for chunk in assembly.chunks.values() {
            bytes.extend_from_slice(chunk);
        }
        whole(bytes, message.1)
    }

    /// Imports one opened update of `window_key`. The relay proves the sealer
    /// held the world's key, not which machine it was: the bytes take the
    /// import a tier with no connection takes. Bytes the import refused stay
    /// nowhere, so no later world import on this connection waits behind
    /// them. What answers a deferred sealed update the import let in goes
    /// into `answers` (FIX 10474).
    fn import_sealed_window(
        &mut self,
        window_key: &str,
        bytes: &[u8],
        answers: &mut Vec<Vec<u8>>,
    ) -> Result<(), String> {
        let imported = self.import_own_device_window_update(
            window_key,
            bytes,
            PeerMachine::Unknown,
            Some(answers),
        );
        if imported.is_err() {
            self.staged_world_updates.retain(|(key, staged, _)| {
                key.as_str() != window_key || staged.as_slice() != bytes
            });
        }
        imported.map_err(|error| error.to_string())
    }

    /// Installs a reader's snapshot of `window_key` as the window's
    /// replacement, which keeps this machine's own writes past it: when this
    /// machine asked for it, or when it holds operations this machine lacks.
    /// A snapshot cannot be merged into a window that holds operations: each
    /// change past its shallow root would wait on the history it leaves out.
    /// The want ends once the replacement is in.
    fn install_sealed_snapshot(&mut self, window_key: &str, snapshot: &[u8]) -> Result<(), String> {
        let asked = self.sealed_updates.wanted.contains_key(window_key);
        if !asked && !self.sealed_snapshot_is_news(window_key, snapshot)? {
            return Ok(());
        }
        let key = WindowKey::try_new(window_key)
            .ok_or_else(|| "a sealed snapshot of no window".to_owned())?;
        let evidence = self
            .staged_entity_evidence()
            .map_err(|error| error.to_string())?;
        // Judged again once no demotion holds the window closed.
        let (window, conflicts) = self
            .manager
            .replace_window_bounded(
                &key,
                snapshot,
                &evidence,
                || {
                    self.full_window_exchange_allowed(window_key)
                        .unwrap_or(false)
                },
                ReplacementByteBound::NetworkFrame,
                crate::sync::window::QueuedSends::Retire,
                None,
            )
            .map_err(|error| error.to_string())?;
        drop(window);
        if !conflicts.is_empty() {
            let _ = self.event_tx.send(SyncEvent::ReplacementConflicts {
                window_key: window_key.to_owned(),
                conflicts,
            });
        }
        // What the home held of the old window witnesses nothing about the
        // new one.
        self.server_vvs.remove(window_key);
        self.sealed_updates.wanted.remove(window_key);
        Ok(())
    }

    /// Whether `snapshot` holds an operation this machine's copy of
    /// `window_key` lacks.
    fn sealed_snapshot_is_news(
        &mut self,
        window_key: &str,
        snapshot: &[u8],
    ) -> Result<bool, String> {
        let Ok(meta) = loro::LoroDoc::decode_import_blob_meta(snapshot, true) else {
            return Ok(false);
        };
        let window = self
            .ensure_window(window_key)
            .map_err(|error| error.to_string())?;
        Ok(!window.doc.oplog_vv().includes_vv(&meta.partial_end_vv))
    }

    /// Whether this machine's copy of `window_key` holds every operation
    /// `update` stands on. A snapshot stands on nothing.
    fn sealed_update_ready(&mut self, window_key: &str, update: &[u8]) -> Result<bool, String> {
        let Ok(meta) = loro::LoroDoc::decode_import_blob_meta(update, true) else {
            return Ok(false);
        };
        if meta.mode != loro::EncodedBlobMode::Updates {
            return Ok(true);
        }
        let window = self
            .ensure_window(window_key)
            .map_err(|error| error.to_string())?;
        Ok(window.doc.oplog_vv().includes_vv(&meta.partial_start_vv))
    }

    /// Asks the world's other readers for `window_key`'s snapshot: a sealed
    /// want, unique per ask so the home stores and relays each one. A want
    /// waits [`WANT_PATIENCE`] for its answer before the window asks again.
    fn want_sealed_snapshot(&mut self, world: EntityId, window_key: &str) {
        let waiting = self
            .sealed_updates
            .wanted
            .get(window_key)
            .is_some_and(|at| at.elapsed() < WANT_PATIENCE);
        if waiting {
            return;
        }
        self.sealed_updates
            .wanted
            .insert(window_key.to_owned(), Instant::now());
        let mut ask = [0u8; 16];
        let kept = match crate::key_material::os_fill(&mut ask) {
            Ok(()) => self.keep_sealed_message(world, SealedUpdateKind::Want, window_key, &ask),
            Err(error) => Err(error.into()),
        };
        if let Err(error) = kept {
            tracing::warn!(%error, "sealed snapshot want not kept");
        }
    }

    /// Answers another reader's want with this machine's replacement snapshot
    /// of `window_key`, the history-free one its home would send a peer
    /// behind the floor, after the same scrubs, when it holds any of the
    /// window. Only a holder of the world's key opens it, so it withholds no
    /// world the grant covers.
    fn answer_sealed_want(&mut self, world: EntityId, window_key: &str) -> Result<(), String> {
        let key = WindowKey::try_new(window_key)
            .ok_or_else(|| "a sealed want of no window".to_owned())?;
        let window = self
            .ensure_window(window_key)
            .map_err(|error| error.to_string())?;
        if window.doc.oplog_vv().iter().next().is_none() {
            return Ok(());
        }
        let snapshot =
            export_window_replacement_for(&self.vault, &key, &window.doc, None, Withhold::Nothing)
                .map_err(|error| error.to_string())?;
        drop(window);
        let Some(snapshot) = snapshot else {
            return Ok(());
        };
        self.keep_sealed_message(world, SealedUpdateKind::Snapshot, window_key, &snapshot)
            .map_err(|error| error.to_string())
    }

    /// The world keys this machine opens of the worlds it reads now, opened
    /// again once older than `fresh`.
    fn sealed_update_keys(&mut self, fresh: Duration) -> Result<&[WorldKey], String> {
        let stale = self
            .sealed_updates
            .keys
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= fresh);
        if stale {
            let keys = self
                .vault
                .bundle_reader_keys(None, false)
                .map_err(|error| error.to_string())?;
            self.sealed_updates.keys = Some((Instant::now(), keys));
        }
        Ok(self
            .sealed_updates
            .keys
            .as_ref()
            .map_or(&[][..], |(_, keys)| keys.as_slice()))
    }

    /// The outbox updates not sent on this connection, once its home offered,
    /// each of a world that still relays sealed; an update whose world no
    /// longer does leaves the outbox.
    fn sealed_update_puts_due(&mut self) -> Vec<Vec<u8>> {
        if self.sealed_updates.offered.is_none() {
            return Vec::new();
        }
        let rows = match sealed_update_outbox(
            &self.vault,
            OUTBOX_SEND_BATCH + self.sealed_updates.sent.len(),
        ) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "sealed update outbox read failed");
                return Vec::new();
            }
        };
        let mut frames = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            if frames.len() >= OUTBOX_SEND_BATCH
                || (!frames.is_empty() && bytes + row.sealed.len() > OUTBOX_SEND_BYTES)
            {
                break;
            }
            if self.sealed_updates.sent.contains(&row.id) {
                continue;
            }
            match self.vault.world_privacy(row.world) {
                Ok(privacy) if world_relays_sealed(&privacy) => {}
                Ok(_) => {
                    if let Err(error) = drop_sealed_update_outbox(&self.vault, &row.id) {
                        tracing::warn!(%error, "sealed update outbox drop failed");
                    }
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "sealed update world settings read failed");
                    continue;
                }
            }
            bytes += row.sealed.len();
            frames.push(frame(&SealedUpdateFrame::Put {
                id: row.id,
                sealed: &row.sealed,
            }));
            self.sealed_updates.sent.insert(row.id);
        }
        frames
    }

    /// What this connection owes its home now: every [`SINCE_EVERY`], a
    /// catch-up from its cursor, with the outbox offered again from the
    /// start; and the outbox updates not yet sent.
    fn sealed_update_frames_due(&mut self) -> Vec<Vec<u8>> {
        let Some(epoch) = self.sealed_updates.offered else {
            return Vec::new();
        };
        let mut frames = Vec::new();
        let due = self
            .sealed_updates
            .last_since
            .is_none_or(|at| at.elapsed() >= SINCE_EVERY);
        let idle = self
            .sealed_updates
            .catching_up
            .is_none_or(|at| at.elapsed() > CATCH_UP_PATIENCE);
        if due && idle {
            match sealed_update_cursor(&self.vault) {
                Ok(cursor) => {
                    let after = cursor
                        .filter(|(held, _)| *held == epoch)
                        .map_or(0, |(_, after)| after);
                    frames.push(frame(&SealedUpdateFrame::Since { epoch, after }));
                    let session = &mut self.sealed_updates;
                    session.catching_up = Some(Instant::now());
                    session.last_since = Some(Instant::now());
                    session.sent.clear();
                }
                Err(error) => tracing::warn!(%error, "sealed update cursor read failed"),
            }
        }
        frames.extend(self.sealed_update_puts_due());
        frames
    }
}

/// Sends on `write`, the socket's send half, what `client` owes its home on
/// the sealed world-update relay now: the steady loop's housekeeping tick and
/// each node tick.
///
/// # Errors
///
/// A send that fails, as the loop's other sends report one.
pub(crate) async fn send_sealed_updates<S>(
    client: &mut SyncClient,
    write: &mut S,
) -> Result<(), String>
where
    S: Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    for frame in client.sealed_update_frames_due() {
        write
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|error| format!("Send failed: {error}"))?;
    }
    Ok(())
}
