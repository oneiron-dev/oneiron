//! In-process session registry, entry state, publish/lookup/membership doors and ref vetting.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::{ArcSwap, ArcSwapOption};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::SessionLocalReceiptLog;
use crate::session_overlay::SessionOverlay;
use crate::store::Store;

use super::types::{
    OFF_RECORD_SESSION_RECORD_VERSION, OFF_RECORD_SESSION_REF_MAX_LEN, OffRecordBackendClass,
    OffRecordMode, OffRecordSessionRecord,
};
use crate::error::OffRecordError;

/// Vault-scoped, in-process source of truth for live off-record sessions.
/// No registry row is ever serialized into the base vault.
pub(crate) struct OffRecordSessionRegistry {
    sessions: Mutex<BTreeMap<String, Arc<OffRecordSessionEntry>>>,
    published: ArcSwap<BTreeMap<String, Arc<OffRecordSessionEntry>>>,
}

pub(super) struct OffRecordSessionEntry {
    pub(super) overlay: Arc<SessionOverlay>,
    pub(super) state: Mutex<OffRecordSessionEntryState>,
    published_record: ArcSwapOption<OffRecordSessionRecord>,
}

pub(super) struct OffRecordSessionEntryState {
    pub(super) record: OffRecordSessionRecord,
    pub(super) receipt_log: Option<SessionLocalReceiptLog>,
    pub(super) post_flip_emit_log: Option<SessionLocalReceiptLog>,
    pub(super) overlay_closed: bool,
    pub(super) gone: bool,
    /// The room's conversation shell, created at SESSION ENTRY and reused for
    /// every later turn so a session reads as ONE conversation (ONE-1729,
    /// owner ruling R-20260807-02 rider 1: the shell is session-owned, one per
    /// live session enforced HERE — never minted per executor run, per verb,
    /// or per bind). Non-optional because entry is the only place it is set:
    /// a reader cannot observe a live room without one. In-memory only, so it
    /// evaporates with the process exactly as the room does.
    pub(super) overlay_shell: EntityId,
    /// Whether the overlay shell's own `Put` has been staged. Allocating the
    /// id and staging its row are separate moments — the id is minted before
    /// the write transaction opens — so a second witness must not re-put the
    /// shell it already created.
    pub(super) overlay_shell_staged: bool,
    /// The BASE conversation shell used while on record (K10). A fresh
    /// conversation allocated on the first post-flip witness and reused until
    /// flip-back. It is deliberately NOT the overlay shell: reusing that id
    /// would write a base row whose conversation is an overlay member — the
    /// taint the K4 guard exists to reject — and would link on-record turns to
    /// a room that is supposed to be invisible from base.
    pub(super) continuation_shell: Option<EntityId>,
    /// The messages of a room's stretch now in base (saved, or said while
    /// the room was on record), each with its turn and the digest of its
    /// body as said. A copy of the talk reads them back from base and keeps
    /// a message only while its body is still that one, so a message never
    /// said in the stretch, or edited since, stays out. Empty for a 1:1,
    /// which has no copy to take.
    pub(super) kept_messages: BTreeMap<EntityId, KeptMessage>,
}

/// A message of the stretch that is in base now: its turn, when it was said
/// and the digest of its body as it was said.
pub(super) struct KeptMessage {
    pub(super) turn: EntityId,
    pub(super) at: u64,
    pub(super) digest: [u8; 32],
}

impl OffRecordSessionEntryState {
    /// Notes `messages` of `turn` (each with when it was said and its body),
    /// now in base, for a copy of a room's talk.
    pub(super) fn keep_messages(&mut self, turn: EntityId, messages: &[(EntityId, u64, &[u8])]) {
        if self.record.room.is_none() {
            return;
        }
        // A retry of a message already kept changes nothing: the vault holds
        // the row as it was first written, so that is the one kept.
        for &(message, at, body) in messages {
            self.kept_messages
                .entry(message)
                .or_insert_with(|| KeptMessage {
                    turn,
                    at,
                    digest: *blake3::hash(body).as_bytes(),
                });
        }
    }

    /// When each kept message of `turn` was said.
    pub(super) fn kept_times(&self, turn: EntityId) -> Vec<u64> {
        self.kept_messages
            .values()
            .filter(|kept| kept.turn == turn)
            .map(|kept| kept.at)
            .collect()
    }
}

impl Default for OffRecordSessionRegistry {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
            published: ArcSwap::from_pointee(BTreeMap::new()),
        }
    }
}

impl OffRecordSessionEntry {
    pub(super) fn publish_state(&self, state: &OffRecordSessionEntryState) {
        let record = (!state.gone).then(|| Arc::new(state.record.clone()));
        self.published_record.store(record);
    }
}

impl OffRecordSessionRegistry {
    fn sessions(&self) -> Result<MutexGuard<'_, BTreeMap<String, Arc<OffRecordSessionEntry>>>> {
        self.sessions
            .lock()
            .map_err(|_| Error::InvariantViolation("off-record session registry mutex poisoned"))
    }

    /// `room` is `(room, started_by)` for a stretch a participant started in
    /// a room, and `None` for one the owner entered alone.
    pub(super) fn enter(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        budget_bytes: usize,
        mode: OffRecordMode,
        room: Option<(EntityId, EntityId)>,
        clock: &crate::ports::StoreClock,
    ) -> Result<Arc<OffRecordSessionEntry>> {
        let mut sessions = self.sessions()?;
        if sessions.contains_key(session_ref) {
            return Err(Error::OffRecord(
                OffRecordError::OffRecordSessionAlreadyExists {
                    session_ref: session_ref.to_owned(),
                },
            ));
        }
        let record = OffRecordSessionRecord {
            version: OFF_RECORD_SESSION_RECORD_VERSION,
            session_ref: session_ref.to_owned(),
            mode,
            backend,
            entered_at: clock.now_recorded_at(),
            promoted_turns: Vec::new(),
            closing: false,
            room: room.map(|(room, _)| *room.as_bytes()),
            started_by: room.map(|(_, by)| *by.as_bytes()),
            notices: Vec::new(),
        };
        let overlay = SessionOverlay::new(budget_bytes);
        if mode == OffRecordMode::Anonymous {
            // An anonymous read view can use the composed-read substrate but
            // must never acquire a writer, even through a lower-level door.
            overlay.seal_writes()?;
        }
        let entry = Arc::new(OffRecordSessionEntry {
            overlay,
            state: Mutex::new(OffRecordSessionEntryState {
                record: record.clone(),
                receipt_log: (mode != OffRecordMode::Anonymous)
                    .then(|| SessionLocalReceiptLog::off_record(session_ref)),
                post_flip_emit_log: None,
                overlay_closed: false,
                gone: false,
                // R-20260807-02 rider 1: the room's shell is born WITH the
                // room. Allocating it lazily made "one shell per live
                // session" a property of whoever touched it first; allocating
                // it here makes it a property of entry.
                overlay_shell: clock.entity_id()?,
                overlay_shell_staged: false,
                continuation_shell: None,
                kept_messages: BTreeMap::new(),
            }),
            published_record: ArcSwapOption::from(Some(Arc::new(record))),
        });
        sessions.insert(session_ref.to_owned(), entry.clone());
        self.published.store(Arc::new(sessions.clone()));
        Ok(entry)
    }

    pub(super) fn entry(&self, session_ref: &str) -> Result<Option<Arc<OffRecordSessionEntry>>> {
        Ok(self.sessions()?.get(session_ref).cloned())
    }

    pub(crate) fn record(&self, session_ref: &str) -> Option<OffRecordSessionRecord> {
        let sessions = self.published.load();
        sessions.get(session_ref).and_then(|entry| {
            entry
                .published_record
                .load_full()
                .map(|record| record.as_ref().clone())
        })
    }

    /// Whether `id` is a member of ANY live session overlay.
    ///
    /// The sole semantic behind both surviving egress doors (sync window
    /// packing, whole-vault export) and the K4 base-write taint guard. Reads
    /// immutable published snapshots, so it takes no registry or entry lock.
    pub(crate) fn contains_entity(&self, id: &EntityId) -> Result<bool> {
        let sessions = self.published.load();
        for entry in sessions.values() {
            if entry.published_record.load().is_some() && entry.overlay.contains_entity(id)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The live session that owns `id` as an overlay member, if any (K7).
    ///
    /// Ownership is unique by construction: conversation shells are allocated
    /// by the session that opens the room, so no id can be a member of two
    /// live overlays. Should a race expose more than one live match anyway, the
    /// first in registry iteration order wins — the door only needs to know
    /// THAT the id is session-owned, and naming any live owner refuses it.
    ///
    /// [`Self::contains_entity`] answers the same membership question for the
    /// egress doors and the taint guard, which need only a bool; the witness
    /// door reports the owning session in its typed refusal, so it needs the
    /// ref.
    pub(crate) fn owning_session_ref(&self, id: &EntityId) -> Result<Option<String>> {
        let sessions = self.published.load();
        for (session_ref, entry) in sessions.iter() {
            if entry.published_record.load().is_some() && entry.overlay.contains_entity(id)? {
                return Ok(Some(session_ref.clone()));
            }
        }
        Ok(None)
    }

    pub(crate) fn has_overlay_entities(&self) -> Result<bool> {
        let sessions = self.published.load();
        for entry in sessions.values() {
            if entry.published_record.load().is_some() && entry.overlay.has_entities()? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn remove_if_same(
        &self,
        session_ref: &str,
        expected: &Arc<OffRecordSessionEntry>,
    ) -> Result<()> {
        let mut sessions = self.sessions()?;
        match sessions.get(session_ref) {
            Some(current) if Arc::ptr_eq(current, expected) => {
                sessions.remove(session_ref);
                self.published.store(Arc::new(sessions.clone()));
                Ok(())
            }
            Some(_) => Err(Error::InvariantViolation(
                "off-record session registry entry changed during close",
            )),
            None => Err(Error::OffRecord(OffRecordError::OffRecordSessionNotFound {
                session_ref: session_ref.to_owned(),
            })),
        }
    }
}

pub(super) fn vet_off_record_session_ref(session_ref: &str) -> Result<()> {
    if session_ref.is_empty() || session_ref.len() > OFF_RECORD_SESSION_REF_MAX_LEN {
        return Err(Error::InvalidConfig(format!(
            "off-record session ref must be 1..={OFF_RECORD_SESSION_REF_MAX_LEN} bytes, got {}",
            session_ref.len()
        )));
    }
    Ok(())
}

pub(super) fn session_entry_state(
    entry: &OffRecordSessionEntry,
) -> Result<MutexGuard<'_, OffRecordSessionEntryState>> {
    entry
        .state
        .lock()
        .map_err(|_| Error::InvariantViolation("off-record session mutex poisoned"))
}

pub(super) fn live_session_entry(
    store: &Store,
    session_ref: &str,
) -> Result<Arc<OffRecordSessionEntry>> {
    store
        .off_record_sessions
        .entry(session_ref)?
        .ok_or_else(|| {
            Error::OffRecord(OffRecordError::OffRecordSessionNotFound {
                session_ref: session_ref.to_owned(),
            })
        })
}
