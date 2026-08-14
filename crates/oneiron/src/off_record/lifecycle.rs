//! OF-326 off-record / ephemeral session seam (ARCH-0052 P6, ONE-1731).
//!
//! An evaporating session mode built on ONE mechanism: session content is
//! written into the session's own [`SessionOverlay`] and never into base. The
//! seam is FOUR verbs:
//!
//! * **Enter** — [`Vault::enter_off_record_session`] creates an in-process
//!   session record and the room's overlay. The engine exposes mode and
//!   backend-class enums; the host owns all user-facing marker composition.
//! * **Mode flip** — [`Vault::set_off_record_session_mode`] seals or rearms
//!   the overlay write path. Off record, writes stage in the overlay; on
//!   record, they are ORDINARY base writes under the session's continuation
//!   shell. A flip moves only where NEW writes land; rows already in the room
//!   stay in the room.
//! * **Promote** — [`OffRecordSession::promote_turn`] replays exactly ONE
//!   witnessed turn's typed-journal closure into base on explicit user
//!   consent, in one transaction, minting a durable
//!   [`OffRecordPromoteReceipt`] that survives close (ARCH-0052 D4).
//! * **Close** — [`Vault::close_off_record_session`] drains the overlay's
//!   leases, drops the overlay, and consumes the session-local receipt log.
//!   The transcript evaporates because the rows only ever existed in the
//!   room; nothing is deleted from base, so promoted content is kept by
//!   construction rather than by an exception in a delete pass.
//!
//! Two properties follow from the one mechanism rather than from any guard:
//!
//! * **Base invisibility.** Base readers hold canonical base-only accessors,
//!   so an overlay row is not something they filter out — it is something
//!   they cannot address. Session handles read overlay ∪ base through
//!   [`crate::store::SessionStoreView`]. The reverse direction is the only
//!   one needing a door: a BASE write naming a live overlay id is refused by
//!   the K4 taint guard in `batch.rs`.
//! * **Pipeline inertness.** Dreamer, extraction and every other derived-row
//!   producer read base, so a room's turns produce no derived rows. There is
//!   no per-entity taint state to carry.
//!
//! Two EGRESS doors remain, because both enumerate ids rather than reading
//! through a session handle: sync window packing and whole-vault export. Each
//! asks [`OffRecordSessionRegistry::contains_entity`] exactly once and SKIPS
//! overlay members. Export never refuses while a session is live.
//!
//! * **Talk-only** — an outbound intent whose originating session is
//!   currently in off-record mode is rejected by the dispatch spine with
//!   the typed [`crate::Error::OffRecordTalkOnly`] (exit-prompt semantics).
//!   The OF-333 floor still classifies real egress; its gate-decision
//!   receipts are floor receipts and survive close untouched.
//! * **RECEIPTS-FOLLOW-TRANSCRIPT** — session-local receipts ride two
//!   substrates and close covers both. Retrieval-run context receipts (whose
//!   `result_ids` would betray what the room was about) are written into the
//!   session's own overlay `VaultMeta` keyspace by the retrieval-run
//!   registration site, so they evaporate with the transcript; close counts
//!   them in the pre-close census. In-memory emit-adjacent receipts (dispatch
//!   emit receipts carrying the OF-369/RS9 context field-set) ride the
//!   session's [`SessionLocalReceiptLog`] — minted via
//!   [`Vault::off_record_receipt_log`] — which close CONSUMES, so there is
//!   one close path and no emit receipt can be orphaned. Only floor
//!   receipts (gate decisions, redaction audits) persist.
//!
//! Voice: the engine has no audio intermediate layer; ASR/TTS intermediates
//! persisted by a caller during a session are overlay rows like any other, so
//! they evaporate with the room without the seam knowing their type.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::{ArcSwap, ArcSwapOption};
use serde::{Deserialize, Serialize};

use crate::ScoredEntity;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptRecord, SessionLocalReceiptLog};
use crate::session_overlay::{OverlayKeyspace, RouteTarget, SessionOverlay, SessionWriteRoute};
use crate::store::Store;

use super::promote::{FloorWrites, PromoteOutcome};

const OFF_RECORD_SESSION_RECORD_VERSION: u8 = 0;

/// Longest accepted caller-supplied opaque session ref, in bytes.
const OFF_RECORD_SESSION_REF_MAX_LEN: usize = 256;

/// Current write-routing mode of an off-record session.
///
/// The mode says where NEW writes land. It never moves rows: flipping to
/// [`OffRecordMode::OnRecord`] seals the overlay so later writes go to base,
/// and the room's earlier turns stay overlay-only until promote or close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordMode {
    OffRecord,
    OnRecord,
}

/// Backend class the disclosure-honesty line is relative to (OF-326
/// EF-316-style honesty caveat): evaporation is backend-relative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordBackendClass {
    /// Local inference: real evaporation — nothing leaves the device and
    /// nothing survives close.
    Local,
    /// Cloud or BYO-key inference: this engine persists nothing at close,
    /// but provider retention applies to what transited the provider API.
    RemoteProvider,
}

/// Read-only projection of one in-process off-record session record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordSessionRecord {
    pub version: u8,
    pub session_ref: String,
    pub mode: OffRecordMode,
    pub backend: OffRecordBackendClass,
    pub entered_at: u64,
    /// Turns promoted into base; close keeps them.
    pub promoted_turns: Vec<[u8; 16]>,
    /// Set by the first close transaction. While `true`, every mutator
    /// (promote, mode flip, emit-receipt record) rejects with
    /// [`Error::OffRecordSessionClosing`] — close drains leases and drops the
    /// overlay across several steps, and a mutation landing in that window
    /// would write into a room that is already going away.
    #[serde(default)]
    pub closing: bool,
}

/// What evaporated at close and what was kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffRecordCloseOutcome {
    /// Transcript entity puts that evaporated with the room (journal roles
    /// `TurnPut`, `MessagePartOf`, `SummaryDerivedFrom`), counted in the
    /// pre-close census. Close deletes nothing from base; these rows stopped
    /// existing because the overlay that held them did.
    pub turns_deleted: usize,
    /// Session-local retrieval-run context receipts evaporated: the count of
    /// retrieval-run receipt rows present in the overlay `VaultMeta` keyspace
    /// immediately BEFORE the overlay closes (the rows are unobservable after,
    /// and evaporation is what deletes them).
    pub context_receipts_deleted: usize,
    /// Emit-adjacent receipts dropped with the session's
    /// [`SessionLocalReceiptLog`] (RECEIPTS-FOLLOW-TRANSCRIPT).
    pub emit_receipts_deleted: usize,
    /// Emit receipts recorded after flipping the session on record.
    pub emit_receipts_retained: Vec<ReceiptRecord>,
    /// Turns promoted into base before close, left in place.
    pub promoted_turns_kept: usize,
}

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

    pub(super) fn enter(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        budget_bytes: usize,
    ) -> Result<Arc<OffRecordSessionEntry>> {
        let mut sessions = self.sessions()?;
        if sessions.contains_key(session_ref) {
            return Err(Error::OffRecordSessionAlreadyExists {
                session_ref: session_ref.to_owned(),
            });
        }
        let record = OffRecordSessionRecord {
            version: OFF_RECORD_SESSION_RECORD_VERSION,
            session_ref: session_ref.to_owned(),
            mode: OffRecordMode::OffRecord,
            backend,
            entered_at: crate::unix_seconds_now(),
            promoted_turns: Vec::new(),
            closing: false,
        };
        let entry = Arc::new(OffRecordSessionEntry {
            overlay: SessionOverlay::new(budget_bytes),
            state: Mutex::new(OffRecordSessionEntryState {
                record: record.clone(),
                receipt_log: Some(SessionLocalReceiptLog::off_record(session_ref)),
                post_flip_emit_log: None,
                overlay_closed: false,
                gone: false,
                // R-20260807-02 rider 1: the room's shell is born WITH the
                // room. Allocating it lazily made "one shell per live
                // session" a property of whoever touched it first; allocating
                // it here makes it a property of entry.
                overlay_shell: EntityId::now(),
                overlay_shell_staged: false,
                continuation_shell: None,
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
            None => Err(Error::OffRecordSessionNotFound {
                session_ref: session_ref.to_owned(),
            }),
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
        .ok_or_else(|| Error::OffRecordSessionNotFound {
            session_ref: session_ref.to_owned(),
        })
}

/// Vault-bound factory for explicit off-record session entry.
pub struct OffRecordSessionVault<'vault> {
    vault: &'vault Vault,
}

/// The room's one shell-staging claim, held while the staging attempt runs.
///
/// [`OffRecordSession::reserve_overlay_conversation_shell`] mints it;
/// [`Self::commit`] keeps the claim consumed once the shell row is durable in
/// the room. Dropping it any other way returns the claim, so a failed staging
/// attempt cannot leave the room believing a row exists that was never written.
#[must_use = "an uncommitted reservation releases the room's shell claim on drop"]
pub(crate) struct OverlayShellReservation {
    entry: Arc<OffRecordSessionEntry>,
    committed: bool,
}

impl OverlayShellReservation {
    /// Consumes the claim for good: the shell's `Put` is staged and committed.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for OverlayShellReservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Best-effort by necessity — `Drop` has no error channel. A poisoned
        // state mutex leaves the claim consumed, which is the safe direction:
        // every session accessor already fails closed on that mutex, so the
        // room is unusable rather than silently dangling.
        if let Ok(mut state) = self.entry.state.lock() {
            state.overlay_shell_staged = false;
        }
    }
}

/// Live session handle. Its borrow of the owning [`Vault`] makes it
/// impossible for safe Rust to retain a session across `StoreOwner::drop`.
pub struct OffRecordSession<'vault> {
    vault: &'vault Vault,
    session_ref: String,
    entry: Arc<OffRecordSessionEntry>,
}

/// The retrieval-run REGISTRATION DOOR a retrieval issued INSIDE a room writes
/// through, minted by [`OffRecordSession::retrieval_telemetry`] (ONE-1570 Arm
/// B). Every telemetry write of an in-room assembly — the registration, the
/// context pack's finalize, and the failure discard — goes through here.
///
/// Crate-private and inert on its own: holding one routes telemetry, never
/// content. Only the retrieval builders consume it.
///
/// It carries the CAPTURED ROUTE rather than a resolved target, and each write
/// revalidates through it. Resolving the target once at the door and handing
/// the arms a bare view was the hole: a `Base` route then collapsed to "no
/// session at all", the assembly took the canonical base door, and that door
/// holds no route to check — so a recall admitted while the room was ON RECORD
/// and flipped OFF RECORD mid-assembly published the room's `result_ids`
/// durably to base, past the K10 boundary. Both targets need the route,
/// because both of them WRITE.
pub(crate) struct SessionRetrievalTelemetry<'session> {
    vault: &'session Vault,
    route: &'session SessionWriteRoute,
}

impl SessionRetrievalTelemetry<'_> {
    /// Whether this assembly's rows stage into the room's overlay rather than
    /// the base ledger.
    ///
    /// The base-only arms of the retrieval path (K6's embed enqueue) key on
    /// THIS, never on session-boundness: an on-record room's retrieval is an
    /// ordinary base one and takes the ordinary base arms.
    pub(crate) fn stages_in_overlay(&self) -> bool {
        self.route.target() == RouteTarget::Overlay
    }

    /// Registers this assembly's retrieval-run row, provisional or published.
    pub(crate) fn register_run(
        &self,
        record: &crate::store::RetrievalRunRecord,
        provisional: bool,
    ) -> Result<()> {
        if self.stages_in_overlay() {
            return self.staged(|view, wtxn| {
                if provisional {
                    view.record_context_pack_provisional_retrieval_run_in_txn(wtxn, record)
                } else {
                    view.record_retrieval_run_in_txn(wtxn, record)
                }
            });
        }
        self.published(record.run_id, || {
            if provisional {
                self.vault
                    .store
                    .record_context_pack_provisional_retrieval_run(record)
            } else {
                self.vault.store.record_retrieval_run(record)
            }
        })
    }

    /// Clears the provisional marker and publishes the final row, against
    /// whichever target the provisional registered through.
    pub(crate) fn finalize_run(
        &self,
        run_id: crate::store::RetrievalRunId,
        elapsed_us: u64,
        claims_suppressed: usize,
        surfaced_result_ids: &[[u8; 16]],
        empty_reason: Option<String>,
    ) -> Result<()> {
        if self.stages_in_overlay() {
            return self.staged(|view, wtxn| {
                view.finalize_context_pack_retrieval_run_in_txn(
                    wtxn,
                    run_id,
                    elapsed_us,
                    claims_suppressed,
                    surfaced_result_ids,
                    empty_reason,
                )
            });
        }
        self.published(run_id, || {
            self.vault.store.finalize_context_pack_retrieval_run(
                run_id,
                elapsed_us,
                claims_suppressed,
                surfaced_result_ids,
                empty_reason,
            )
        })
    }

    /// Removes a provisional row whose assembly failed.
    ///
    /// The base arm takes no route check: a REMOVAL publishes nothing, so
    /// refusing it under a replaced route would only strand the residue the
    /// call exists to clear.
    pub(crate) fn discard_run(&self, run_id: crate::store::RetrievalRunId) -> Result<()> {
        if self.stages_in_overlay() {
            return self.staged(|view, wtxn| view.delete_retrieval_run_in_txn(wtxn, run_id));
        }
        self.vault.store.delete_retrieval_run(run_id)
    }

    /// One staged overlay write, under the captured route, revalidated INSIDE
    /// the transaction that publishes it.
    ///
    /// Base writer FIRST, then the segment permit — the overlay's own
    /// documented order, and the only one that cannot deadlock against a
    /// concurrent witness on the same room. The view is built AFTER the
    /// install so it is segment-aware: a [`crate::store::SessionStoreView`]
    /// freezes its overlay snapshot at construction, and the context pack's
    /// finalize READS its provisional row before rewriting it, so a view
    /// frozen before the segment made finalize a silent no-op that left the
    /// provisional marker standing forever.
    fn staged<F>(&self, apply: F) -> Result<()>
    where
        F: FnOnce(&crate::store::SessionStoreView<'_>, &mut heed::RwTxn<'_>) -> Result<()>,
    {
        let overlay = self.route.overlay();
        let segment = self.vault.with_write_txn(|wtxn| {
            let segment = overlay.install_txn_segment()?;
            self.route.revalidate()?;
            let view = self.vault.store.session_view(overlay.clone())?;
            apply(&view, wtxn)?;
            Ok(segment)
        })?;
        segment.commit()
    }

    /// One BASE-ledger telemetry publication, under the captured route.
    ///
    /// The base telemetry door opens its own transaction and refuses to nest,
    /// so the route cannot ride inside the publishing transaction the way
    /// `witness_with_route` puts it. It is therefore checked on BOTH sides:
    /// the pre-check refuses a room that flipped before the write, and a row
    /// that landed under a route the room replaced DURING the write is
    /// withdrawn rather than left standing — the same compensating shape the
    /// settle contract names for a failed registration. Either way the call
    /// returns the stale-route refusal; it never returns success over a row
    /// the room no longer authorizes.
    fn published(
        &self,
        run_id: crate::store::RetrievalRunId,
        write: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.route.revalidate()?;
        write()?;
        if let Err(stale) = self.route.revalidate() {
            self.vault.store.delete_retrieval_run(run_id)?;
            return Err(stale);
        }
        Ok(())
    }
}

impl<'vault> OffRecordSessionVault<'vault> {
    pub fn enter(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
    ) -> Result<OffRecordSession<'vault>> {
        let entry = self.vault.enter_off_record_session_entry(
            session_ref,
            backend,
            self.vault.config.off_record_overlay_budget_bytes,
        )?;
        Ok(OffRecordSession {
            vault: self.vault,
            session_ref: session_ref.to_owned(),
            entry,
        })
    }

    /// Acquires a handle on an ALREADY-LIVE session (ONE-1729).
    ///
    /// The host binds `off_record_session_ref` once and downstream code
    /// receives this typed handle rather than an unchecked string or a second
    /// [`Vault`] clone. Acquisition is a pure lookup: it creates no overlay,
    /// does not re-enter, does not mutate mode, and writes no base row — so a
    /// refused bind leaves no registry entry, overlay, replay row, raw
    /// output, turn, or gate decision behind.
    ///
    /// # Errors
    ///
    /// [`Error::OffRecordSessionNotFound`] for an unknown ref and
    /// [`Error::OffRecordSessionClosing`] for one whose close pass has begun
    /// or finished — the same typed refusals every other session mutator
    /// raises, so a binder cannot tell a closing room from a live one by
    /// error shape alone.
    pub fn bind(&self, session_ref: &str) -> Result<OffRecordSession<'vault>> {
        vet_off_record_session_ref(session_ref)?;
        let entry = live_session_entry(&self.vault.store, session_ref)?;
        let state = session_entry_state(&entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: session_ref.to_owned(),
            });
        }
        drop(state);
        Ok(OffRecordSession {
            vault: self.vault,
            session_ref: session_ref.to_owned(),
            entry,
        })
    }

    /// Explicit budget override used by bounded hosts and the byte-exact
    /// overlay budget contract.
    pub fn enter_with_budget(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        budget_bytes: usize,
    ) -> Result<OffRecordSession<'vault>> {
        let entry =
            self.vault
                .enter_off_record_session_entry(session_ref, backend, budget_bytes)?;
        Ok(OffRecordSession {
            vault: self.vault,
            session_ref: session_ref.to_owned(),
            entry,
        })
    }
}

impl OffRecordSession<'_> {
    #[must_use]
    pub fn session_ref(&self) -> &str {
        &self.session_ref
    }

    pub fn mode(&self) -> Result<OffRecordMode> {
        Ok(session_entry_state(&self.entry)?.record.mode)
    }

    pub fn backend_class(&self) -> Result<OffRecordBackendClass> {
        Ok(session_entry_state(&self.entry)?.record.backend)
    }

    /// Captures one snapshot for all 28 accessors, so a multi-step composed
    /// read never sees a torn overlay-base union. The returned view borrows
    /// this handle, so `close(self)` is unavailable until the view is dropped.
    pub(crate) fn read_view(&self) -> Result<crate::store::SessionStoreView<'_>> {
        self.vault.store.session_view(self.entry.overlay.clone())
    }

    pub(crate) fn overlay(&self) -> Arc<SessionOverlay> {
        self.entry.overlay.clone()
    }

    /// Mints the current mode-aware write route (K10): `Overlay` while
    /// `OffRecord`, `Base` after a flip to `OnRecord`.
    ///
    /// The mode read and the mint happen under ONE hold of the session state
    /// lock — the same lock `set_off_record_session_mode` holds across the
    /// seal/rearm and the record publication — so a route can never pair a
    /// pre-flip target with a post-flip generation. A concurrent flip that
    /// lands after the mint is caught by `SessionWriteRoute::revalidate`.
    ///
    /// On a `Base` route, session witness writes under the registry-held
    /// on-record continuation shell, never the overlay conversation id.
    pub(crate) fn write_route(&self) -> Result<SessionWriteRoute> {
        let state = session_entry_state(&self.entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            });
        }
        let target = match state.record.mode {
            OffRecordMode::OffRecord => RouteTarget::Overlay,
            OffRecordMode::OnRecord => RouteTarget::Base,
        };
        SessionWriteRoute::mint(&self.entry.overlay, target)
    }

    /// The room's conversation shell, created at session ENTRY.
    ///
    /// One shell per room, so an in-session reader sees one conversation
    /// rather than a turn-per-conversation shred. The id lives only on the
    /// in-memory record — no durable session row — so it evaporates with the
    /// process exactly as the room does.
    pub(crate) fn overlay_conversation_shell(&self) -> Result<EntityId> {
        let state = session_entry_state(&self.entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            });
        }
        Ok(state.overlay_shell)
    }

    /// Reserves the right to STAGE the overlay shell's `Put`, exactly once per
    /// room: `Some` to the first caller, `None` to every later one, so a second
    /// witness reuses the shell instead of overwriting it.
    ///
    /// The reservation is RELEASED on drop unless
    /// [`OverlayShellReservation::commit`] runs. A plain one-shot flag was
    /// consumed before the witness's fallible work, so a FAILED first witness
    /// (malformed message id, refused actor binding, exhausted overlay budget)
    /// left the room marked shell-staged with nothing staged; every later
    /// witness then staged `PartOf`/`BelongsTo` edges against a conversation id
    /// that had no entity row — a dangling journal promote would replay
    /// (ONE-1730).
    ///
    /// One window remains, and it is narrower than the reservation: a SECOND
    /// witness that reads `None` while the first is still in flight and commits
    /// before the first fails leaves the shell row unstaged until a third
    /// witness takes the released reservation. Closing that too would mean
    /// holding the session state lock across the write transaction, in the
    /// opposite order to a base writer (state -> writer) — the deadlock this
    /// seam refuses to build.
    pub(crate) fn reserve_overlay_conversation_shell(
        &self,
    ) -> Result<Option<OverlayShellReservation>> {
        let mut state = session_entry_state(&self.entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            });
        }
        if std::mem::replace(&mut state.overlay_shell_staged, true) {
            return Ok(None);
        }
        Ok(Some(OverlayShellReservation {
            entry: self.entry.clone(),
            committed: false,
        }))
    }

    /// The base conversation shell this session witnesses under while ON
    /// RECORD (K10), allocated on the first post-flip witness and reused until
    /// flip-back.
    ///
    /// Deliberately distinct from the overlay shell: witnessing an on-record
    /// turn under the overlay conversation id would write a BASE row
    /// referencing an overlay member — precisely the taint K4 rejects — and
    /// would make the private room reachable from base by following the edge.
    /// The two mode's transcripts stay separate conversations, which is what
    /// "pre-flip turns remain base-invisible" means structurally.
    pub(crate) fn on_record_continuation_shell(&self) -> Result<EntityId> {
        let mut state = session_entry_state(&self.entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            });
        }
        if state.record.mode != OffRecordMode::OnRecord {
            return Err(Error::InvariantViolation(
                "the on-record continuation shell is only reachable while on record",
            ));
        }
        Ok(*state.continuation_shell.get_or_insert_with(EntityId::now))
    }

    /// In-room BM25 retrieval over the composed union, minting its own route.
    ///
    /// The one-shot sibling of [`Self::search_text_routed`], for callers with
    /// no run to bind to; a bound RUN never takes this door, because its
    /// applies all go through the one route it captured at run entry.
    #[allow(
        dead_code,
        reason = "one-shot sibling: the lib-target search caller is ONE-1729's bound executor \
                  run, which necessarily carries its own route"
    )]
    pub(crate) fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        self.search_text_routed(&self.write_route()?, query, limit)
    }

    /// In-room BM25 retrieval over the composed union (ARCH-0052 §7), applied
    /// through the route the CALLER captured.
    ///
    /// This is the session sibling of `Vault::search_text_with_telemetry` and
    /// mirrors it exactly: the same generalized `bm25::search_text` body, the
    /// same `VaultSearch` telemetry shape. Only the target differs — scoring
    /// reads overlay ∪ base, and the retrieval-run row registers into the
    /// room's overlay `VaultMeta`, so the base telemetry ledger gains nothing
    /// (K10) and the row evaporates at close, where the pre-close census
    /// counts it as a deleted context receipt (K8).
    ///
    /// ONE view serves the whole run. Constructing a view snapshots the
    /// overlay, so a walk that built a view per step could see a torn union
    /// if a concurrent stage landed between them; scoring and registration
    /// therefore share this one.
    ///
    /// Scores ride out with the ids (ONE-1729): the canonical sibling returns
    /// [`ScoredEntity`] and the executor's `self.memory.search` outcome
    /// carries per-hit scores, so projecting them away here would have forced
    /// a second scoring body on the session path.
    ///
    /// The route is a PARAMETER (ONE-1729): registering the retrieval-run row
    /// makes search an APPLY, so a bound run takes it through the single route
    /// it captured at run entry, like every other apply. Minting one here
    /// instead would let a run whose room flipped mid-search land base
    /// telemetry under a route it never held while its neighbouring applies
    /// refused — torn run bookkeeping, and exactly the silent re-mint the
    /// run-entry capture exists to prevent.
    pub(crate) fn search_text_routed(
        &self,
        route: &SessionWriteRoute,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        route.revalidate()?;
        let view = self.read_view()?;
        let search = self.vault.search_text_scored(
            &view,
            query,
            limit,
            &crate::config::Bm25RankProfile::default(),
        )?;
        drop(view);

        let record = Vault::vault_search_retrieval_run_record(
            crate::store::RetrievalSignal::Text,
            search.started_at,
            search.started,
            &search.scores,
            limit,
        );
        // Both targets go through the room's one registration door, so the
        // in-room BM25 path and the assembled paths cannot drift: the overlay
        // arm stages under the route, and the base arm — post-flip the room is
        // on record and telemetry routes to base ordinarily (K10) — publishes
        // under the same route rather than through the routeless canonical
        // door.
        self.retrieval_telemetry(route)?
            .register_run(&record, false)?;

        Ok(search.scores)
    }

    /// The retrieval-run REGISTRATION DOOR for retrievals issued inside this
    /// room (ONE-1570 Arm B, on the ONE-1731/P6 substrate).
    ///
    /// Mints the handle that every telemetry write of an in-room retrieval
    /// goes through — the raw pipeline's registration, the context pack's
    /// finalize, and the failure discard — for BOTH targets.
    /// `search_text_routed` above takes the same door for the in-room BM25
    /// path; the assembled paths take the handle as a builder channel instead
    /// of staging inline.
    ///
    /// **Why a retrieval needs a door at all.** A retrieval-run row carries
    /// `result_ids` and a score breakdown, so it betrays what the room was
    /// asking about even though the retrieval itself reads base. Off record
    /// the row therefore registers into the session's own overlay `VaultMeta`
    /// and evaporates with the transcript, where
    /// [`Vault::close_off_record_session`]'s pre-close census counts it as a
    /// deleted context receipt (K8). On record — and for an ordinary
    /// commissioned retrieval that simply happens while a room is live
    /// elsewhere — the run is an ORDINARY one and belongs in the base ledger
    /// like any other; the room never claims it.
    ///
    /// **Why the route is a PARAMETER.** Same reason `search_text_routed`
    /// takes one: registering a run makes retrieval an APPLY, so a bound run
    /// takes it through the single route it captured at run entry. It also
    /// makes the target a value the CALLER holds for the whole assembly.
    /// A context pack registers a PROVISIONAL row and finalizes it in a
    /// second write; re-deriving the target between those two would let an
    /// assembly whose room flipped mid-run stage its provisional into the
    /// overlay and then finalize into BASE, publishing the room's
    /// `result_ids` durably under a route it no longer held. One captured
    /// route, every write.
    pub(crate) fn retrieval_telemetry<'session>(
        &'session self,
        route: &'session SessionWriteRoute,
    ) -> Result<SessionRetrievalTelemetry<'session>> {
        route.revalidate()?;
        Ok(SessionRetrievalTelemetry {
            vault: self.vault,
            route,
        })
    }

    /// Mode-aware VaultMeta write (ONE-1728 K10): the overlay keyspace while
    /// `OffRecord`, the base `vault_meta` while `OnRecord`.
    ///
    /// The route revalidates before anything is staged, so a write minted
    /// against a mode epoch that a concurrent flip has replaced is refused
    /// rather than landing in the wrong place. The base half runs inside this
    /// module's private vault access; no vault getter escapes.
    #[allow(
        dead_code,
        reason = "ONE-1730 inherits the route-carrying VaultMeta pair (pinned by the P4a blueprint)"
    )]
    pub(crate) fn vault_meta_put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.vault_meta_put_routed(&self.write_route()?, key, value)
    }

    /// The same write against a route the CALLER captured.
    ///
    /// Long-lived writers (ONE-1729's executor run) capture one route at run
    /// entry and apply everything through it, so a mid-run flip is caught by
    /// that route's own `revalidate` instead of being papered over by a fresh
    /// mint per call. [`Self::vault_meta_put`] is the one-shot sibling for
    /// callers with no run to bind to; both share this body, so the two
    /// cannot drift in keyspace or ordering.
    pub(crate) fn vault_meta_put_routed(
        &self,
        route: &SessionWriteRoute,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        route.revalidate()?;
        match route.target() {
            RouteTarget::Overlay => {
                // Same base-writer-then-segment-permit order as the retrieval
                // arm above: the permit is never held while waiting for the
                // base writer.
                let overlay = self.entry.overlay.clone();
                let segment = self.vault.with_write_txn(|wtxn| {
                    let segment = overlay.install_txn_segment()?;
                    route.revalidate()?;
                    let view = self.vault.store.session_view(overlay.clone())?;
                    view.vault_meta_put_in_txn(wtxn, key, value)?;
                    Ok(segment)
                })?;
                segment.commit()
            }
            RouteTarget::Base => self.vault.with_write_txn(|wtxn| {
                route.revalidate()?;
                self.vault.store.vault_meta.put(wtxn, key, value)
            }),
        }
    }

    /// The routed write, conditional on what the row holds RIGHT NOW.
    ///
    /// `accepts_current` sees the composed value inside the very transaction
    /// that replaces it, so the pair is a real compare-and-set. Reading
    /// through an earlier snapshot instead would let two bound runs observe
    /// the same generation, both pass, and both commit — a lost update with
    /// each writer told it won. Its refusal is the CALLER's typed error: the
    /// protocol being compared belongs to the caller, the transaction
    /// discipline belongs here.
    pub(crate) fn vault_meta_compare_and_put_routed(
        &self,
        route: &SessionWriteRoute,
        key: &[u8],
        value: &[u8],
        accepts_current: impl FnOnce(Option<&[u8]>) -> Result<()>,
    ) -> Result<()> {
        route.revalidate()?;
        match route.target() {
            RouteTarget::Overlay => {
                // Same base-writer-then-segment-permit order as the sibling
                // above; the composed read is taken after the segment installs
                // so it cannot miss a room-mate's just-applied row.
                let overlay = self.entry.overlay.clone();
                let segment = self.vault.with_write_txn(|wtxn| {
                    let segment = overlay.install_txn_segment()?;
                    route.revalidate()?;
                    let view = self.vault.store.session_view(overlay.clone())?;
                    accepts_current(view.vault_meta_get_in_txn(&*wtxn, key)?.as_deref())?;
                    view.vault_meta_put_in_txn(wtxn, key, value)?;
                    Ok(segment)
                })?;
                segment.commit()
            }
            RouteTarget::Base => self.vault.with_write_txn(|wtxn| {
                route.revalidate()?;
                // Composed, not base-only: the row this run is updating may
                // still be the overlay row an earlier off-record run of the
                // same room wrote, which is exactly what the unconditional
                // read sees.
                let view = self.vault.store.session_view(self.entry.overlay.clone())?;
                accepts_current(view.vault_meta_get_in_txn(&*wtxn, key)?.as_deref())?;
                self.vault.store.vault_meta.put(wtxn, key, value)
            }),
        }
    }

    /// Composed VaultMeta read over overlay ∪ base.
    pub(crate) fn vault_meta_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let view = self.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        view.vault_meta_get_in_txn(&rtxn, key)
    }

    /// Identity of the store this session belongs to, as a bare pointer.
    ///
    /// The executor binding compares its storage's owning store against its
    /// dispatcher's before it reads or writes anything, and equal
    /// `session_ref`s across two different vaults must not read as the same
    /// binding. A POINTER is the whole answer that question needs, so this
    /// projects one rather than lending out the [`Store`] — nothing
    /// dereferenceable escapes.
    pub(crate) fn store_identity(&self) -> *const Store {
        std::ptr::from_ref(&self.vault.store)
    }

    pub fn flip_on_record(&self) -> Result<()> {
        self.vault
            .set_off_record_session_mode(&self.session_ref, OffRecordMode::OnRecord)?;
        Ok(())
    }

    /// K10 flip-back: returns the session to `OffRecord`, rearming the overlay
    /// so new writes stage there again. Pre-flip turns stay base-invisible.
    pub fn flip_off_record(&self) -> Result<()> {
        self.vault
            .set_off_record_session_mode(&self.session_ref, OffRecordMode::OffRecord)?;
        Ok(())
    }

    /// Records one emit-adjacent receipt in the registry-owned log consumed
    /// by the single close path.
    pub fn record_emit_receipt(&self, receipt: ReceiptRecord) -> Result<()> {
        let mut state = session_entry_state(&self.entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            });
        }
        match state.record.mode {
            OffRecordMode::OffRecord => state
                .receipt_log
                .as_mut()
                .ok_or(Error::InvariantViolation(
                    "live off-record session is missing its receipt log",
                ))?
                .record(receipt),
            OffRecordMode::OnRecord => state
                .post_flip_emit_log
                .get_or_insert_with(|| SessionLocalReceiptLog::on_record(self.session_ref.clone()))
                .record(receipt),
        }
    }

    /// Promotes exactly ONE witnessed turn out of the room and into the
    /// durable vault (ARCH-0052 D4, ONE-1730).
    ///
    /// This is the ONLY session-overlay-to-base write. It selects the turn's
    /// closure from the TYPED JOURNAL — never from overlay index keys, which
    /// are shared across turns — and replays that closure through the ordinary
    /// batch pipeline against current base state, so base indexes, canonical
    /// short ids, counters, validators, gates, and decision receipts are all
    /// re-derived exactly as for any other write.
    ///
    /// # Locking
    ///
    /// The per-session state lock is held across SELECTION and the durable
    /// commit, so close cannot stamp `closing` and freeze a stale view in the
    /// middle of a promotion. The lock order is state -> base writer; nothing
    /// inside the write transaction takes the session state lock, so the order
    /// cannot invert.
    ///
    /// # Ordering after commit
    ///
    /// Nothing observable happens until `wtxn.commit()` returns. Only then does
    /// the session record publish the turn as promoted and the overlay retire
    /// the committed closure. A crash between the two is safe: the durable
    /// receipt answers the retry, and a crashed process evaporates the stale
    /// overlay outright.
    pub fn promote_turn(&self, turn: &EntityId) -> Result<PromoteOutcome> {
        let outcome = {
            let mut state = session_entry_state(&self.entry)?;
            if state.record.closing || state.gone {
                return Err(Error::OffRecordSessionClosing {
                    session_ref: self.session_ref.clone(),
                });
            }
            // RETRY, ahead of the journal: a promoted turn's closure has
            // already been retired from the overlay, so planning it again would
            // fail with "no journaled turn" for a turn that IS promoted. The
            // durable receipt is the answer, and it stays the answer after
            // close. `FloorWrites::promote` re-reads it inside the write
            // transaction, which is where the atomicity of that decision lives;
            // this read only spares the caller a plan it cannot build.
            if let Some(receipt) = self.vault.off_record_promote_receipt(turn)? {
                return Ok(receipt.outcome);
            }
            // The snapshot is taken under the state lock, so the journal this
            // plan is cut from is the journal the commit below applies against.
            let plan = self.entry.overlay.snapshot()?.plan_promotion(*turn)?;
            let outcome = self.vault.with_write_txn(|wtxn| {
                FloorWrites::new(&self.vault.store).promote(
                    self.vault,
                    wtxn,
                    &self.session_ref,
                    &plan,
                    crate::unix_seconds_now(),
                )
            })?;
            // Committed. Publish the RAM state, then drop the promoted rows and
            // journal entries from the room — in that order, and never before.
            // The receipt-first return above makes this the turn's first and
            // only push: a second promote never reaches here.
            state.record.promoted_turns.push(*turn.as_bytes());
            self.entry.publish_state(&state);
            // Best-effort for the same reason the window refresh below is: the
            // subgraph and its receipt are already durable, so a failure to
            // tidy the ROOM must not tell the caller their consented promotion
            // did not happen. The un-retired rows are byte-identical to the
            // base rows the replay just wrote and evaporate at close.
            if let Err(error) = self.entry.overlay.retire_promoted_closure(&plan) {
                tracing::warn!(
                    turn = %turn.to_hex(),
                    error = %error,
                    "off-record promotion committed but overlay closure retirement deferred to close"
                );
            }
            outcome
        };

        // The promotion is durable here. The live-window refresh is best-effort
        // by contract: turning post-commit drift into an error would report a
        // failed promote for content that is committed and kept.
        #[cfg(feature = "sync")]
        if let Err(error) = self.vault.refresh_promoted_turn_in_live_window(turn) {
            tracing::warn!(
                turn = %turn.to_hex(),
                error = %error,
                "off-record promotion committed but live-window sync refresh deferred to recovery"
            );
        }

        Ok(outcome)
    }

    pub fn close(self) -> Result<OffRecordCloseOutcome> {
        self.vault.close_off_record_session(
            &self.session_ref,
            SessionLocalReceiptLog::off_record(&self.session_ref),
        )
    }
}

/// What one executor turn is (ONE-1729, K-EXEC).
///
/// A LABEL, not a schema. The turn's shape — conversation identity, container
/// resolution, role tags, session routing — belongs to the facade witness
/// door; this only says which of the three utterances the door is forming, so
/// the executor never grows a transcript surface of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorUtterance {
    /// Addressed to the user.
    Speak,
    /// Reasoning the run kept for itself.
    Think,
    /// Non-verbal expression accompanying a turn.
    Express,
}

impl ExecutorUtterance {
    /// Message-type string carried into the witness door.
    #[must_use]
    pub const fn as_message_type(self) -> &'static str {
        match self {
            Self::Speak => "executor.speak",
            Self::Think => "executor.think",
            Self::Express => "executor.express",
        }
    }
}

/// Session-bound EXECUTOR surfaces (ONE-1729/P4b).
///
/// Everything a session-bound code run needs that is not already an ordinary
/// session accessor, gathered where the private `&Vault` borrow lives. The
/// executor holds a typed session handle and nothing else: no vault getter,
/// no raw store, no second [`Vault`] clone. Post-flip writes are ORDINARY
/// base writes — the room is on record — so they run the same trap functions
/// a canonical run runs, reached through [`Self::base_write_vault`], which
/// never leaves this module.
impl OffRecordSession<'_> {
    /// Witnesses ONE executor turn through ONE-1728's facade door.
    ///
    /// Guest-supplied turn identity meets a TYPED PRE-CONSTRUCTION REFUSAL
    /// (owner ruling R-20260807-02): `turn_ref` `Some(_)` returns
    /// [`Error::OffRecordGuestTurnRefRejected`] before a `WitnessTurn` is
    /// formed — zero overlay/base delta, zero gate decisions — and the rule
    /// holds in BOTH modes, because a room that flipped on record is still
    /// not a place where a guest names turns. `None` is the only passing
    /// value; a host caller that wants guest transcript ingress must widen
    /// this surface, which is a visible API change.
    ///
    /// `route` is the caller's RUN-ENTRY route, revalidated here so a mid-run
    /// flip refuses the turn outright rather than letting the door mint a
    /// fresh route and publish across the flip.
    ///
    /// The shell is the session's own (rider 1); the door re-resolves it from
    /// the session on both arms, so `container` cannot redirect the turn — it
    /// states, at the call site, the identity the door will use.
    #[expect(
        clippy::too_many_arguments,
        reason = "every parameter is a distinct binding the refusal or the door needs; folding \
                  them into a struct would hide which one the typed refusal reads"
    )]
    pub(crate) fn witness_executor_turn(
        &self,
        container: &EntityId,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        turn_ref: Option<&EntityId>,
        route: &SessionWriteRoute,
        actor: crate::WriteActor,
    ) -> Result<crate::facade::WitnessReceipt> {
        if turn_ref.is_some() {
            return Err(Error::OffRecordGuestTurnRefRejected {
                session_ref: self.session_ref.clone(),
            });
        }
        route.revalidate()?;
        self.vault
            .memory_facade(actor.entity_ref(), actor.actor_class())
            .witness_into_session(
                self,
                &crate::facade::WitnessTurn {
                    conversation_ref: container.to_hex(),
                    turn_ref: None,
                    messages: vec![crate::facade::WitnessMessage {
                        id: None,
                        author: crate::facade::WitnessAuthor::Companion,
                        message_type: kind.as_message_type().to_owned(),
                        content: text.to_owned(),
                        metadata: None,
                        is_visible: matches!(kind, ExecutorUtterance::Speak),
                        order: 0,
                    }],
                    occurred_at,
                },
                None,
            )
            // The door reports a code+message `FacadeError`. Every refusal
            // this entry OWNS is raised as a typed error above, and the turn
            // is built here from executor-controlled parts, so anything the
            // door still rejects means an executor-side invariant broke.
            .map_err(|_| {
                Error::InvariantViolation("executor witness door rejected the session turn")
            })
    }

    /// The conversation shell this run's turns ride, for `route`'s mode.
    ///
    /// Off record it is the ROOM's shell, created at session entry (rider 1);
    /// on record it is the session's continuation shell, deliberately a
    /// different conversation so a base row never references an overlay
    /// member. Either way the session machinery owns it — the executor reads
    /// it, never mints it.
    pub(crate) fn routed_conversation_shell(&self, route: &SessionWriteRoute) -> Result<EntityId> {
        match route.target() {
            RouteTarget::Overlay => self.overlay_conversation_shell(),
            RouteTarget::Base => self.on_record_continuation_shell(),
        }
    }

    /// The owning vault for a write the route says is ORDINARY.
    ///
    /// MODULE-PRIVATE on purpose: it is the one place a `&Vault` is produced
    /// from a session handle, and it produces one only under a revalidated
    /// `Base` route — the sole evidence the room went on record. An `Overlay`
    /// route means the caller reached a durable write while off record, which
    /// the effect policy is supposed to have refused first.
    fn base_write_vault(&self, route: &SessionWriteRoute) -> Result<&Vault> {
        route.revalidate()?;
        match route.target() {
            RouteTarget::Base => Ok(self.vault),
            RouteTarget::Overlay => Err(Error::OffRecordTalkOnly {
                session_ref: self.session_ref.clone(),
            }),
        }
    }

    /// Write-path gate check for a session-bound code run's durable write.
    pub(crate) fn executor_check_write_gate(
        &self,
        route: &SessionWriteRoute,
        id: EntityId,
        body: &crate::ClaimBody,
        envelope: &crate::WriteEnvelope,
        can_resolve_pending_consent: bool,
    ) -> Result<()> {
        let vault = self.base_write_vault(route)?;
        crate::code_run::check_write_gate_against_vault(
            vault,
            id,
            body,
            envelope,
            can_resolve_pending_consent,
        )
    }

    /// `self.memory.write_fixture` on a session-bound run.
    pub(crate) fn executor_batch_claim_candidate(
        &self,
        route: &SessionWriteRoute,
        id: &EntityId,
        candidate: crate::ClaimCandidate,
        envelope: &crate::WriteEnvelope,
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.base_write_vault(route)?
            .batch()
            .claim_candidate(id, candidate, envelope, occurred, learned_at)
            .commit()
    }

    /// `self.memory.put_claim` on a session-bound run.
    pub(crate) fn executor_put_claim_candidate(
        &self,
        route: &SessionWriteRoute,
        id: &EntityId,
        candidate: crate::ClaimCandidate,
        envelope: &crate::WriteEnvelope,
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.base_write_vault(route)?
            .put_claim_candidate_without_lexical_query_reconcile(
                id, candidate, envelope, occurred, learned_at,
            )
    }

    /// `self.memory.supersede_claim` on a session-bound run. ONE-1936's
    /// stale-target guard lives INSIDE this trap and stays authoritative
    /// there; this only chooses the route.
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the canonical supersede trap arity exactly"
    )]
    pub(crate) fn executor_supersede_claim(
        &self,
        route: &SessionWriteRoute,
        new_id: &EntityId,
        old_id: &EntityId,
        now: u64,
        envelope: &crate::WriteEnvelope,
        claim_gate_id: EntityId,
        claim_gate_body: &crate::ClaimBody,
        edge_gate_id: EntityId,
        edge_gate_body: &crate::ClaimBody,
    ) -> Result<()> {
        self.base_write_vault(route)?
            .supersede_claim_for_code_run_trap(
                new_id,
                old_id,
                now,
                envelope,
                claim_gate_id,
                claim_gate_body,
                edge_gate_id,
                edge_gate_body,
            )
    }

    /// `self.memory.put_edge` on a session-bound run.
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the canonical put-edge trap arity exactly"
    )]
    pub(crate) fn executor_put_edge(
        &self,
        route: &SessionWriteRoute,
        src: &EntityId,
        kind: crate::EdgeKind,
        tgt: &EntityId,
        weight: f32,
        envelope: &crate::WriteEnvelope,
        gate_id: EntityId,
        gate_body: &crate::ClaimBody,
    ) -> Result<()> {
        self.base_write_vault(route)?
            .put_edge_for_code_run_trap(src, kind, tgt, weight, envelope, gate_id, gate_body)
    }
}

impl Vault {
    #[must_use]
    pub fn off_record_session_vault(&self) -> OffRecordSessionVault<'_> {
        OffRecordSessionVault { vault: self }
    }

    /// Explicitly enters off-record mode for `session_ref` (OF-326: enter is
    /// never implicit). Errors with [`Error::OffRecordSessionAlreadyExists`]
    /// while a record for the ref exists — a closed session's ref may be
    /// reused because close removes the record.
    pub fn enter_off_record_session(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
    ) -> Result<OffRecordSessionRecord> {
        self.enter_off_record_session_with_budget(
            session_ref,
            backend,
            self.config.off_record_overlay_budget_bytes,
        )
    }

    pub(super) fn enter_off_record_session_with_budget(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        budget_bytes: usize,
    ) -> Result<OffRecordSessionRecord> {
        let entry = self.enter_off_record_session_entry(session_ref, backend, budget_bytes)?;
        Ok(session_entry_state(&entry)?.record.clone())
    }

    fn enter_off_record_session_entry(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        budget_bytes: usize,
    ) -> Result<Arc<OffRecordSessionEntry>> {
        if !self.config.off_record_enabled {
            return Err(Error::KillSwitchDisabled);
        }
        vet_off_record_session_ref(session_ref)?;
        self.store
            .off_record_sessions
            .enter(session_ref, backend, budget_bytes)
    }

    /// Reads the off-record session record for `session_ref`, if any. A ref
    /// that fails the session-ref length bound cannot name a session (enter
    /// enforces the same bound), so it reads as `None` without building a
    /// key — arbitrary caller-supplied refs never drive allocation size.
    pub fn off_record_session(&self, session_ref: &str) -> Result<Option<OffRecordSessionRecord>> {
        if vet_off_record_session_ref(session_ref).is_err() {
            return Ok(None);
        }
        Ok(self.store.off_record_sessions.record(session_ref))
    }

    /// Flips the session's write-routing mode, in either direction (ARCH-0052
    /// D5 / K10). Rows already in the room stay in the room across the flip.
    ///
    /// * `OffRecord -> OnRecord` seals the overlay write path. New writes —
    ///   telemetry included — route to base ordinarily, under the session's
    ///   on-record continuation shell; reads stay composed, so the room's
    ///   earlier turns remain visible in-session.
    /// * `OnRecord -> OffRecord` REARMS the overlay (`Sealed` -> `Live`). New
    ///   writes route to the overlay again. Pre-flip turns stay overlay-only
    ///   and base-invisible throughout; rearm reopens the write door and
    ///   touches no row.
    ///
    /// Both directions publish a fresh overlay mode generation under the held
    /// state lock, so a `SessionWriteRoute` minted before the flip is refused
    /// by `SessionWriteRoute::revalidate` before it can stage or commit.
    pub fn set_off_record_session_mode(
        &self,
        session_ref: &str,
        mode: OffRecordMode,
    ) -> Result<OffRecordSessionRecord> {
        vet_off_record_session_ref(session_ref)?;
        let entry = live_session_entry(&self.store, session_ref)?;
        // Hold the per-session state lock across the irreversible overlay seal
        // AND the mode-record update, so the two are atomic. Releasing the lock
        // between the seal and the record write (the prior snapshot/reconcile
        // shape) let a concurrent record mutation win the post-seal drift check
        // AFTER the overlay was already permanently sealed, stranding a sealed
        // overlay under a record that still read `OffRecord` (overlay writes
        // then failed though the mode never changed). Deadlock-safe:
        // `seal_writes` takes only the overlay's own lock, never `entry.state`.
        let mut state = session_entry_state(&entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: session_ref.to_owned(),
            });
        }
        if state.record.mode == mode {
            return Ok(state.record.clone());
        }
        match mode {
            OffRecordMode::OnRecord => entry.overlay.seal_writes()?,
            OffRecordMode::OffRecord => entry.overlay.rearm()?,
        }
        state.record.mode = mode;
        entry.publish_state(&state);
        Ok(state.record.clone())
    }

    /// Opens the session-local emit receipt log bound to a live off-record
    /// session. One log per session: dispatch-emitted receipts are recorded
    /// into it, and [`Vault::close_off_record_session`] consumes it so no
    /// emit-adjacent receipt can be orphaned past close. After a mid-session
    /// flip back on-record, new emit receipts belong in a fresh
    /// [`SessionLocalReceiptLog::on_record`] log; anything still riding the
    /// off-record log is dropped at close (over-deletion is the safe
    /// direction).
    pub fn off_record_receipt_log(&self, session_ref: &str) -> Result<SessionLocalReceiptLog> {
        vet_off_record_session_ref(session_ref)?;
        if self.off_record_session(session_ref)?.is_none() {
            return Err(Error::OffRecordSessionNotFound {
                session_ref: session_ref.to_owned(),
            });
        }
        Ok(SessionLocalReceiptLog::off_record(session_ref))
    }

    /// Closes the session: the off-record transcript evaporates.
    ///
    /// Close DELETES NOTHING. The transcript stops existing because the
    /// overlay that held it is dropped, and P5-promoted rows survive because
    /// they were written into base by an explicitly consented promote and
    /// close never looks at base at all. There is no ARCH-0038 `PolicyDelete`
    /// pass, no redaction cascade for session content, and no retention
    /// marker outliving the room.
    ///
    /// Session-local receipts follow the transcript: the session's
    /// retrieval-run context receipts and its witnessed transcript rows live
    /// in the overlay and evaporate with it — close censuses them immediately
    /// BEFORE the overlay closes, because they are unobservable after — and
    /// the session's [`SessionLocalReceiptLog`] is consumed here, the one
    /// close path, so its emit-adjacent receipts drop with the room.
    ///
    /// Concurrency contract: close first stamps `closing` on the record, after
    /// which every mutator rejects with [`Error::OffRecordSessionClosing`], so
    /// nothing writes into a room that is going away. Each later phase
    /// re-reads the record and fails closed on drift instead of trusting the
    /// frozen snapshot. The registry entry is dropped LAST, so a close
    /// interrupted mid-way can simply be called again (mint a fresh empty log
    /// via [`Vault::off_record_receipt_log`] to retry).
    pub fn close_off_record_session(
        &self,
        session_ref: &str,
        receipt_log: SessionLocalReceiptLog,
    ) -> Result<OffRecordCloseOutcome> {
        vet_off_record_session_ref(session_ref)?;
        if receipt_log.session_ref() != session_ref {
            return Err(Error::InvariantViolation(
                "off-record close given another session's receipt log",
            ));
        }
        if !receipt_log.is_off_record() {
            return Err(Error::InvariantViolation(
                "off-record close requires an off-record receipt log",
            ));
        }
        // Freeze the in-process record under its short per-session lock, then
        // release it before draining overlay leases. Mutators observe the
        // published closing bit and reject while close reconciles the frozen
        // record after every blocking phase.
        let entry = live_session_entry(&self.store, session_ref)?;
        let (record, close_overlay) = {
            let mut state = session_entry_state(&entry)?;
            if state.gone {
                return Err(Error::OffRecordSessionNotFound {
                    session_ref: session_ref.to_owned(),
                });
            }
            state.record.closing = true;
            entry.publish_state(&state);
            (state.record.clone(), !state.overlay_closed)
        };
        // PRE-CLOSE CENSUS (K8). Session-local retrieval-run receipts and
        // witnessed transcript entities live in the overlay, so close does not
        // delete them — the overlay's evaporation does. They are unobservable
        // the instant `close()` returns, so the counts the outcome reports must
        // be captured HERE, while the rows are still readable.
        let (context_receipts_deleted, overlay_transcript_deleted) = if close_overlay {
            let snapshot = entry.overlay.snapshot()?;
            (
                snapshot.live_row_count(OverlayKeyspace::VaultMeta, |key| {
                    key.starts_with(crate::store::RETRIEVAL_RUN_KEY_PREFIX)
                }),
                snapshot.transcript_entity_put_count(),
            )
        } else {
            (0, 0)
        };
        if close_overlay {
            // Session handles lend composed views from `&self`, so safe
            // callers must drop all read views before consuming close.
            entry.overlay.close()?;
        }
        let (internal_receipt_log, post_flip_emit_log) = {
            let mut state = session_entry_state(&entry)?;
            if state.gone || state.record != record {
                return Err(Error::InvariantViolation(
                    "off-record session record drifted during overlay close",
                ));
            }
            if close_overlay {
                state.overlay_closed = true;
            }
            if !state.overlay_closed {
                return Err(Error::InvariantViolation(
                    "off-record overlay remained live during close",
                ));
            }
            (state.receipt_log.take(), state.post_flip_emit_log.take())
        };
        let receipt_close = receipt_log.close();
        assert!(receipt_close.retained.is_empty());
        let internal_receipt_close = internal_receipt_log.map(SessionLocalReceiptLog::close);
        let emit_receipts_deleted = receipt_close
            .deleted
            .checked_add(
                internal_receipt_close
                    .as_ref()
                    .map_or(0, |close| close.deleted),
            )
            .ok_or(Error::ArithmeticOverflow(
                "off-record deleted emit receipt count",
            ))?;
        let emit_receipts_retained = post_flip_emit_log
            .map(SessionLocalReceiptLog::close)
            .map_or_else(Vec::new, |close| close.retained);

        // The room's transcript stopped existing when the overlay evaporated.
        // Nothing in base is touched, so there is no delete pass to census and
        // no promoted row to spare from one.
        let turns_deleted = overlay_transcript_deleted;

        // Validate the frozen in-process record one last time, then drop the
        // registry entry. Neither the session record nor its content ever had
        // a durable row to remove.
        {
            let mut state = session_entry_state(&entry)?;
            if state.gone || state.record != record {
                return Err(Error::InvariantViolation(
                    "off-record session record drifted during close",
                ));
            }
            state.gone = true;
            entry.publish_state(&state);
        }
        self.store
            .off_record_sessions
            .remove_if_same(session_ref, &entry)?;

        Ok(OffRecordCloseOutcome {
            turns_deleted,
            context_receipts_deleted,
            emit_receipts_deleted,
            emit_receipts_retained,
            promoted_turns_kept: record.promoted_turns.len(),
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
