//! OF-326 off-record / ephemeral session seam (ONE-1546 / OFRC-1).
//!
//! A no-write, evaporating session mode. The seam is four verbs plus one
//! standing law:
//!
//! * **Enter is explicit** — [`Vault::enter_off_record_session`] creates an
//!   in-process session record. The engine exposes mode and backend-class
//!   enums; the host owns all user-facing marker composition.
//! * **THE FENCE** — turns tagged via [`Vault::tag_turn_off_record`] carry a
//!   per-entity fence row that the retrieval/extraction candidate filter
//!   consults unconditionally (`off_record_fence_active`, wired into
//!   `pipeline_candidate_matches_filters_and_gate`). Fenced turns are never
//!   surfaced to witness/extraction, and the tag outlives a same-session
//!   flip back on-record: only promote or delete-at-close lifts it.
//! * **Defer-sync** — fenced entities and incident edges are held out of
//!   both window-packing paths until explicit promotion. The fence remains
//!   device-local; promoting one turn lifts only that turn's fence, so only
//!   that turn joins ordinary sync.
//! * **Talk-only** — an outbound intent whose originating session is
//!   currently in off-record mode is rejected by the dispatch spine with
//!   the typed [`crate::Error::OffRecordTalkOnly`] (exit-prompt semantics).
//!   The OF-333 floor still classifies real egress; its gate-decision
//!   receipts are floor receipts and survive close untouched.
//! * **RECEIPTS-FOLLOW-TRANSCRIPT** — session-local receipts ride two
//!   substrates and close covers both. Durable retrieval-run context
//!   receipts (whose `result_ids` would betray what the room was about) are
//!   registered via [`Vault::note_off_record_context_receipt`] and deleted
//!   at close. In-memory emit-adjacent receipts (dispatch emit receipts
//!   carrying the OF-369/RS9 context field-set) ride the session's
//!   [`SessionLocalReceiptLog`] — minted via
//!   [`Vault::off_record_receipt_log`] — which close CONSUMES, so there is
//!   one close path and no emit receipt can be orphaned. Only floor
//!   receipts (gate decisions, redaction audits) persist.
//!
//!   **MUST (caller discipline):** every retrieval run executed FOR an
//!   off-record session MUST be registered via
//!   [`Vault::note_off_record_context_receipt`] with the run id the
//!   pipeline returned (`run_with_telemetry`). The retrieval-telemetry
//!   write path has no session ref, so the engine CANNOT auto-register —
//!   one forgotten call permanently leaks the room's activated-memory ids
//!   in a durable retrieval-run row.
//! * **Delete-at-close** — [`Vault::close_off_record_session`] deletes every
//!   still-fenced turn through the pinned ARCH-0038 contract
//!   ([`DeleteReason::PolicyDelete`]: CRDT tombstone FIRST, active-store
//!   hard purge, opaque REDACTION_AUDIT receipt, historical-carrier sweep),
//!   then deletes the context receipts, and removes the fence rows and the
//!   session record LAST so an interrupted close stays retryable.
//! * **Promote** — [`Vault::promote_off_record_turn`] lifts the fence for
//!   exactly ONE turn on explicit user consent, moving it out of the
//!   delete-at-close set and minting a durable user-initiated
//!   [`OffRecordPromoteReceipt`] that survives close.
//!
//! Voice: the engine has no audio intermediate layer; ASR/TTS intermediates
//! persisted as vault entities by a caller ride the same fence + deletion by
//! being tagged like any other turn (the fence keys on entity id, not
//! entity type).
//!
//! # Known limitations (OFRC-2 scope)
//!
//! Ticketed follow-ups pending an owner design pass — deliberately named
//! here, not silently absent:
//!
//! * **Whole-vault export refuses while a session is live.** The export seam
//!   checks the in-process registry before it writes an artifact, returning
//!   a typed error naming the open session rather than producing a bundle that
//!   could outlive close with fenced content.
//! * **Context-receipt registration is caller discipline.** See the MUST
//!   above — auto-registration needs session plumbing at the
//!   retrieval-telemetry seam (e.g. a session ref on `PipelineBuilder`)
//!   that does not exist today.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::{ArcSwap, ArcSwapOption};
use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::deletion::DeleteReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptRecord, SessionLocalReceiptLog};
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
use crate::session_overlay::SessionOverlay;
use crate::store::{GateDecisionRecord, RetrievalRunId, Store};

/// `vault_meta` key prefix for per-entity fence rows (value = session ref).
const OFF_RECORD_FENCE_KEY_PREFIX: &[u8] = b"offrecord_fence:v0:";
/// Value replacing a tag-before-write fence after close. An empty value can
/// never be a live session ref (`vet_off_record_session_ref` rejects empty),
/// so it preserves the closed write door without retaining session metadata.
const OFF_RECORD_CLOSED_FENCE_VALUE: &[u8] = b"";

const OFF_RECORD_SESSION_RECORD_VERSION: u8 = 0;

/// Longest accepted caller-supplied opaque session ref, in bytes.
const OFF_RECORD_SESSION_REF_MAX_LEN: usize = 256;
/// Hard cap on fenced turns tracked by one session record.
const OFF_RECORD_MAX_FENCED_TURNS: usize = 65_536;
/// Hard cap on session-local context receipts tracked by one session record.
const OFF_RECORD_MAX_CONTEXT_RECEIPTS: usize = 65_536;

/// Current tagging mode of an off-record session.
///
/// Flipping back to [`OffRecordMode::OnRecord`] mid-session stops NEW turns
/// from being tagged; it never lifts the fence on turns already tagged
/// (they linger in context but stay unextractable until promote or close).
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
    /// Turns still fenced (the delete-at-close set).
    pub fenced_turns: Vec<[u8; 16]>,
    /// Turns promoted out of the fence; close keeps them.
    pub promoted_turns: Vec<[u8; 16]>,
    /// Session-local context receipts (retrieval runs) deleted at close.
    pub context_receipt_runs: Vec<RetrievalRunId>,
    /// Set by the first close transaction. While `true`, every mutator
    /// (tag, promote, note-context-receipt, mode flip) rejects with
    /// [`Error::OffRecordSessionClosing`] — close's multi-transaction
    /// deletion pass must never race a record mutation (a stale snapshot
    /// could hard-delete a just-promoted, user-consented turn).
    #[serde(default)]
    pub closing: bool,
}

/// What close deleted and what it kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffRecordCloseOutcome {
    /// Fenced turns hard-deleted through the ARCH-0038 PolicyDelete path.
    pub turns_deleted: usize,
    /// Fenced turn ids with no stored entity (tag-before-write where the
    /// write never landed); nothing to delete.
    pub turns_missing: usize,
    /// Session-local retrieval-run context receipts removed.
    pub context_receipts_deleted: usize,
    /// Emit-adjacent receipts dropped with the session's
    /// [`SessionLocalReceiptLog`] (RECEIPTS-FOLLOW-TRANSCRIPT).
    pub emit_receipts_deleted: usize,
    /// Sessionless closed-fence rows kept for turns that were MISSING at
    /// delete time (tag-before-write where the write had not landed). The
    /// retained marker rejects a late entity write without keeping session
    /// metadata; equals `turns_missing`.
    pub fence_rows_retained: usize,
    /// Promoted turns intentionally left in place.
    pub promoted_turns_kept: usize,
    /// REDACTION_AUDIT receipt ids minted by the per-turn deletions (floor
    /// receipts: they persist).
    pub redaction_receipt_ids: Vec<EntityId>,
}

mod floor_writes_seal {
    pub(super) struct Seal;
}

/// The only durable writer surface made available to session lifecycle code.
/// Its constructor and seal are crate-private, and it exposes exactly the
/// three floor operations allowed by ARCH-0052.
pub(crate) struct FloorWrites<'store> {
    pub(super) store: &'store Store,
    _seal: floor_writes_seal::Seal,
}

impl<'store> FloorWrites<'store> {
    pub(crate) fn new(store: &'store Store) -> Self {
        Self {
            store,
            _seal: floor_writes_seal::Seal,
        }
    }

    /// Floor operation 1/3: append one evaluated egress gate decision.
    pub(crate) fn append_egress_gate_decision(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<()> {
        self.store.append_gate_decision_in_txn(wtxn, record)
    }

    /// Floor operation 2/3: append one REDACTION_AUDIT entity and its exact
    /// ordinary entity-index footprint.
    pub(crate) fn append_redaction_audit(
        &self,
        wtxn: &mut RwTxn<'_>,
        receipt_id: &EntityId,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()> {
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        payload.extend_from_slice(&crate::deletion::receipt_envelope_header(learned_at));
        payload.extend_from_slice(body);
        self.store
            .entities
            .put(wtxn, receipt_id.as_bytes(), &payload)?;

        let type_key = Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, receipt_id);
        self.store.type_index.put(wtxn, &type_key, &[])?;
        let temporal_key = Store::encode_temporal_key(learned_at, receipt_id);
        self.store
            .temporal_occurred_start
            .put(wtxn, &temporal_key, &[])?;
        self.store.temporal_learned.put(wtxn, &temporal_key, &[])?;
        Ok(())
    }
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
    pub(super) overlay_closed: bool,
    pub(super) gone: bool,
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
            fenced_turns: Vec::new(),
            promoted_turns: Vec::new(),
            context_receipt_runs: Vec::new(),
            closing: false,
        };
        let entry = Arc::new(OffRecordSessionEntry {
            overlay: SessionOverlay::new(budget_bytes),
            state: Mutex::new(OffRecordSessionEntryState {
                record: record.clone(),
                receipt_log: Some(SessionLocalReceiptLog::off_record(session_ref)),
                overlay_closed: false,
                gone: false,
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

    pub(crate) fn first_session_ref(&self) -> Result<Option<String>> {
        Ok(self.sessions()?.keys().next().cloned())
    }

    pub(crate) fn contains_entity(&self, id: &EntityId) -> Result<bool> {
        let sessions = self.published.load();
        for entry in sessions.values() {
            if entry.published_record.load().is_some() && entry.overlay.contains_entity(id)? {
                return Ok(true);
            }
        }
        Ok(false)
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

pub(super) fn off_record_fence_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(OFF_RECORD_FENCE_KEY_PREFIX.len() + 16);
    key.extend_from_slice(OFF_RECORD_FENCE_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
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

/// THE FENCE probe consulted by the retrieval/extraction candidate filter:
/// `true` means the entity is tagged off-record and must never surface,
/// regardless of the owning session's current mode. Live-overlay membership
/// reads immutable published snapshots without registry or entry locks; the
/// durable fence key is built on the stack.
pub(crate) fn off_record_fence_active(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if store.off_record_sessions.contains_entity(id)? {
        return Ok(true);
    }
    const PREFIX_LEN: usize = OFF_RECORD_FENCE_KEY_PREFIX.len();
    let mut key = [0_u8; PREFIX_LEN + 16];
    key[..PREFIX_LEN].copy_from_slice(OFF_RECORD_FENCE_KEY_PREFIX);
    key[PREFIX_LEN..].copy_from_slice(id.as_bytes());
    Ok(store.vault_meta.get(rtxn, &key)?.is_some())
}

/// Returns whether the vault has any fence rows at all. Retrieval channels use
/// this once-per-query probe to preserve their fence-free fast path before
/// checking returned candidates individually.
pub(crate) fn off_record_fences_present(store: &Store, rtxn: &RoTxn<'_>) -> Result<bool> {
    if store.off_record_sessions.has_overlay_entities()? {
        return Ok(true);
    }
    Ok(store
        .vault_meta
        .prefix_iter(rtxn, OFF_RECORD_FENCE_KEY_PREFIX)?
        .next()
        .transpose()?
        .is_some())
}

/// Whole-vault-export durable backstop: returns the session ref of the first
/// durable fence row carrying a NON-EMPTY value (a live-session-ref fence), or
/// `None`. The empty value is the sessionless closed-fence marker retained past
/// close and must NOT block export, so the scan filters on value length > 0. A
/// live session's fence is caught by the in-process registry check first; this
/// only surfaces a CRASH-ORPHANED row (no registry entry) that the next
/// `Vault::open` sweep will lift.
pub(crate) fn off_record_orphaned_live_fence_session_ref(
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<Option<String>> {
    for entry in store
        .vault_meta
        .prefix_iter(rtxn, OFF_RECORD_FENCE_KEY_PREFIX)?
    {
        let (_key, value) = entry?;
        if !value.is_empty() {
            return Ok(Some(String::from_utf8_lossy(&value).into_owned()));
        }
    }
    Ok(None)
}

/// Fail-closed entity materialization door for off-record fences.
///
/// Every ordinary, typed, claim-candidate, and replicated entity put reaches
/// this probe through `batch::apply_put` before it can stage bytes, index
/// rows, or gate receipts. A live fence permits only the local
/// tag-before-write flow; a replicated write, or a closing, closed, malformed,
/// or mismatched fence rejects with a typed error. The retained post-close
/// marker is sessionless, so this guard never needs to surface or preserve an
/// evaporated session ref.
pub(crate) fn guard_off_record_entity_put(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    replicated: bool,
) -> Result<()> {
    let rejected = || Error::OffRecordFencedTurnWriteRejected {
        turn_ref: id.to_hex(),
    };
    if store.off_record_sessions.contains_entity(id)? {
        return Err(rejected());
    }
    let fence_key = off_record_fence_key(id);
    let Some(fence_value) = store.vault_meta.get(wtxn, &fence_key)? else {
        return Ok(());
    };

    let Some(session_ref) = std::str::from_utf8(&fence_value)
        .ok()
        .filter(|session_ref| !session_ref.is_empty())
    else {
        return Err(rejected());
    };
    let Some(record) = store.off_record_sessions.record(session_ref) else {
        return Err(rejected());
    };
    if replicated || record.closing || !record.fenced_turns.contains(id.as_bytes()) {
        return Err(rejected());
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

/// Live session handle. Its borrow of the owning [`Vault`] makes it
/// impossible for safe Rust to retain a session across `StoreOwner::drop`.
pub struct OffRecordSession<'vault> {
    vault: &'vault Vault,
    session_ref: String,
    entry: Arc<OffRecordSessionEntry>,
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

    /// Captures one snapshot for all 28 accessors. The returned view borrows
    /// this handle, so `close(self)` is unavailable until the view is dropped.
    #[allow(
        dead_code,
        reason = "ONE-1727 completes the session view contract; ONE-1728 witness/retrieval is its first lib-target caller"
    )]
    pub(crate) fn read_view(&self) -> Result<crate::store::SessionStoreView<'_>> {
        self.vault.store.session_view(self.entry.overlay.clone())
    }

    #[allow(
        dead_code,
        reason = "ONE-1726 oracle access; production overlay writes arrive with ONE-1728 witness"
    )]
    pub(crate) fn overlay(&self) -> Arc<SessionOverlay> {
        self.entry.overlay.clone()
    }

    pub fn flip_on_record(&self) -> Result<()> {
        self.vault
            .set_off_record_session_mode(&self.session_ref, OffRecordMode::OnRecord)?;
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
        state
            .receipt_log
            .as_mut()
            .ok_or(Error::InvariantViolation(
                "live off-record session is missing its receipt log",
            ))?
            .record(receipt)
    }

    pub fn close(self) -> Result<OffRecordCloseOutcome> {
        self.vault.close_off_record_session(
            &self.session_ref,
            SessionLocalReceiptLog::off_record(&self.session_ref),
        )
    }
}

impl Vault {
    #[must_use]
    pub fn off_record_session_vault(&self) -> OffRecordSessionVault<'_> {
        OffRecordSessionVault { vault: self }
    }

    /// Refuses whole-vault export while any in-process session registry entry
    /// remains live, including throughout its closing state, AND — model A's
    /// durable backstop — while any crash-orphaned durable fence row survives.
    pub(crate) fn ensure_no_open_off_record_session(&self) -> Result<()> {
        if let Some(session_ref) = self.store.off_record_sessions.first_session_ref()? {
            return Err(Error::OffRecordExportRefused { session_ref });
        }
        // Durable backstop (model A): a crash mid-session can leave an ORPHANED
        // durable fence row — a live-session-ref value with no registry entry —
        // whose fenced base turn is still on disk. The in-process check above
        // cannot see it, so also refuse whole-vault export while ANY non-empty
        // `offrecord_fence:v0:` row exists (the empty value is the sessionless
        // closed-fence marker and never blocks). The next `Vault::open` sweep,
        // or a re-driven close, lifts the row and re-permits export. Fail closed
        // on either leg.
        let rtxn = self.store.env.read_txn()?;
        if let Some(session_ref) = off_record_orphaned_live_fence_session_ref(&self.store, &rtxn)? {
            return Err(Error::OffRecordExportRefused { session_ref });
        }
        Ok(())
    }

    /// Crash-orphan recovery — model A's "evaporation at next open". A crash
    /// mid-session can leave durable `offrecord_fence:v0:` rows whose value
    /// names a session with no live registry entry; the fenced base turns are
    /// then undeletable and would ship through whole-vault export. Run at
    /// [`Vault::open`] BEFORE the handle is usable: at open the in-process
    /// registry is always empty, so EVERY non-empty fence row is orphaned.
    /// PolicyDelete each fenced turn on the pinned ARCH-0038 contract (CRDT
    /// tombstone first, active-store purge, opaque audit receipt), then lift
    /// the fence row exactly as [`Vault::close_off_record_session`] does: delete
    /// the row for a turn that existed (or was already hard-deleted), or leave
    /// the sessionless empty closed-fence marker for a fully-missing
    /// tag-before-write turn so its late write is still rejected at the entity
    /// door. Idempotent and a no-op when there are zero orphans; the empty
    /// closed-fence markers left by a prior sweep/close are skipped.
    pub(crate) fn sweep_orphaned_off_record_fences(&self) -> Result<()> {
        // The 16-byte suffix after the prefix is the fenced turn's entity id.
        let orphans: Vec<EntityId> = {
            let rtxn = self.store.env.read_txn()?;
            let mut ids = Vec::new();
            for entry in self
                .store
                .vault_meta
                .prefix_iter(&rtxn, OFF_RECORD_FENCE_KEY_PREFIX)?
            {
                let (key, value) = entry?;
                if value.is_empty() {
                    // Sessionless closed-fence marker — already lifted.
                    continue;
                }
                let suffix = &key[OFF_RECORD_FENCE_KEY_PREFIX.len()..];
                let bytes: [u8; 16] = suffix.try_into().map_err(|_| {
                    Error::InvariantViolation("malformed off-record fence key at open")
                })?;
                ids.push(EntityId::from_bytes(bytes)?);
            }
            ids
        };
        if orphans.is_empty() {
            return Ok(());
        }
        for id in &orphans {
            let outcome = self.delete_entity_with_reason(id, DeleteReason::PolicyDelete)?;
            // Mirror close's fence-row disposition: a turn that existed (or was
            // already hard-deleted by a partially-applied prior sweep) has its
            // fence row removed; a fully-missing tag-before-write turn keeps a
            // sessionless closed-fence marker so a late write stays rejected.
            let turn_existed = if outcome.existed {
                true
            } else {
                let rtxn = self.store.env.read_txn()?;
                let already_hard_deleted =
                    self.local_hard_delete_marker_exists_in_txn(&rtxn, id)?;
                drop(rtxn);
                already_hard_deleted
            };
            self.with_write_txn(|wtxn| {
                if turn_existed {
                    self.store
                        .vault_meta
                        .delete(wtxn, &off_record_fence_key(id))?;
                } else {
                    self.store
                        .delete_gate_decisions_for_missing_off_record_turn_in_txn(wtxn, id)?;
                    self.store.vault_meta.put(
                        wtxn,
                        &off_record_fence_key(id),
                        OFF_RECORD_CLOSED_FENCE_VALUE,
                    )?;
                }
                Ok(())
            })?;
        }
        Ok(())
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

    /// Flips the session's tagging mode (e.g. back on-record mid-session).
    /// Fence rows on already-tagged turns are untouched: THE FENCE holds
    /// across the flip.
    pub fn set_off_record_session_mode(
        &self,
        session_ref: &str,
        mode: OffRecordMode,
    ) -> Result<OffRecordSessionRecord> {
        vet_off_record_session_ref(session_ref)?;
        let entry = live_session_entry(&self.store, session_ref)?;
        let record = {
            let state = session_entry_state(&entry)?;
            if state.record.closing || state.gone {
                return Err(Error::OffRecordSessionClosing {
                    session_ref: session_ref.to_owned(),
                });
            }
            if state.record.mode == mode {
                return Ok(state.record.clone());
            }
            if state.record.mode == OffRecordMode::OnRecord {
                return Err(Error::InvariantViolation(
                    "a sealed off-record overlay cannot be reopened for writes",
                ));
            }
            state.record.clone()
        };

        entry.overlay.seal_writes()?;

        let mut state = session_entry_state(&entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: session_ref.to_owned(),
            });
        }
        if state.record != record {
            return Err(Error::InvariantViolation(
                "off-record session record drifted during mode seal",
            ));
        }
        state.record.mode = OffRecordMode::OnRecord;
        entry.publish_state(&state);
        Ok(state.record.clone())
    }

    /// Tags one turn off-record: writes the fence row and adds the turn to
    /// the session's delete-at-close set. Requires the session to currently
    /// be in [`OffRecordMode::OffRecord`] (turns written after a flip back
    /// on-record are ordinary turns). The turn entity may not exist yet —
    /// tagging BEFORE the turn write closes the race against a concurrent
    /// extraction pass. Idempotent for a turn already fenced by this session.
    pub fn tag_turn_off_record(&self, session_ref: &str, turn_id: &EntityId) -> Result<()> {
        vet_off_record_session_ref(session_ref)?;
        let entry = live_session_entry(&self.store, session_ref)?;
        let record = {
            let state = session_entry_state(&entry)?;
            if state.record.closing || state.gone {
                return Err(Error::OffRecordSessionClosing {
                    session_ref: session_ref.to_owned(),
                });
            }
            if state.record.mode != OffRecordMode::OffRecord {
                return Err(Error::InvariantViolation(
                    "off-record tag requires the session to be in off-record mode",
                ));
            }
            if state.record.promoted_turns.contains(turn_id.as_bytes()) {
                return Err(Error::InvariantViolation(
                    "off-record tag targeted a promoted turn",
                ));
            }
            state.record.clone()
        };
        let mut next_record = record.clone();
        self.with_write_txn(|wtxn| {
            // Fail early on entity kinds the close-path PolicyDelete would
            // refuse anyway (delete-protected engine records).
            if let Some(raw) = self.store.entities.get(wtxn, turn_id.as_bytes())?
                && let Some(&entity_type) = raw.first()
                && crate::registry::is_delete_protected_engine_record(entity_type)
            {
                return Err(Error::MaintenanceKindNotWritable(entity_type));
            }
            let fence_key = off_record_fence_key(turn_id);
            if let Some(existing) = self.store.vault_meta.get(wtxn, &fence_key)? {
                if *existing == *session_ref.as_bytes() {
                    // Idempotent re-tag: the durable fence is already held by
                    // THIS session. ADOPT the turn into the delete-at-close set
                    // if it is not already tracked. Returning `Ok` without
                    // adopting would silently accept a fence with no in-process
                    // delete-at-close coverage (e.g. a fence whose owning
                    // session's `fenced_turns` push was lost, or a crash-orphan
                    // re-tagged under a reused ref), leaving the fenced base turn
                    // undeletable at close. Adoption is safe: the value proves
                    // this turn is genuinely fenced by us, so close deleting it
                    // is correct — it cannot cause wrongful deletion. Chosen over
                    // a stale-fence error because it RESTORES close/delete
                    // coverage instead of forcing the caller to unwind a durable
                    // row it cannot see. No double-push (guarded on the id);
                    // respects the fenced-turn capacity bound.
                    if !next_record.fenced_turns.contains(turn_id.as_bytes()) {
                        if next_record.fenced_turns.len() >= OFF_RECORD_MAX_FENCED_TURNS {
                            return Err(Error::InvariantViolation(
                                "off-record session fenced-turn capacity exceeded",
                            ));
                        }
                        next_record.fenced_turns.push(*turn_id.as_bytes());
                    }
                    #[cfg(feature = "sync")]
                    crate::sync::queue::scrub_outbox_for_off_record_fence_in_txn(self, wtxn)?;
                    return Ok(());
                }
                return Err(Error::InvariantViolation(
                    "off-record fence already held by another session",
                ));
            }
            if next_record.fenced_turns.len() >= OFF_RECORD_MAX_FENCED_TURNS {
                return Err(Error::InvariantViolation(
                    "off-record session fenced-turn capacity exceeded",
                ));
            }
            next_record.fenced_turns.push(*turn_id.as_bytes());
            self.store
                .vault_meta
                .put(wtxn, &fence_key, session_ref.as_bytes())?;
            #[cfg(feature = "sync")]
            crate::sync::queue::scrub_outbox_for_off_record_fence_in_txn(self, wtxn)?;
            Ok(())
        })?;
        {
            let mut state = session_entry_state(&entry)?;
            if state.record.closing || state.gone {
                return Err(Error::OffRecordSessionClosing {
                    session_ref: session_ref.to_owned(),
                });
            }
            if state.record != record && state.record != next_record {
                return Err(Error::InvariantViolation(
                    "off-record session record drifted during tag",
                ));
            }
            if state.record == record {
                state.record = next_record.clone();
                entry.publish_state(&state);
            }
        }

        // The fence is durable before touching the CRDT. If this turn was
        // already present in a registry-owned window, scrub its body and
        // incident edges now instead of waiting for a later packing pass.
        // Export paths also run the same scrub as a fail-closed backstop; a
        // refresh failure therefore must not turn the committed tag into an
        // ambiguous error response.
        #[cfg(feature = "sync")]
        if let Err(error) = self.scrub_tagged_turn_in_live_window(turn_id) {
            tracing::warn!(
                turn = %turn_id.to_hex(),
                error = %error,
                "off-record fence committed but live-window carrier scrub deferred to export"
            );
        }
        #[cfg(feature = "sync")]
        {
            let state = session_entry_state(&entry)?;
            if state.record.closing || state.gone {
                return Err(Error::OffRecordSessionClosing {
                    session_ref: session_ref.to_owned(),
                });
            }
            if state.record != next_record {
                return Err(Error::InvariantViolation(
                    "off-record session record drifted during live-window tag scrub",
                ));
            }
        }

        Ok(())
    }

    /// Scrubs a newly fenced turn from every registry-owned live window.
    /// Incident edges live in their source entity's month, which can differ
    /// from the fenced target's month. This never faults a closed window into
    /// memory; persistence/VV export performs the same whole-doc backstop.
    #[cfg(feature = "sync")]
    fn scrub_tagged_turn_in_live_window(&self, _turn_id: &EntityId) -> Result<()> {
        use crate::sync::window::scrub_off_record_fenced_carriers;

        for window in self.live_windows() {
            scrub_off_record_fenced_carriers(self, &window.key, &window.doc)?;
        }
        Ok(())
    }

    /// Whether `id` is currently fenced off-record (public probe over the
    /// same row the retrieval/extraction filter consults).
    pub fn is_turn_off_record_fenced(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        off_record_fence_active(&self.store, &rtxn, id)
    }

    /// Registers one emit-adjacent context receipt (a retrieval-run record —
    /// its `result_ids` are the activated memory ids) as session-local:
    /// RECEIPTS-FOLLOW-TRANSCRIPT, so close deletes it with the transcript.
    pub fn note_off_record_context_receipt(
        &self,
        session_ref: &str,
        run_id: RetrievalRunId,
    ) -> Result<()> {
        vet_off_record_session_ref(session_ref)?;
        let entry = live_session_entry(&self.store, session_ref)?;
        let mut state = session_entry_state(&entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecordSessionClosing {
                session_ref: session_ref.to_owned(),
            });
        }
        // After a flip, telemetry routes to base and must not be registered
        // for deletion with the pre-flip overlay.
        if state.record.mode != OffRecordMode::OffRecord {
            return Err(Error::InvariantViolation(
                "off-record context receipt requires the session to be in off-record mode",
            ));
        }
        if state.record.context_receipt_runs.contains(&run_id) {
            return Ok(());
        }
        if state.record.context_receipt_runs.len() >= OFF_RECORD_MAX_CONTEXT_RECEIPTS {
            return Err(Error::InvariantViolation(
                "off-record session context-receipt capacity exceeded",
            ));
        }
        state.record.context_receipt_runs.push(run_id);
        entry.publish_state(&state);
        Ok(())
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
    /// Every still-fenced turn is deleted through the pinned ARCH-0038
    /// contract ([`DeleteReason::PolicyDelete`]: CRDT tombstone first,
    /// active-store hard purge, opaque REDACTION_AUDIT receipt,
    /// historical-carrier sweep — the receipts are deletion provenance and
    /// persist as floor receipts). Session-local receipts follow the
    /// transcript: the durable retrieval-run context receipts are deleted,
    /// and the session's [`SessionLocalReceiptLog`] is consumed here — the
    /// one close path — so its emit-adjacent receipts drop with the room.
    /// Promoted turns and their promote receipts are kept.
    ///
    /// Concurrency contract: the FIRST transaction stamps `closing` on the
    /// record, after which every mutator rejects with
    /// [`Error::OffRecordSessionClosing`] — the multi-transaction deletion
    /// pass can never race a tag or promote (a stale snapshot must not
    /// hard-delete a just-promoted, user-consented turn). The FINAL
    /// transaction re-reads the record and fails closed on drift instead of
    /// trusting the snapshot. Fence rows for turns that were MISSING at
    /// delete time become sessionless closed-fence markers: a tag-before-write
    /// turn whose write lands after close is rejected at the entity write
    /// door instead of silently rejoining retrieval. Fence rows for deleted
    /// turns and the session record are removed LAST, so a close interrupted
    /// mid-way can simply be called again (mint a fresh empty log via
    /// [`Vault::off_record_receipt_log`] to retry).
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
        if close_overlay {
            // Session handles lend composed views from `&self`, so safe
            // callers must drop all read views before consuming close.
            entry.overlay.close()?;
        }
        let internal_receipt_log = {
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
            state.receipt_log.take()
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

        let mut turns_deleted = 0_usize;
        let mut missing_turns: Vec<[u8; 16]> = Vec::new();
        let mut redaction_receipt_ids = Vec::new();
        for bytes in &record.fenced_turns {
            let id = EntityId::from_bytes(*bytes)?;
            let outcome = self.delete_entity_with_reason(&id, DeleteReason::PolicyDelete)?;
            if outcome.existed {
                turns_deleted += 1;
            } else {
                let rtxn = self.store.env.read_txn()?;
                let already_hard_deleted =
                    self.local_hard_delete_marker_exists_in_txn(&rtxn, &id)?;
                drop(rtxn);
                if already_hard_deleted {
                    // A crash can land after PolicyDelete's purge transaction
                    // (which writes the permanent `dt:` marker) but before this
                    // close path removes the fence row. On retry the entity is
                    // absent, but it was a written turn already deleted by this
                    // close; treating it as tag-before-write would retain a
                    // permanent closed fence and misreport the outcome.
                    turns_deleted += 1;
                } else {
                    // Fully-missing id: the ARCH-0038 delete is a strict no-op
                    // (no tombstone) — remember it so its fence row is retained.
                    missing_turns.push(*bytes);
                }
            }
            if let Some(receipt_id) = outcome.receipt_id {
                redaction_receipt_ids.push(receipt_id);
            }
        }

        for run_id in &record.context_receipt_runs {
            self.store.delete_retrieval_run(*run_id)?;
        }
        let context_receipts_deleted = record.context_receipt_runs.len();

        // Final cleanup validates the frozen in-process record, removes only
        // legacy fence rows, then drops the registry entry. The session
        // record itself never had a durable row to remove.
        {
            let state = session_entry_state(&entry)?;
            if state.gone || state.record != record {
                return Err(Error::InvariantViolation(
                    "off-record session record drifted during close",
                ));
            }
        }
        self.with_write_txn(|wtxn| {
            for bytes in &record.fenced_turns {
                let id = EntityId::from_bytes(*bytes)?;
                if missing_turns.contains(bytes) {
                    // Keep the write-door denial without retaining the
                    // session ref after close (session metadata evaporates).
                    // A standalone claim preflight can have recorded a gate
                    // decision while this fence was live, before close won
                    // the race and prevented the actual entity write. That
                    // receipt names a turn which never entered the vault, so
                    // delete it with the closed-fence marker rather than
                    // leaking an off-record artifact.
                    self.store
                        .delete_gate_decisions_for_missing_off_record_turn_in_txn(wtxn, &id)?;
                    self.store.vault_meta.put(
                        wtxn,
                        &off_record_fence_key(&id),
                        OFF_RECORD_CLOSED_FENCE_VALUE,
                    )?;
                    continue;
                }
                self.store
                    .vault_meta
                    .delete(wtxn, &off_record_fence_key(&id))?;
            }
            Ok(())
        })?;
        {
            let mut state = session_entry_state(&entry)?;
            if state.gone || state.record != record {
                return Err(Error::InvariantViolation(
                    "off-record session record drifted during close cleanup",
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
            turns_missing: missing_turns.len(),
            context_receipts_deleted,
            emit_receipts_deleted,
            fence_rows_retained: missing_turns.len(),
            promoted_turns_kept: record.promoted_turns.len(),
            redaction_receipt_ids,
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
