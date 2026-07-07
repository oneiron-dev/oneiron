//! OF-326 off-record / ephemeral session seam (ONE-1546 / OFRC-1).
//!
//! A no-write, evaporating session mode. The seam is four verbs plus one
//! standing law:
//!
//! * **Enter is explicit** — [`Vault::enter_off_record_session`] mints a
//!   durable session record; both parties know (the caller injects
//!   [`off_record_context_marker`] into the agent context, and the marker's
//!   backend-relative disclosure line keeps the evaporation claim honest:
//!   local = real evaporation; cloud/BYO = this engine persists nothing but
//!   provider retention applies to what transited their API).
//! * **THE FENCE** — turns tagged via [`Vault::tag_turn_off_record`] carry a
//!   per-entity fence row that the retrieval/extraction candidate filter
//!   consults unconditionally (`off_record_fence_active`, wired into
//!   `pipeline_candidate_matches_filters_and_gate`). Fenced turns are never
//!   surfaced to witness/extraction, and the tag outlives a same-session
//!   flip back on-record: only promote or delete-at-close lifts it.
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

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::deletion::DeleteReason;
use crate::error::{Error, Result};
use crate::receipt::SessionLocalReceiptLog;
use crate::store::{RetrievalRunId, Store};
use crate::types::EntityId;

/// `vault_meta` key prefix for off-record session records.
const OFF_RECORD_SESSION_KEY_PREFIX: &[u8] = b"offrecord_session:v0:";
/// `vault_meta` key prefix for per-entity fence rows (value = session ref).
const OFF_RECORD_FENCE_KEY_PREFIX: &[u8] = b"offrecord_fence:v0:";
/// `vault_meta` key prefix for durable promote receipts (survive close).
const OFF_RECORD_PROMOTE_KEY_PREFIX: &[u8] = b"offrecord_promote:v0:";

const OFF_RECORD_SESSION_RECORD_VERSION: u8 = 0;
const OFF_RECORD_PROMOTE_RECEIPT_VERSION: u8 = 0;

/// Longest accepted session ref, in bytes (session refs are caller-supplied
/// opaque ids; they become `vault_meta` key suffixes).
const OFF_RECORD_SESSION_REF_MAX_LEN: usize = 256;
/// Hard cap on fenced turns tracked by one session record.
const OFF_RECORD_MAX_FENCED_TURNS: usize = 65_536;
/// Hard cap on session-local context receipts tracked by one session record.
const OFF_RECORD_MAX_CONTEXT_RECEIPTS: usize = 65_536;

/// The mode line injected into the agent context so both parties know the
/// session is off-record (OF-326: no secret recording either way).
pub const OFF_RECORD_SESSION_MARKER_LINE: &str = "This session is OFF-RECORD: nothing said here is written to memory, and the transcript is deleted when the session closes. Outbound actions and commitments are disabled while off-record; taking an action requires exiting off-record mode. The user may explicitly promote a single turn into memory.";

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

impl OffRecordBackendClass {
    /// The honesty line the mode surfaces for this backend.
    #[must_use]
    pub const fn disclosure_line(self) -> &'static str {
        match self {
            Self::Local => {
                "Evaporation is real on this backend: inference is local, nothing leaves this device, and nothing is retained after close."
            }
            Self::RemoteProvider => {
                "This engine persists nothing after close, but inference transits a cloud provider; the provider's own retention policy applies to what crossed its API."
            }
        }
    }
}

/// Builds the full agent-context marker for an off-record session: the mode
/// line plus the backend-relative disclosure line.
#[must_use]
pub fn off_record_context_marker(backend: OffRecordBackendClass) -> String {
    format!(
        "{OFF_RECORD_SESSION_MARKER_LINE}\n{}",
        backend.disclosure_line()
    )
}

/// Durable state of one off-record session, keyed by the caller's opaque
/// session ref. Deleted (with its fence rows) at close.
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
}

/// Durable, user-initiated receipt minted by promote. Survives close: it is
/// the provenance for why one turn outlived the evaporated room. Carries
/// opaque ids only — never turn content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordPromoteReceipt {
    pub version: u8,
    pub session_ref: String,
    pub turn: [u8; 16],
    pub promoted_at: u64,
    /// Always `"user"`: promote exists only as an explicit user consent act.
    pub initiator: String,
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
    /// Promoted turns intentionally left in place.
    pub promoted_turns_kept: usize,
    /// REDACTION_AUDIT receipt ids minted by the per-turn deletions (floor
    /// receipts: they persist).
    pub redaction_receipt_ids: Vec<EntityId>,
}

fn off_record_session_key(session_ref: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(OFF_RECORD_SESSION_KEY_PREFIX.len() + session_ref.len());
    key.extend_from_slice(OFF_RECORD_SESSION_KEY_PREFIX);
    key.extend_from_slice(session_ref.as_bytes());
    key
}

fn off_record_fence_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(OFF_RECORD_FENCE_KEY_PREFIX.len() + 16);
    key.extend_from_slice(OFF_RECORD_FENCE_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

fn off_record_promote_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(OFF_RECORD_PROMOTE_KEY_PREFIX.len() + 16);
    key.extend_from_slice(OFF_RECORD_PROMOTE_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

fn encode_off_record_session(record: &OffRecordSessionRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("off-record session record encode failed"))
}

fn decode_off_record_session(bytes: &[u8]) -> Result<OffRecordSessionRecord> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("off-record session record"))
}

fn encode_off_record_promote(receipt: &OffRecordPromoteReceipt) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(receipt)
        .map_err(|_| Error::InvariantViolation("off-record promote receipt encode failed"))
}

fn decode_off_record_promote(bytes: &[u8]) -> Result<OffRecordPromoteReceipt> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("off-record promote receipt"))
}

fn vet_off_record_session_ref(session_ref: &str) -> Result<()> {
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
/// regardless of the owning session's current mode.
pub(crate) fn off_record_fence_active(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(store
        .vault_meta
        .get(rtxn, &off_record_fence_key(id))?
        .is_some())
}

fn session_record_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    session_ref: &str,
) -> Result<Option<OffRecordSessionRecord>> {
    let Some(bytes) = store
        .vault_meta
        .get(rtxn, &off_record_session_key(session_ref))?
    else {
        return Ok(None);
    };
    let record = decode_off_record_session(bytes)?;
    if record.session_ref != session_ref {
        return Err(Error::CorruptedIndex("off-record session record"));
    }
    Ok(Some(record))
}

impl Vault {
    /// Explicitly enters off-record mode for `session_ref` (OF-326: enter is
    /// never implicit). Errors with [`Error::OffRecordSessionAlreadyExists`]
    /// while a record for the ref exists — a closed session's ref may be
    /// reused because close removes the record.
    pub fn enter_off_record_session(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
    ) -> Result<OffRecordSessionRecord> {
        vet_off_record_session_ref(session_ref)?;
        let record = OffRecordSessionRecord {
            version: OFF_RECORD_SESSION_RECORD_VERSION,
            session_ref: session_ref.to_owned(),
            mode: OffRecordMode::OffRecord,
            backend,
            entered_at: crate::unix_seconds_now(),
            fenced_turns: Vec::new(),
            promoted_turns: Vec::new(),
            context_receipt_runs: Vec::new(),
        };
        let key = off_record_session_key(session_ref);
        let value = encode_off_record_session(&record)?;
        self.with_write_txn(|wtxn| {
            if self.store.vault_meta.get(wtxn, &key)?.is_some() {
                return Err(Error::OffRecordSessionAlreadyExists {
                    session_ref: session_ref.to_owned(),
                });
            }
            self.store.vault_meta.put(wtxn, &key, &value)?;
            Ok(())
        })?;
        Ok(record)
    }

    /// Reads the off-record session record for `session_ref`, if any.
    pub fn off_record_session(&self, session_ref: &str) -> Result<Option<OffRecordSessionRecord>> {
        let rtxn = self.store.env.read_txn()?;
        session_record_in_txn(&self.store, &rtxn, session_ref)
    }

    /// Flips the session's tagging mode (e.g. back on-record mid-session).
    /// Fence rows on already-tagged turns are untouched: THE FENCE holds
    /// across the flip.
    pub fn set_off_record_session_mode(
        &self,
        session_ref: &str,
        mode: OffRecordMode,
    ) -> Result<OffRecordSessionRecord> {
        self.with_write_txn(|wtxn| {
            let mut record =
                session_record_in_txn(&self.store, wtxn, session_ref)?.ok_or_else(|| {
                    Error::OffRecordSessionNotFound {
                        session_ref: session_ref.to_owned(),
                    }
                })?;
            record.mode = mode;
            self.store.vault_meta.put(
                wtxn,
                &off_record_session_key(session_ref),
                &encode_off_record_session(&record)?,
            )?;
            Ok(record)
        })
    }

    /// Tags one turn off-record: writes the fence row and adds the turn to
    /// the session's delete-at-close set. Requires the session to currently
    /// be in [`OffRecordMode::OffRecord`] (turns written after a flip back
    /// on-record are ordinary turns). The turn entity may not exist yet —
    /// tagging BEFORE the turn write closes the race against a concurrent
    /// extraction pass. Idempotent for a turn already fenced by this session.
    pub fn tag_turn_off_record(&self, session_ref: &str, turn_id: &EntityId) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let mut record =
                session_record_in_txn(&self.store, wtxn, session_ref)?.ok_or_else(|| {
                    Error::OffRecordSessionNotFound {
                        session_ref: session_ref.to_owned(),
                    }
                })?;
            if record.mode != OffRecordMode::OffRecord {
                return Err(Error::InvariantViolation(
                    "off-record tag requires the session to be in off-record mode",
                ));
            }
            // Fail early on entity kinds the close-path PolicyDelete would
            // refuse anyway (delete-protected engine records).
            if let Some(raw) = self.store.entities.get(wtxn, turn_id.as_bytes())?
                && let Some(&entity_type) = raw.first()
                && crate::vault::is_delete_protected_engine_record(entity_type)
            {
                return Err(Error::MaintenanceKindNotWritable(entity_type));
            }
            let fence_key = off_record_fence_key(turn_id);
            if let Some(existing) = self.store.vault_meta.get(wtxn, &fence_key)? {
                if existing == session_ref.as_bytes() {
                    return Ok(());
                }
                return Err(Error::InvariantViolation(
                    "off-record fence already held by another session",
                ));
            }
            if record.fenced_turns.len() >= OFF_RECORD_MAX_FENCED_TURNS {
                return Err(Error::InvariantViolation(
                    "off-record session fenced-turn capacity exceeded",
                ));
            }
            record.fenced_turns.push(*turn_id.as_bytes());
            self.store
                .vault_meta
                .put(wtxn, &fence_key, session_ref.as_bytes())?;
            self.store.vault_meta.put(
                wtxn,
                &off_record_session_key(session_ref),
                &encode_off_record_session(&record)?,
            )?;
            Ok(())
        })
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
        self.with_write_txn(|wtxn| {
            let mut record =
                session_record_in_txn(&self.store, wtxn, session_ref)?.ok_or_else(|| {
                    Error::OffRecordSessionNotFound {
                        session_ref: session_ref.to_owned(),
                    }
                })?;
            if record.context_receipt_runs.contains(&run_id) {
                return Ok(());
            }
            if record.context_receipt_runs.len() >= OFF_RECORD_MAX_CONTEXT_RECEIPTS {
                return Err(Error::InvariantViolation(
                    "off-record session context-receipt capacity exceeded",
                ));
            }
            record.context_receipt_runs.push(run_id);
            self.store.vault_meta.put(
                wtxn,
                &off_record_session_key(session_ref),
                &encode_off_record_session(&record)?,
            )?;
            Ok(())
        })
    }

    /// Promotes exactly ONE fenced turn into witness on explicit user
    /// consent: lifts its fence row (extraction may now see it), moves it
    /// out of the delete-at-close set, and mints a durable user-initiated
    /// [`OffRecordPromoteReceipt`] — all in one write transaction.
    pub fn promote_off_record_turn(
        &self,
        session_ref: &str,
        turn_id: &EntityId,
    ) -> Result<OffRecordPromoteReceipt> {
        self.with_write_txn(|wtxn| {
            let mut record =
                session_record_in_txn(&self.store, wtxn, session_ref)?.ok_or_else(|| {
                    Error::OffRecordSessionNotFound {
                        session_ref: session_ref.to_owned(),
                    }
                })?;
            let position = record
                .fenced_turns
                .iter()
                .position(|bytes| bytes == turn_id.as_bytes())
                .ok_or_else(|| Error::OffRecordTurnNotFenced {
                    session_ref: session_ref.to_owned(),
                    turn_ref: turn_id.to_hex(),
                })?;
            record.fenced_turns.remove(position);
            record.promoted_turns.push(*turn_id.as_bytes());
            let receipt = OffRecordPromoteReceipt {
                version: OFF_RECORD_PROMOTE_RECEIPT_VERSION,
                session_ref: session_ref.to_owned(),
                turn: *turn_id.as_bytes(),
                promoted_at: crate::unix_seconds_now(),
                initiator: "user".to_owned(),
            };
            self.store
                .vault_meta
                .delete(wtxn, &off_record_fence_key(turn_id))?;
            self.store.vault_meta.put(
                wtxn,
                &off_record_promote_key(turn_id),
                &encode_off_record_promote(&receipt)?,
            )?;
            self.store.vault_meta.put(
                wtxn,
                &off_record_session_key(session_ref),
                &encode_off_record_session(&record)?,
            )?;
            Ok(receipt)
        })
    }

    /// Reads the durable promote receipt for `turn_id`, if the turn was ever
    /// promoted out of an off-record session.
    pub fn off_record_promote_receipt(
        &self,
        turn_id: &EntityId,
    ) -> Result<Option<OffRecordPromoteReceipt>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self
            .store
            .vault_meta
            .get(&rtxn, &off_record_promote_key(turn_id))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_off_record_promote(bytes)?))
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
    /// Promoted turns and their promote receipts are kept. Fence rows and
    /// the session record are removed LAST, so a close interrupted mid-way
    /// can simply be called again (mint a fresh empty log via
    /// [`Vault::off_record_receipt_log`] to retry).
    pub fn close_off_record_session(
        &self,
        session_ref: &str,
        receipt_log: SessionLocalReceiptLog,
    ) -> Result<OffRecordCloseOutcome> {
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
        let record = self.off_record_session(session_ref)?.ok_or_else(|| {
            Error::OffRecordSessionNotFound {
                session_ref: session_ref.to_owned(),
            }
        })?;
        let receipt_close = receipt_log.close();
        debug_assert!(receipt_close.retained.is_empty());
        let emit_receipts_deleted = receipt_close.deleted;

        let mut turns_deleted = 0_usize;
        let mut turns_missing = 0_usize;
        let mut redaction_receipt_ids = Vec::new();
        for bytes in &record.fenced_turns {
            let id = EntityId::from_bytes(*bytes)?;
            let outcome = self.delete_entity_with_reason(&id, DeleteReason::PolicyDelete)?;
            if outcome.existed {
                turns_deleted += 1;
            } else {
                turns_missing += 1;
            }
            if let Some(receipt_id) = outcome.receipt_id {
                redaction_receipt_ids.push(receipt_id);
            }
        }

        for run_id in &record.context_receipt_runs {
            self.store.delete_retrieval_run(*run_id)?;
        }
        let context_receipts_deleted = record.context_receipt_runs.len();

        self.with_write_txn(|wtxn| {
            for bytes in &record.fenced_turns {
                let id = EntityId::from_bytes(*bytes)?;
                self.store
                    .vault_meta
                    .delete(wtxn, &off_record_fence_key(&id))?;
            }
            self.store
                .vault_meta
                .delete(wtxn, &off_record_session_key(session_ref))?;
            Ok(())
        })?;

        Ok(OffRecordCloseOutcome {
            turns_deleted,
            turns_missing,
            context_receipts_deleted,
            emit_receipts_deleted,
            promoted_turns_kept: record.promoted_turns.len(),
            redaction_receipt_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::outbound::{
        OutboundDispatchActor, OutboundDispatchError, OutboundDispatchGate,
        OutboundDispatchPipeline, OutboundDispatchRequest, OutboundExecutionOutcome,
        OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
        OutboundIntentTrigger,
    };
    use crate::pipeline::{DreamerWorkingSetBudget, DreamerWorkingSetCursor};
    use crate::store::{GateDecisionId, GateDecisionRecord};
    use crate::types::{ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_TURN, TimeRange, VaultConfig};

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
        (tmp, vault)
    }

    fn seed_turn(vault: &Vault, at: u64) -> EntityId {
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange { start: at, end: at },
                at,
                b"off-record fixture turn",
            )
            .expect("seed turn");
        id
    }

    fn surfaced_turns(vault: &Vault) -> Vec<EntityId> {
        vault
            .query()
            .search_temporal(900, 1100, 16)
            .filter_types(&[ENTITY_TYPE_TURN])
            .limit(16)
            .run()
            .expect("pipeline run")
            .into_iter()
            .map(|scored| scored.id)
            .collect()
    }

    fn dreamer_working_set_turns(vault: &Vault) -> Vec<EntityId> {
        vault
            .query()
            .search_temporal(900, 1100, 16)
            .filter_types(&[ENTITY_TYPE_TURN])
            .run_dreamer_working_set(
                DreamerWorkingSetCursor::start(),
                DreamerWorkingSetBudget::new(16),
                16,
            )
            .expect("dreamer working set")
            .rows
            .into_iter()
            .map(|scored| scored.id)
            .collect()
    }

    fn floor_gate_decision() -> GateDecisionRecord {
        GateDecisionRecord {
            version: 0,
            decision_id: GateDecisionId::now(),
            created_at: 10,
            outcome: "allow".to_owned(),
            reason_codes: vec!["gate.policy_model.allow".to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "agent".to_owned(),
            actor_ref: Some("agent-alpha".to_owned()),
            content_kind: "outbound_content".to_owned(),
            policy_manifest_version: "test-policy".to_owned(),
            claim_id: None,
            grant_ref: None,
            diff_handle: vec![0xA5],
            read_frontier_hash: [0xB6; 32],
        }
    }

    struct PanicSink;

    impl OutboundExecutionSink for PanicSink {
        fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
            panic!("execution sink must not run in these tests");
        }
    }

    fn talk_only_request(session_ref: &str) -> OutboundDispatchRequest {
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com"),
            OutboundIntentTrigger::agent_immediate("intent:off-record-test"),
        );
        OutboundDispatchRequest::new(
            "receipt-off-record-test",
            "intent-off-record-test",
            intent,
            OutboundDispatchActor::agent(EntityId::now()),
            OutboundDispatchGate::allow_when_policy_grants(),
            100,
        )
        .originating_session(session_ref)
    }

    #[test]
    fn off_record_enter_is_explicit_marked_and_single_shot() {
        let (_tmp, vault) = temp_vault();
        let record = vault
            .enter_off_record_session("sess-enter", OffRecordBackendClass::Local)
            .expect("enter");
        assert_eq!(record.mode, OffRecordMode::OffRecord);
        assert_eq!(record.backend, OffRecordBackendClass::Local);
        assert!(record.fenced_turns.is_empty());

        let double_enter = vault
            .enter_off_record_session("sess-enter", OffRecordBackendClass::Local)
            .expect_err("enter is single-shot");
        assert_eq!(
            double_enter.kind(),
            ErrorKind::OffRecordSessionAlreadyExists
        );

        // Disclosure honesty is backend-relative and rides the marker.
        let local = off_record_context_marker(OffRecordBackendClass::Local);
        let remote = off_record_context_marker(OffRecordBackendClass::RemoteProvider);
        assert!(local.contains(OFF_RECORD_SESSION_MARKER_LINE));
        assert!(remote.contains(OFF_RECORD_SESSION_MARKER_LINE));
        assert!(local.contains(OffRecordBackendClass::Local.disclosure_line()));
        assert!(remote.contains(OffRecordBackendClass::RemoteProvider.disclosure_line()));
        assert_ne!(local, remote);
    }

    #[test]
    fn off_record_fenced_turns_are_unextractable_including_post_flip() {
        let (_tmp, vault) = temp_vault();
        let fenced = seed_turn(&vault, 1000);
        let plain = seed_turn(&vault, 1001);
        vault
            .enter_off_record_session("sess-fence", OffRecordBackendClass::Local)
            .expect("enter");
        vault
            .tag_turn_off_record("sess-fence", &fenced)
            .expect("tag");
        assert!(vault.is_turn_off_record_fenced(&fenced).expect("probe"));

        let surfaced = surfaced_turns(&vault);
        assert!(!surfaced.contains(&fenced), "fenced turn surfaced");
        assert!(surfaced.contains(&plain), "plain turn missing");

        let working_set = dreamer_working_set_turns(&vault);
        assert!(
            !working_set.contains(&fenced),
            "fenced turn reached the dreamer working set"
        );
        assert!(working_set.contains(&plain));

        // Flip back on-record: the fence holds on the lingering turn, new
        // turns are ordinary, and tagging is rejected outside the mode.
        vault
            .set_off_record_session_mode("sess-fence", OffRecordMode::OnRecord)
            .expect("flip");
        let post_flip = seed_turn(&vault, 1002);
        let surfaced = surfaced_turns(&vault);
        assert!(
            !surfaced.contains(&fenced),
            "fence must outlive the flip back on-record"
        );
        assert!(surfaced.contains(&post_flip));
        vault
            .tag_turn_off_record("sess-fence", &post_flip)
            .expect_err("tagging requires off-record mode");
    }

    #[test]
    fn off_record_outbound_rejected_in_mode_with_typed_error() {
        let (_tmp, vault) = temp_vault();
        vault
            .enter_off_record_session("sess-talk", OffRecordBackendClass::RemoteProvider)
            .expect("enter");

        let error = OutboundDispatchPipeline
            .dispatch(&vault, talk_only_request("sess-talk"), &mut PanicSink)
            .expect_err("in-mode outbound must be rejected");
        match error {
            OutboundDispatchError::Engine(Error::OffRecordTalkOnly { session_ref }) => {
                assert_eq!(session_ref, "sess-talk");
            }
            other => panic!("expected OffRecordTalkOnly, got {other:?}"),
        }

        // Flipped back on-record the rejection lifts, and the OF-333 floor
        // classifies the egress (gate decision = persistent floor receipt).
        vault
            .set_off_record_session_mode("sess-talk", OffRecordMode::OnRecord)
            .expect("flip");
        let result = OutboundDispatchPipeline
            .dispatch(&vault, talk_only_request("sess-talk"), &mut PanicSink)
            .expect("post-flip dispatch reaches the gate");
        drop(result);
        assert!(
            !vault.gate_decisions(10).expect("gate decisions").is_empty(),
            "floor must classify post-flip egress"
        );
    }

    #[test]
    fn off_record_close_deletes_transcript_and_context_receipts_keeps_floor_receipts() {
        let (_tmp, vault) = temp_vault();
        let fenced_a = seed_turn(&vault, 1000);
        let fenced_b = seed_turn(&vault, 1001);
        vault
            .enter_off_record_session("sess-close", OffRecordBackendClass::Local)
            .expect("enter");
        vault
            .tag_turn_off_record("sess-close", &fenced_a)
            .expect("tag a");
        vault
            .tag_turn_off_record("sess-close", &fenced_b)
            .expect("tag b");

        // Emit-adjacent context receipt: a real retrieval run (result_ids =
        // activated memory ids), registered session-local.
        let telemetry = vault
            .query()
            .search_temporal(900, 1100, 16)
            .filter_types(&[ENTITY_TYPE_TURN])
            .limit(16)
            .run_with_telemetry()
            .expect("retrieval with telemetry");
        let run_id = telemetry.run_id.expect("telemetry run id");
        vault
            .note_off_record_context_receipt("sess-close", run_id)
            .expect("note context receipt");
        assert!(vault.retrieval_run(run_id).expect("run lookup").is_some());

        // Emit-adjacent dispatch receipt: rides the session-local log that
        // close consumes (RECEIPTS-FOLLOW-TRANSCRIPT, ONE-1544 seam).
        let mut receipt_log = vault
            .off_record_receipt_log("sess-close")
            .expect("mint receipt log");
        let emit_receipt = crate::receipt::outbound_intent_receipt(
            "receipt-off-record-close",
            "intent-off-record-close",
            &OutboundIntent::from_trigger(
                OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com"),
                OutboundIntentTrigger::agent_immediate("intent:off-record-close"),
            ),
            100,
            "delivered_to_channel",
        );
        receipt_log.record(emit_receipt).expect("log emit receipt");
        assert_eq!(receipt_log.receipts().len(), 1);

        // Floor receipt (OF-333 egress classification): persists.
        let floor = floor_gate_decision();
        vault
            .with_write_txn(|wtxn| vault.store.append_gate_decision_in_txn(wtxn, &floor))
            .expect("record floor receipt");

        // Binding is validated: another session's log or an on-record log
        // cannot close this session.
        let foreign_log = SessionLocalReceiptLog::off_record("sess-other");
        let mismatch = vault
            .close_off_record_session("sess-close", foreign_log)
            .expect_err("foreign log rejected");
        assert_eq!(mismatch.kind(), ErrorKind::InvariantViolation);
        let on_record_log = SessionLocalReceiptLog::on_record("sess-close");
        let wrong_mode = vault
            .close_off_record_session("sess-close", on_record_log)
            .expect_err("on-record log rejected");
        assert_eq!(wrong_mode.kind(), ErrorKind::InvariantViolation);

        let outcome = vault
            .close_off_record_session("sess-close", receipt_log)
            .expect("close");
        assert_eq!(outcome.turns_deleted, 2);
        assert_eq!(outcome.turns_missing, 0);
        assert_eq!(outcome.context_receipts_deleted, 1);
        assert_eq!(outcome.emit_receipts_deleted, 1);
        assert_eq!(outcome.promoted_turns_kept, 0);
        assert_eq!(outcome.redaction_receipt_ids.len(), 2);

        // Transcript gone (ARCH-0038 PolicyDelete hard purge)...
        assert!(vault.get(&fenced_a).expect("read a").is_none());
        assert!(vault.get(&fenced_b).expect("read b").is_none());
        // ...context receipts gone with it...
        assert!(vault.retrieval_run(run_id).expect("run lookup").is_none());
        // ...floor receipts remain: the gate decision, and the opaque
        // redaction-audit receipts minted by the deletion itself.
        assert!(!vault.gate_decisions(10).expect("gate decisions").is_empty());
        for receipt_id in &outcome.redaction_receipt_ids {
            assert_eq!(
                vault.get_entity_type(receipt_id).expect("receipt type"),
                Some(ENTITY_TYPE_REDACTION_AUDIT)
            );
        }
        // Session record and fence rows are gone; close is not replayable.
        assert!(
            vault
                .off_record_session("sess-close")
                .expect("session lookup")
                .is_none()
        );
        assert!(!vault.is_turn_off_record_fenced(&fenced_a).expect("probe"));
        let reclose = vault
            .close_off_record_session(
                "sess-close",
                SessionLocalReceiptLog::off_record("sess-close"),
            )
            .expect_err("second close");
        assert_eq!(reclose.kind(), ErrorKind::OffRecordSessionNotFound);
        // The log helper is bound to a live session too.
        let stale_log = vault
            .off_record_receipt_log("sess-close")
            .expect_err("log requires live session");
        assert_eq!(stale_log.kind(), ErrorKind::OffRecordSessionNotFound);
    }

    #[test]
    fn off_record_promote_writes_exactly_one_turn() {
        let (_tmp, vault) = temp_vault();
        let kept = seed_turn(&vault, 1000);
        let dropped_a = seed_turn(&vault, 1001);
        let dropped_b = seed_turn(&vault, 1002);
        vault
            .enter_off_record_session("sess-promote", OffRecordBackendClass::Local)
            .expect("enter");
        for id in [&kept, &dropped_a, &dropped_b] {
            vault.tag_turn_off_record("sess-promote", id).expect("tag");
        }
        assert!(surfaced_turns(&vault).is_empty());

        let receipt = vault
            .promote_off_record_turn("sess-promote", &kept)
            .expect("promote");
        assert_eq!(receipt.turn, *kept.as_bytes());
        assert_eq!(receipt.session_ref, "sess-promote");
        assert_eq!(receipt.initiator, "user");

        // Exactly one turn crossed the fence.
        let record = vault
            .off_record_session("sess-promote")
            .expect("session lookup")
            .expect("session record");
        assert_eq!(record.fenced_turns.len(), 2);
        assert_eq!(record.promoted_turns, vec![*kept.as_bytes()]);
        let surfaced = surfaced_turns(&vault);
        assert_eq!(surfaced, vec![kept]);

        let repromote = vault
            .promote_off_record_turn("sess-promote", &kept)
            .expect_err("promote lifts one live fence");
        assert_eq!(repromote.kind(), ErrorKind::OffRecordTurnNotFenced);

        let receipt_log = vault
            .off_record_receipt_log("sess-promote")
            .expect("mint receipt log");
        let outcome = vault
            .close_off_record_session("sess-promote", receipt_log)
            .expect("close");
        assert_eq!(outcome.turns_deleted, 2);
        assert_eq!(outcome.emit_receipts_deleted, 0);
        assert_eq!(outcome.promoted_turns_kept, 1);

        // The promoted turn and its user-initiated receipt survive close.
        assert!(vault.get(&kept).expect("read kept").is_some());
        assert!(vault.get(&dropped_a).expect("read a").is_none());
        assert!(vault.get(&dropped_b).expect("read b").is_none());
        assert_eq!(surfaced_turns(&vault), vec![kept]);
        let persisted = vault
            .off_record_promote_receipt(&kept)
            .expect("receipt lookup")
            .expect("promote receipt persists");
        assert_eq!(persisted, receipt);
    }
}
