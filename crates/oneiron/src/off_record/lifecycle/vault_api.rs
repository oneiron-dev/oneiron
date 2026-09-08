//! Vault verbs: session vault handle, enter, mode flip, receipt log and close.

use std::sync::Arc;

use crate::Vault;
use crate::error::{Error, Result};
use crate::receipt::SessionLocalReceiptLog;
use crate::session_overlay::OverlayKeyspace;

use super::registry::{
    OffRecordSessionEntry, live_session_entry, session_entry_state, vet_off_record_session_ref,
};
use super::session::OffRecordSessionVault;
use super::types::{
    OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode, OffRecordSessionRecord,
};

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

    pub(super) fn enter_off_record_session_entry(
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
