//! Vault verbs: session vault handle, enter, mode flip, receipt log and close.

use std::sync::Arc;

use crate::Vault;
use crate::error::{Error, Result};
use crate::receipt::SessionLocalReceiptLog;
use crate::session_overlay::OverlayKeyspace;

use super::registry::{
    OffRecordSessionEntry, OffRecordSessionEntryState, SessionStart, live_session_entry,
    session_entry_state, vet_off_record_session_ref,
};
use super::session::OffRecordSessionVault;
use super::types::{
    OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode, OffRecordSessionRecord,
};
use crate::error::OffRecordError;

impl Vault {
    #[must_use]
    pub fn off_record_session_vault(&self) -> OffRecordSessionVault<'_> {
        OffRecordSessionVault { vault: self }
    }

    /// Explicitly enters off-record mode for `session_ref` (OF-326: enter is
    /// never implicit). Errors with [`OffRecordError::OffRecordSessionAlreadyExists`](crate::error::OffRecordError::OffRecordSessionAlreadyExists)
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
        let entry =
            self.enter_off_record_session_entry(session_ref, backend, budget_bytes, None)?;
        Ok(session_entry_state(&entry)?.record.clone())
    }

    /// `room` is `(room, started_by)` for a stretch a participant starts in a
    /// room; the caller has checked the starter is a member of it.
    pub(super) fn enter_off_record_session_entry(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        budget_bytes: usize,
        room: Option<(crate::EntityId, crate::EntityId)>,
    ) -> Result<Arc<OffRecordSessionEntry>> {
        if !self.config.off_record_enabled {
            return Err(Error::OffRecord(OffRecordError::KillSwitchDisabled));
        }
        vet_off_record_session_ref(session_ref)?;
        if room.is_none() {
            vet_roomless_session_ref(session_ref)?;
        }
        self.store.off_record_sessions.enter(
            session_ref,
            backend,
            budget_bytes,
            OffRecordMode::OffRecord,
            room.map_or(SessionStart::Alone(None), |(room, by)| {
                SessionStart::InRoom(room, by)
            }),
            &self.store.clock,
        )
    }

    /// Enters an immutable anonymous session. Only explicit session-bound
    /// reads are available. Operations requiring stored content or audit
    /// evidence refuse without writing; close leaves no transcript to delete.
    /// It names no entering actor, so its no-record exception keeps the
    /// unchecked rule (see [`Self::off_record_session_is_anonymous_for`]).
    pub fn enter_anonymous_session(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
    ) -> Result<OffRecordSessionRecord> {
        let entry = self.enter_anonymous_session_entry(session_ref, backend, None)?;
        Ok(session_entry_state(&entry)?.record.clone())
    }

    /// `entered_by` is the actor the entering door verified, kept on the
    /// record as the one caller the stretch's no-record exception serves.
    pub(super) fn enter_anonymous_session_entry(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        entered_by: Option<crate::EntityId>,
    ) -> Result<Arc<OffRecordSessionEntry>> {
        if !self.config.off_record_enabled {
            return Err(Error::OffRecord(OffRecordError::KillSwitchDisabled));
        }
        vet_off_record_session_ref(session_ref)?;
        vet_roomless_session_ref(session_ref)?;
        self.store.off_record_sessions.enter(
            session_ref,
            backend,
            0,
            OffRecordMode::Anonymous,
            SessionStart::Alone(entered_by),
            &self.store.clock,
        )
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

    /// Whether a call made for `principal` naming `session_ref` runs inside
    /// an anonymous off-record session that principal is verified in, so it
    /// keeps nothing (ARCH-0052): the one signal OF-538's call receipts and
    /// OF-063's reference-refusal receipts both read, judged afresh each
    /// time either decides to write nothing. `principal` is the person or
    /// actor the request's credential names (its holder), whatever class
    /// acts under it; `None` for a credential that names none.
    ///
    /// The live registry must hold the session in [`OffRecordMode::Anonymous`],
    /// and the principal must be in it (OF-063; a call, canon silent): on its
    /// room's roster now, by the room bind (`bind_for`, which checks the
    /// roster before the name), or, for a stretch entered alone, the actor
    /// its entering door recorded (`entered_by`). Only a caller whose
    /// principal provably differs, one naming another's anonymous session,
    /// has its call and refusal receipts written as anywhere else.
    ///
    /// What cannot be proven keeps the unchecked rule, so a call that might
    /// be a legitimate anonymous one records nothing: a credential that
    /// names no principal (the host root, an OAuth relay, the legacy shared
    /// secret), a stretch entered alone through a door that named no actor
    /// ([`Self::enter_anonymous_session`],
    /// `OffRecordSessionVault::enter_anonymous`, the embedded anonymous
    /// chat), and a session the registry cannot be asked about.
    #[must_use]
    pub fn off_record_session_is_anonymous_for(
        &self,
        session_ref: &str,
        principal: Option<crate::EntityId>,
    ) -> bool {
        let session_ref = session_ref.trim();
        let record = match self.off_record_session(session_ref) {
            Ok(Some(record)) => record,
            Ok(None) => return false,
            Err(_) => return true,
        };
        if record.mode != OffRecordMode::Anonymous {
            return false;
        }
        let Some(principal) = principal else {
            return true;
        };
        if record.room.is_some() {
            return self
                .off_record_session_vault()
                .bind_for(session_ref, principal)
                .is_ok();
        }
        record
            .entered_by
            .is_none_or(|entered_by| entered_by == *principal.as_bytes())
    }

    /// Whether any off-record stretch is open. A host that would write this
    /// process's RAM to disk, a vault VM's snapshot, asks first: no snapshot
    /// while a stretch is open (OFFREC-SNAPSHOT = A).
    #[must_use]
    pub fn has_open_off_record_session(&self) -> bool {
        self.store.off_record_sessions.any_live()
    }

    /// Takes the session back off record (ARCH-0052 D5 / K10). Rows already
    /// in the room stay in the room across the flip.
    ///
    /// * `OffRecord -> OnRecord` is refused here, alone or in a room: on
    ///   record, later turns land in this vault, which is the owner's consent
    ///   to give. Only the owner's proof-bound door,
    ///   [`OffRecordSession::flip_on_record_as`](crate::off_record::OffRecordSession::flip_on_record_as),
    ///   puts a stretch on record.
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
        // A stretch goes on record only through the owner's proof-bound door,
        // `OffRecordSession::flip_on_record_as`, which also tells a room: on
        // record, later turns land in this vault (everyone's, in a room). A
        // closing, anonymous or already on-record session answers as before.
        if mode == OffRecordMode::OnRecord
            && state.record.mode == OffRecordMode::OffRecord
            && !(state.record.closing || state.gone)
        {
            return Err(Error::OffRecord(
                OffRecordError::OffRecordPromoteUnauthenticated {
                    session_ref: session_ref.to_owned(),
                    actor_ref: String::new(),
                },
            ));
        }
        set_entry_mode(&entry, &mut state, session_ref, mode)
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
        let record = self.off_record_session(session_ref)?.ok_or_else(|| {
            Error::OffRecord(OffRecordError::OffRecordSessionNotFound {
                session_ref: session_ref.to_owned(),
            })
        })?;
        record.mode.write_target().require_recording(session_ref)?;
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
    /// which every mutator rejects with [`OffRecordError::OffRecordSessionClosing`](crate::error::OffRecordError::OffRecordSessionClosing), so
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
                return Err(Error::OffRecord(OffRecordError::OffRecordSessionNotFound {
                    session_ref: session_ref.to_owned(),
                }));
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
        // The room's spilled result bodies go with its overlay: nothing it
        // wrote off record outlives the close on disk either.
        #[cfg(unix)]
        self.store.remove_session_bodies(session_ref)?;
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
            .map_or_else(Vec::new, |mut close| std::mem::take(&mut close.retained));

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

/// A stretch entered alone may not take a name a room's stretch is keyed by,
/// so the two never collide.
fn vet_roomless_session_ref(session_ref: &str) -> Result<()> {
    if session_ref.starts_with(super::room::ROOM_KEY_PREFIX) {
        return Err(Error::InvalidConfig(format!(
            "off-record session refs starting with {:?} name a room's stretches",
            super::room::ROOM_KEY_PREFIX
        )));
    }
    Ok(())
}

/// Flips `entry`'s mode under its held state lock, so the overlay's seal or
/// rearm and the record's mode change are one step (see
/// [`Vault::set_off_record_session_mode`]). A handle passes its own entry, so
/// the flip lands on the stretch it holds, never on one that took its name
/// since.
pub(super) fn set_entry_mode(
    entry: &OffRecordSessionEntry,
    state: &mut OffRecordSessionEntryState,
    session_ref: &str,
    mode: OffRecordMode,
) -> Result<OffRecordSessionRecord> {
    if state.record.closing || state.gone {
        return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
            session_ref: session_ref.to_owned(),
        }));
    }
    if state.record.mode == mode {
        return Ok(state.record.clone());
    }
    // Anonymous is an entry-time choice, never a way to hide an existing
    // transcript or later publish one. Check both ends before touching the
    // overlay's lifecycle or publishing another mode.
    state
        .record
        .mode
        .write_target()
        .require_recording(session_ref)?;
    mode.write_target().require_recording(session_ref)?;
    match mode {
        OffRecordMode::Anonymous => unreachable!("anonymous mode change refused above"),
        OffRecordMode::OnRecord => entry.overlay.seal_writes()?,
        OffRecordMode::OffRecord => entry.overlay.rearm()?,
    }
    state.record.mode = mode;
    // Off record again, nobody's vault takes the room's turns.
    if mode != OffRecordMode::OnRecord {
        state.saver = None;
    }
    entry.publish_state(state);
    Ok(state.record.clone())
}
