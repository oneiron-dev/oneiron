//! NOTE and claim writes through an off-record session's handle (DOOR-127;
//! Engine ruling 10-18 on ARCH-0052 D1/D2). While the room is off record,
//! the row this handle writes stages in the room's overlay
//! (`OffRecordSession::stage_session_rows`): own union reads find it, base
//! readers cannot address it, and close drops it. The same checks the
//! ordinary doors run come first; the room only changes where the row lands.
//!
//! A room on record writes ordinary memory through the ordinary doors, and
//! an anonymous room keeps nothing, so both refuse here.

mod routed;

use super::{
    CommitReceipt, EntityRefReceipt, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    ScopedClaimInput,
};
use crate::off_record::OffRecordSession;
use crate::session_overlay::{RouteTarget, SessionWriteRoute};

impl Memory<'_> {
    /// The route a write through `session` stages under: the room's own,
    /// while it is off record, minted for this one call. A run's writes
    /// stage on the route the run captured instead (`routed`).
    fn session_write_route(
        &self,
        session: &OffRecordSession<'_>,
        ordinary: &str,
    ) -> MemoryResult<SessionWriteRoute> {
        self.same_vault(session)?;
        let route = session.write_route()?;
        self.admit_session_route(session, &route, ordinary)?;
        Ok(route)
    }

    /// Refuses a write through `session` that this handle's vault does not
    /// hold.
    fn same_vault(&self, session: &OffRecordSession<'_>) -> MemoryResult<()> {
        if session.vault_id() != self.vault.vault_id() {
            return Err(MemoryError::bad_request(
                "off-record session belongs to a different vault than this memory facade",
            ));
        }
        Ok(())
    }

    /// Admits `route` for a write through `session`: the room's own, while
    /// it is off record. A route that flipped or went stale refuses; none
    /// re-targets.
    fn admit_session_route(
        &self,
        session: &OffRecordSession<'_>,
        route: &SessionWriteRoute,
        ordinary: &str,
    ) -> MemoryResult<()> {
        self.same_vault(session)?;
        // An anonymous room keeps nothing: the talk-only refusal.
        route.require_recording(session.session_ref())?;
        if route.target() != RouteTarget::Overlay {
            let hint = format!("Write it through {ordinary}.");
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                format!(
                    "off-record session {} is on record: its writes are ordinary memory",
                    session.session_ref()
                ),
                &[hint.as_str()],
            ));
        }
        Ok(())
    }

    /// Creates one NOTE of a registered kind in `session`'s room, its first
    /// authored text as its birth, as [`Self::create_note`] creates one in
    /// the vault. The receipt names the room's short id for it and no
    /// record ref: the row is no vault record unless the vault comes to hold
    /// it. Its NOTE document and its birth stage beside it, the birth
    /// keeping `evidence` as its caller supplied it, each ref read in the
    /// room as a TURN or kept as supplied (FIX 4280, 4281).
    ///
    /// # Errors
    ///
    /// As [`Self::create_note`]; `FORBIDDEN` when the room is anonymous or
    /// full; `INVALID_STATE` when it is on record or closing. Its evidence
    /// never refuses it.
    pub fn create_note_in_session(
        &self,
        session: &OffRecordSession<'_>,
        kind: &str,
        markdown: &str,
        evidence: &[String],
    ) -> MemoryResult<EntityRefReceipt> {
        let route = self.session_write_route(session, "vault.notes.create")?;
        self.prepare_note_in_session(session, &route, kind, markdown, evidence)?
            .stage(session, &route)
            .map_err(MemoryError::from)
    }

    /// Admits one explicitly placed claim into `session`'s room, as
    /// [`Self::claim_upsert_scoped`] admits one into the vault: the same
    /// positions, the same caps, the caller's source and the gate's ruling
    /// on base policy, an `auto` request that the gate refuses asked again
    /// as `proposed`. In the room it supersedes nothing: base's heads stay
    /// as they are, and the room's claim stands beside them until close.
    ///
    /// # Errors
    ///
    /// As [`Self::claim_upsert_scoped`] before its write; the gate's
    /// refusal; `NOT_FOUND` when the room reads no subject;
    /// `FORBIDDEN` when the room is anonymous or full; `INVALID_STATE` when
    /// it is on record or closing, or for a keyed or expression claim.
    pub fn claim_upsert_in_session(
        &self,
        session: &OffRecordSession<'_>,
        input: &ScopedClaimInput,
    ) -> MemoryResult<CommitReceipt> {
        let route = self.session_write_route(session, "vault.claims.upsert")?;
        self.prepare_claim_in_session(session, &route, None, input)?
            .stage(session, &route)
            .map_err(MemoryError::from)
    }
}
