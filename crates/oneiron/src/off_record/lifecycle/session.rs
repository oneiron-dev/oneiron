//! Session and vault handles: routes, shells, search, VaultMeta family, flips, receipts, close.

use std::sync::Arc;

use crate::ScoredEntity;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptRecord, SessionLocalReceiptLog};
use crate::session_overlay::{
    OverlayKeyspace, RouteTarget, SessionOverlay, SessionWriteRoute, SnapshotLookup,
};
use crate::side_table::{SideCodec, SideKey, SideTable};
use crate::vault::VaultId;

use super::on_record::OnRecordSaver;
use super::participant::RunParticipant;
use super::registry::{
    OffRecordSessionEntry, live_session_entry, session_entry_state, vet_off_record_session_ref,
};
use super::telemetry::SessionRetrievalTelemetry;
use super::types::{OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode};
use crate::error::OffRecordError;

/// Vault-bound factory for explicit off-record session entry.
pub struct OffRecordSessionVault<'vault> {
    pub(super) vault: &'vault Vault,
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
    pub(in crate::off_record) vault: &'vault Vault,
    pub(super) session_ref: String,
    pub(super) entry: Arc<OffRecordSessionEntry>,
    /// The participant a run's handle acts as; `None` on every other handle.
    pub(super) participant: Option<RunParticipant>,
}

impl<'vault> OffRecordSessionVault<'vault> {
    /// A handle on the stretch `entry` registers under `session_ref`.
    pub(super) fn handle(
        &self,
        session_ref: String,
        entry: Arc<OffRecordSessionEntry>,
    ) -> OffRecordSession<'vault> {
        OffRecordSession {
            vault: self.vault,
            session_ref,
            entry,
            participant: None,
        }
    }

    /// Enters anonymous mode. No session content or receipt is retained, and
    /// the mode cannot be flipped or promoted into persistence. It names no
    /// entering actor; a door that verified one enters through
    /// [`Self::enter_anonymous_as`].
    pub fn enter_anonymous(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
    ) -> Result<OffRecordSession<'vault>> {
        let entry = self
            .vault
            .enter_anonymous_session_entry(session_ref, backend, None)?;
        Ok(self.handle(session_ref.to_owned(), entry))
    }

    /// [`Self::enter_anonymous`] on the owner's proof: the stretch keeps the
    /// owner's live person as the actor who entered it, the one caller its
    /// no-record exception serves (`Vault::off_record_session_is_anonymous_for`,
    /// OF-063). That is the id the HTTP facade and the MCP gateway carry for
    /// the same owner's credential: its bound principal.
    pub fn enter_anonymous_as(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<OffRecordSession<'vault>> {
        let actor = owner.revalidate(self.vault)?;
        let entry = self
            .vault
            .enter_anonymous_session_entry(session_ref, backend, Some(actor))?;
        Ok(self.handle(session_ref.to_owned(), entry))
    }

    pub fn enter(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
    ) -> Result<OffRecordSession<'vault>> {
        let entry = self.vault.enter_off_record_session_entry(
            session_ref,
            backend,
            self.vault.config.off_record_overlay_budget_bytes,
            None,
        )?;
        Ok(self.handle(session_ref.to_owned(), entry))
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
    /// [`OffRecordError::OffRecordSessionNotFound`](crate::error::OffRecordError::OffRecordSessionNotFound) for an unknown ref and
    /// [`OffRecordError::OffRecordSessionClosing`](crate::error::OffRecordError::OffRecordSessionClosing) for one whose close pass has begun
    /// or finished — the same typed refusals every other session mutator
    /// raises, so a binder cannot tell a closing room from a live one by
    /// error shape alone.
    pub fn bind(&self, session_ref: &str) -> Result<OffRecordSession<'vault>> {
        vet_off_record_session_ref(session_ref)?;
        let entry = live_session_entry(&self.vault.store, session_ref)?;
        let state = session_entry_state(&entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: session_ref.to_owned(),
            }));
        }
        drop(state);
        Ok(self.handle(session_ref.to_owned(), entry))
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
                .enter_off_record_session_entry(session_ref, backend, budget_bytes, None)?;
        Ok(self.handle(session_ref.to_owned(), entry))
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
        self.route_and_saver().map(|(route, _)| route)
    }

    /// [`Self::write_route`] and, for a `Base` route, the saver whose vault
    /// it lands in, read under the same lock.
    pub(super) fn route_and_saver(&self) -> Result<(SessionWriteRoute, Option<OnRecordSaver>)> {
        let state = session_entry_state(&self.entry)?;
        if state.record.closing || state.gone {
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            }));
        }
        let target = state.record.mode.write_target();
        let saver = match target {
            RouteTarget::Base => state.saver.clone(),
            RouteTarget::Overlay | RouteTarget::Discard => None,
        };
        Ok((SessionWriteRoute::mint(&self.entry.overlay, target)?, saver))
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
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            }));
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
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            }));
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
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            }));
        }
        if state.record.mode != OffRecordMode::OnRecord {
            return Err(Error::InvariantViolation(
                "the on-record continuation shell is only reachable while on record",
            ));
        }
        if state.continuation_shell.is_none() {
            state.continuation_shell = Some(self.vault.store.clock.entity_id()?);
        }
        state
            .continuation_shell
            .ok_or(Error::InvariantViolation("continuation shell allocation"))
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
    /// [`ScoredEntity`] and the executor's `vault.search` outcome
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
        self.search_text_routed_over(route, query, limit, true)
    }

    /// [`Self::search_text_routed`] over base's postings alone, for a reader
    /// that reads base alone in this room (a credential that cannot place
    /// the room's rows): the room's words choose nothing it reads. Its run
    /// still goes through the room's door.
    pub(crate) fn search_base_text_routed(
        &self,
        route: &SessionWriteRoute,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        self.search_text_routed_over(route, query, limit, false)
    }

    fn search_text_routed_over(
        &self,
        route: &SessionWriteRoute,
        query: &str,
        limit: usize,
        room: bool,
    ) -> Result<Vec<ScoredEntity>> {
        route.revalidate()?;
        let profile = crate::config::Bm25RankProfile::default();
        let admit = |txn: &heed::RoTxn<'_>| self.participant_in_txn(txn);
        let (search, holds_room_rows) = if room {
            let view = self.read_view()?;
            let search = self
                .vault
                .search_text_scored(&view, query, limit, &profile, admit)?;
            (search, view.read().holds_room_rows())
        } else {
            let search =
                self.vault
                    .search_text_scored(&self.vault.store, query, limit, &profile, admit)?;
            (search, false)
        };

        let telemetry = self.retrieval_telemetry(route)?;
        // A search that read the room may name its rows while it holds any,
        // and base holds no reference to a live overlay row (the taint guard
        // covers references): on record, such a run keeps no row in base,
        // though its saver must still hold.
        if !self.vault.store.retrieval_telemetry_capture_enabled() {
            telemetry.revalidate_without_capture()?;
            return Ok(search.scores);
        }
        if telemetry.writes_to_base() && holds_room_rows {
            telemetry.admit_withheld_write()?;
            return Ok(search.scores);
        }
        let record = Vault::vault_search_retrieval_run_record(
            crate::store::RetrievalRunId::from_bytes(self.vault.store.clock.ulid()?),
            crate::store::RetrievalSignal::Text,
            search.started_at,
            search.started,
            &search.scores,
            limit,
        );
        // Both targets go through the room's one registration door, so the
        // in-room BM25 path and the assembled paths cannot drift: the overlay
        // arm stages under the route, and the base arm — post-flip the room is
        // on record and, once it holds no row of its own, telemetry routes to
        // base ordinarily (K10) — publishes under the same route rather than
        // through the routeless canonical door.
        telemetry.register_run(&record, false)?;

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
    /// route, every write. On record, the route lands under its
    /// saver, and each base write checks the saver again in its own
    /// transaction, as every other landing does.
    pub(crate) fn retrieval_telemetry<'session>(
        &'session self,
        route: &'session SessionWriteRoute,
    ) -> Result<SessionRetrievalTelemetry<'session>> {
        route.revalidate()?;
        Ok(SessionRetrievalTelemetry {
            vault: self.vault,
            landing: self.landing(route)?,
        })
    }

    /// Mode-aware side-table write (ONE-1728 K10): the overlay keyspace while
    /// `OffRecord`, the base table while `OnRecord`.
    ///
    /// The route revalidates before anything is staged, so a write minted
    /// against a mode epoch that a concurrent flip has replaced is refused
    /// rather than landing in the wrong place. The base half runs inside this
    /// module's private vault access; no vault getter escapes.
    #[cfg(test)]
    pub(crate) fn side_table_put<K: SideKey, V, C: SideCodec<V>>(
        &self,
        table: &SideTable<K, V, C>,
        key: &K,
        value: &V,
    ) -> Result<()> {
        self.side_table_put_routed(&self.write_route()?, table, key, value)
    }

    /// The same write against a route the CALLER captured.
    ///
    /// Long-lived writers (ONE-1729's executor run) capture one route at run
    /// entry and apply everything through it, so a mid-run flip is caught by
    /// that route's own `revalidate` instead of being papered over by a fresh
    /// mint per call. [`Self::side_table_put`] is the one-shot sibling for
    /// callers with no run to bind to; both share this body, so the two
    /// cannot drift in keyspace or ordering.
    pub(crate) fn side_table_put_routed<K: SideKey, V, C: SideCodec<V>>(
        &self,
        route: &SessionWriteRoute,
        table: &SideTable<K, V, C>,
        key: &K,
        value: &V,
    ) -> Result<()> {
        self.side_table_compare_and_put_routed(route, table, key, value, |_| Ok(()))
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
    pub(crate) fn side_table_compare_and_put_routed<K: SideKey, V, C: SideCodec<V>>(
        &self,
        route: &SessionWriteRoute,
        table: &SideTable<K, V, C>,
        key: &K,
        value: &V,
        accepts_current: impl FnOnce(Option<&V>) -> Result<()>,
    ) -> Result<()> {
        route.require_recording(&self.session_ref)?;
        match route.target() {
            RouteTarget::Discard => unreachable!("anonymous recording refused above"),
            RouteTarget::Overlay => {
                // Same base-writer-then-segment-permit order as the retrieval
                // arm above: the permit is never held while waiting for the
                // base writer. The composed read is taken after the segment
                // installs so it cannot miss a room-mate's just-applied row.
                let overlay = self.entry.overlay.clone();
                let segment = self.vault.with_write_txn_grouped(|wtxn| {
                    let segment = overlay.install_txn_segment()?;
                    self.participant_in_txn(wtxn)?;
                    route.revalidate()?;
                    let view = self.vault.store.session_view(overlay.clone())?;
                    accepts_current(table.get(&view, wtxn, key)?.as_ref())?;
                    table.put(&view, wtxn, key, value)?;
                    Ok(segment)
                })?;
                segment.commit()
            }
            // A stretch on record writes here only while its saver holds.
            RouteTarget::Base => {
                self.with_saver_write_txn(self.saver_check_for(route)?, |wtxn| {
                    route.revalidate()?;
                    // Composed, not base-only: the row this run is updating
                    // may still be the overlay row an earlier off-record run
                    // of the same room wrote, which is exactly what the
                    // unconditional read sees.
                    let view = self.vault.store.session_view(self.entry.overlay.clone())?;
                    accepts_current(table.get(&view, wtxn, key)?.as_ref())?;
                    table.put(&self.vault.store, wtxn, key, value)
                })
            }
        }
    }

    /// One transaction over side tables on a route the caller captured, in
    /// which `f` reads every row through the composed view and writes along
    /// the route: [`Self::side_table_compare_and_put_routed`]'s two arms with
    /// the body handed over. `f` gets the base write transaction too, so a
    /// base row it writes (a spend scope) commits with the routed ones.
    ///
    /// While the room is off record the reads and writes are the view's,
    /// staged into one segment that commits with the base transaction. Once
    /// it is on record they write base, and only while the saver holds; the
    /// reads stay composed, since a row may still be one an earlier
    /// off-record run of the room wrote.
    pub(crate) fn routed_side_txn<T>(
        &self,
        route: &SessionWriteRoute,
        f: impl FnOnce(
            &mut heed::RwTxn<'_>,
            crate::side_table::RoutedDbs<'_>,
            crate::side_table::RoutedDbs<'_>,
        ) -> Result<T>,
    ) -> Result<T> {
        use crate::side_table::RoutedDbs;
        route.require_recording(&self.session_ref)?;
        match route.target() {
            RouteTarget::Discard => unreachable!("anonymous recording refused above"),
            RouteTarget::Overlay => {
                let overlay = self.entry.overlay.clone();
                let (segment, answer) = self.vault.with_write_txn_grouped(|wtxn| {
                    let segment = overlay.install_txn_segment()?;
                    self.participant_in_txn(wtxn)?;
                    route.revalidate()?;
                    let view = self.vault.store.session_view(overlay.clone())?;
                    let answer = f(wtxn, RoutedDbs::Session(&view), RoutedDbs::Session(&view))?;
                    Ok((segment, answer))
                })?;
                segment.commit()?;
                Ok(answer)
            }
            RouteTarget::Base => self.with_saver_write_txn(self.saver_check_for(route)?, |wtxn| {
                route.revalidate()?;
                let view = self.vault.store.session_view(self.entry.overlay.clone())?;
                f(
                    wtxn,
                    RoutedDbs::Session(&view),
                    RoutedDbs::Base(&self.vault.store),
                )
            }),
        }
    }

    /// One composed read of side tables over overlay ∪ base, while the
    /// handle's participant is in the room, checked in the read.
    pub(crate) fn routed_side_read<T>(
        &self,
        f: impl FnOnce(&heed::RoTxn<'_>, crate::side_table::RoutedDbs<'_>) -> Result<T>,
    ) -> Result<T> {
        let view = self.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        self.participant_in_txn(&rtxn)?;
        f(&rtxn, crate::side_table::RoutedDbs::Session(&view))
    }

    /// The base spend scopes this session's reader children spend under
    /// (OF-532): units and ids, no content.
    pub(crate) fn spend_book(&self) -> crate::code_run::SpendBook<'_> {
        crate::code_run::SpendBook::new(self.vault)
    }

    /// The runner this session's vault wakes its reader children through.
    pub(crate) fn reader_job_runner(&self) -> Option<Arc<dyn crate::code_run::ReaderJobRunner>> {
        self.vault.reader_job_runner()
    }

    /// One overlay write of the caller's own, on a route the caller captured:
    /// [`Self::side_table_compare_and_put_routed`]'s Overlay arm with the
    /// body handed over. `write` runs inside the base writer once the segment
    /// is installed and the participant and route are checked; `apply`
    /// stages one journaled op through the session apply, on a fresh view, so
    /// each op sees the ones before it. A fresh [`Self::read_view`] inside
    /// `write` sees them too. Everything staged commits with the segment, or
    /// none of it does.
    ///
    /// Only an `Overlay` route writes here. A late writer whose room flipped
    /// or closed meets the route's own refusal, not a write.
    pub(crate) fn overlay_write_routed<T>(
        &self,
        route: &SessionWriteRoute,
        write: impl FnOnce(
            &mut heed::RwTxn<'_>,
            &dyn Fn(&mut heed::RwTxn<'_>, crate::session_overlay::JournalEntry) -> Result<()>,
        ) -> Result<T>,
    ) -> Result<T> {
        route.require_recording(&self.session_ref)?;
        if route.target() != RouteTarget::Overlay {
            return Err(Error::InvariantViolation(
                "an overlay write needs an Overlay route",
            ));
        }
        let overlay = self.entry.overlay.clone();
        let apply: &dyn Fn(
            &mut heed::RwTxn<'_>,
            crate::session_overlay::JournalEntry,
        ) -> Result<()> = &|wtxn, entry| {
            crate::batch::apply_ops_session(
                &self.read_view()?,
                route,
                &self.vault.config,
                &self.vault.analyzer,
                wtxn,
                vec![entry],
            )
        };
        let (segment, written) = self.vault.with_write_txn_grouped(|wtxn| {
            let segment = overlay.install_txn_segment()?;
            self.participant_in_txn(wtxn)?;
            route.revalidate()?;
            let written = write(wtxn, apply)?;
            Ok((segment, written))
        })?;
        segment.commit()?;
        Ok(written)
    }

    /// Atomically compare-and-put one routed side-table row and update one
    /// additive counter contribution beside it (ONE-1929).
    ///
    /// The counter has two components: the durable base value and this room's
    /// overlay-local delta. Overlay writes advance only the delta; base writes
    /// advance only the base value. Reading their sum prevents an overlay row
    /// from shadowing canonical increments that commit after the room first
    /// touched the counter, which is what makes the executor's per-model heal
    /// tally survive an off-record -> on-record flip additively instead of
    /// losing one side.
    ///
    /// Both arms do the compare, the row put and the counter put inside ONE
    /// transaction, so a refused comparison writes neither and a committed
    /// append can never be followed by a lost or double-counted tally.
    #[expect(
        clippy::too_many_arguments,
        reason = "one routed transaction over two typed tables: each table travels with its key, \
                  and the compare and the counter update are the caller's protocol"
    )]
    pub(crate) fn side_table_compare_and_put_with_counter_routed<K, V, C, CK, CV, CC>(
        &self,
        route: &SessionWriteRoute,
        table: &SideTable<K, V, C>,
        key: &K,
        value: &V,
        accepts_current: impl FnOnce(Option<&V>) -> Result<()>,
        counter: &SideTable<CK, CV, CC>,
        counter_key: &CK,
        update_counter: impl FnOnce(Option<CV>, Option<CV>, RouteTarget) -> Result<(CV, u64)>,
    ) -> Result<u64>
    where
        K: SideKey,
        C: SideCodec<V>,
        CK: SideKey,
        CC: SideCodec<CV>,
    {
        route.require_recording(&self.session_ref)?;
        let target = route.target();
        if target == RouteTarget::Discard {
            unreachable!("anonymous recording refused above");
        }
        let overlay = self.entry.overlay.clone();
        // A stretch on record writes into base only while its saver holds.
        let check = self.saver_check_for(route)?;
        let (segment, total) = self.with_saver_write_txn(check, |wtxn| {
            let segment = match target {
                RouteTarget::Overlay => Some(overlay.install_txn_segment()?),
                RouteTarget::Base | RouteTarget::Discard => None,
            };
            route.revalidate()?;
            let view = self.vault.store.session_view(overlay.clone())?;
            accepts_current(table.get(&view, wtxn, key)?.as_ref())?;
            let base = counter.get(&self.vault.store, wtxn, counter_key)?;
            let delta = self.overlay_counter_delta(counter, counter_key)?;
            let (next_counter, total) = update_counter(base, delta, target)?;
            if target == RouteTarget::Overlay {
                table.put(&view, wtxn, key, value)?;
                counter.put(&view, wtxn, counter_key, &next_counter)?;
            } else {
                table.put(&self.vault.store, wtxn, key, value)?;
                counter.put(&self.vault.store, wtxn, counter_key, &next_counter)?;
            }
            Ok((segment, total))
        })?;
        if let Some(segment) = segment {
            segment.commit()?;
        }
        Ok(total)
    }

    /// This room's overlay-local contribution to an additive counter row;
    /// `None` when the overlay holds no row for it.
    fn overlay_counter_delta<K: SideKey, V, C: SideCodec<V>>(
        &self,
        counter: &SideTable<K, V, C>,
        key: &K,
    ) -> Result<Option<V>> {
        match self
            .entry
            .overlay
            .snapshot()?
            .lookup_single(OverlayKeyspace::VaultMeta, &counter.key_bytes(key))
        {
            SnapshotLookup::Present(value) => counter.decode_value(&value).map(Some),
            SnapshotLookup::Passthrough | SnapshotLookup::Tombstone => Ok(None),
        }
    }

    /// The base and room-overlay components of an additive side-table
    /// counter. Ordinary composed reads intentionally keep shadow semantics;
    /// only additive counters opt into this explicit merge.
    #[cfg(test)]
    pub(crate) fn side_table_counter_components<K: SideKey, V, C: SideCodec<V>>(
        &self,
        counter: &SideTable<K, V, C>,
        key: &K,
    ) -> Result<(Option<V>, Option<V>)> {
        let overlay = self.overlay_counter_delta(counter, key)?;
        let rtxn = self.vault.store.env.read_txn()?;
        self.participant_in_txn(&rtxn)?;
        Ok((counter.get(&self.vault.store, &rtxn, key)?, overlay))
    }

    /// Composed side-table read over overlay ∪ base. A run's handle reads
    /// only while its participant is in the room, checked in the read.
    pub(crate) fn side_table_get<K: SideKey, V, C: SideCodec<V>>(
        &self,
        table: &SideTable<K, V, C>,
        key: &K,
    ) -> Result<Option<V>> {
        let view = self.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        self.participant_in_txn(&rtxn)?;
        table.get(&view, &rtxn, key)
    }

    /// [`Self::side_table_get`]'s stored bytes, lent to `read` inside the
    /// read: a base row is read in place, an overlay row from its copy.
    pub(crate) fn side_table_read_bytes<K: SideKey, V, C: SideCodec<V>, R>(
        &self,
        table: &SideTable<K, V, C>,
        key: &K,
        read: impl FnOnce(&[u8]) -> Result<R>,
    ) -> Result<Option<R>> {
        let view = self.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        self.participant_in_txn(&rtxn)?;
        table
            .get_borrowed(&view, &rtxn, key)?
            .map(|bytes| read(&bytes))
            .transpose()
    }

    /// Where a result body this session writes along `target` goes: the
    /// session's own body directory while the room is off record, never the
    /// vault's; the vault's `bodies/` once it is on record.
    pub(crate) fn body_dir(&self, target: RouteTarget) -> Result<crate::store::BodyDir> {
        match target {
            RouteTarget::Overlay => self
                .vault
                .store
                .session_body_dir(&self.session_ref, true)?
                .ok_or(Error::InvariantViolation(
                    "off-record body directory missing",
                )),
            RouteTarget::Base => self.vault.store.body_dir(),
            RouteTarget::Discard => Err(Error::InvariantViolation(
                "anonymous routes write no result bodies",
            )),
        }
    }

    /// Pins the result body `digest` in this session's vault (OF-597).
    pub(crate) fn pin_result_body(&self, digest: [u8; 32]) -> crate::result_body::ResultBodyPin {
        self.vault.pin_result_body(digest)
    }

    /// Where a result body this session reads may be: its own body
    /// directory, then the vault's.
    pub(crate) fn body_dirs(&self) -> Result<Vec<crate::store::BodyDir>> {
        let mut dirs = Vec::with_capacity(2);
        if let Some(dir) = self
            .vault
            .store
            .session_body_dir(&self.session_ref, false)?
        {
            dirs.push(dir);
        }
        dirs.push(self.vault.store.body_dir()?);
        Ok(dirs)
    }

    /// The `[limits]` rows of this session's vault.
    pub(crate) fn limit_watch(&self) -> &crate::limit_ask::LimitWatch {
        self.vault.limit_watch()
    }

    /// A share of the result-memory pool for one run in this session.
    pub(crate) fn result_share(&self) -> crate::result_memory::ResultShare {
        self.vault.result_share()
    }

    /// Identity of the vault this session belongs to.
    ///
    /// The executor binding compares its storage's owning vault against its
    /// dispatcher's before it reads or writes anything, and equal
    /// `session_ref`s across two different vaults must not read as the same
    /// binding. The vault's identity is the whole answer that question needs,
    /// so this projects it rather than lending out the vault.
    pub(crate) fn vault_id(&self) -> VaultId {
        self.vault.vault_id()
    }

    /// Notes the messages of a turn witnessed while the room was on record:
    /// they landed in base, where a copy of the talk reads them.
    pub(crate) fn note_on_record_messages(
        &self,
        turn: EntityId,
        messages: &[(EntityId, u64, &[u8])],
    ) {
        if let Ok(mut state) = session_entry_state(&self.entry)
            && !state.record.closing
            && !state.gone
        {
            state.keep_messages(turn, messages);
        }
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
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            }));
        }
        state
            .record
            .mode
            .write_target()
            .require_recording(&self.session_ref)?;
        match state.record.mode {
            OffRecordMode::Anonymous => unreachable!("anonymous recording refused above"),
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

    pub fn close(self) -> Result<OffRecordCloseOutcome> {
        self.vault.close_off_record_session(
            &self.session_ref,
            SessionLocalReceiptLog::off_record(&self.session_ref),
        )
    }
}
