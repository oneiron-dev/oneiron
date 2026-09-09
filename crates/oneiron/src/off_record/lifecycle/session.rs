//! Session and vault handles: routes, shells, search, VaultMeta family, flips, receipts, promote_turn, close.

use std::sync::Arc;

use crate::ScoredEntity;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::off_record::promote::{FloorWrites, PromoteOutcome};
use crate::receipt::{ReceiptRecord, SessionLocalReceiptLog};
use crate::session_overlay::{
    OverlayKeyspace, RouteTarget, SessionOverlay, SessionWriteRoute, SnapshotLookup,
};
use crate::store::Store;

use super::registry::{
    OffRecordSessionEntry, live_session_entry, session_entry_state, vet_off_record_session_ref,
};
use super::telemetry::SessionRetrievalTelemetry;
#[cfg(test)]
use super::types::VaultMetaCounterComponents;
use super::types::{OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode};

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
    pub(super) vault: &'vault Vault,
    pub(super) session_ref: String,
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

    /// Atomically compare-and-put one routed VaultMeta row and update one
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
    pub(crate) fn vault_meta_compare_and_put_with_counter_routed(
        &self,
        route: &SessionWriteRoute,
        compare_key: &[u8],
        compare_value: &[u8],
        accepts_current: impl FnOnce(Option<&[u8]>) -> Result<()>,
        counter_key: &[u8],
        update_counter: impl FnOnce(Option<&[u8]>, Option<&[u8]>, RouteTarget) -> Result<(Vec<u8>, u64)>,
    ) -> Result<u64> {
        route.revalidate()?;
        match route.target() {
            RouteTarget::Overlay => {
                let overlay = self.entry.overlay.clone();
                let (segment, total) = self.vault.with_write_txn(|wtxn| {
                    let segment = overlay.install_txn_segment()?;
                    route.revalidate()?;
                    let view = self.vault.store.session_view(overlay.clone())?;
                    accepts_current(view.vault_meta_get_in_txn(&*wtxn, compare_key)?.as_deref())?;
                    let base = self
                        .vault
                        .store
                        .vault_meta
                        .get(&*wtxn, counter_key)?
                        .map(|raw| raw.to_vec());
                    let overlay_value = match overlay
                        .snapshot()?
                        .lookup_single(OverlayKeyspace::VaultMeta, counter_key)
                    {
                        SnapshotLookup::Present(value) => Some(value),
                        SnapshotLookup::Passthrough | SnapshotLookup::Tombstone => None,
                    };
                    let (next_counter, total) = update_counter(
                        base.as_deref(),
                        overlay_value.as_deref(),
                        RouteTarget::Overlay,
                    )?;
                    view.vault_meta_put_in_txn(wtxn, compare_key, compare_value)?;
                    view.vault_meta_put_in_txn(wtxn, counter_key, &next_counter)?;
                    Ok((segment, total))
                })?;
                segment.commit()?;
                Ok(total)
            }
            RouteTarget::Base => self.vault.with_write_txn(|wtxn| {
                route.revalidate()?;
                let overlay = self.entry.overlay.clone();
                let view = self.vault.store.session_view(overlay.clone())?;
                accepts_current(view.vault_meta_get_in_txn(&*wtxn, compare_key)?.as_deref())?;
                let base = self
                    .vault
                    .store
                    .vault_meta
                    .get(&*wtxn, counter_key)?
                    .map(|raw| raw.to_vec());
                let overlay_value = match overlay
                    .snapshot()?
                    .lookup_single(OverlayKeyspace::VaultMeta, counter_key)
                {
                    SnapshotLookup::Present(value) => Some(value),
                    SnapshotLookup::Passthrough | SnapshotLookup::Tombstone => None,
                };
                let (next_counter, total) =
                    update_counter(base.as_deref(), overlay_value.as_deref(), RouteTarget::Base)?;
                self.vault
                    .store
                    .vault_meta
                    .put(wtxn, compare_key, compare_value)?;
                self.vault
                    .store
                    .vault_meta
                    .put(wtxn, counter_key, &next_counter)?;
                Ok(total)
            }),
        }
    }

    /// The raw base and room-overlay components for an additive VaultMeta
    /// counter. Ordinary composed reads intentionally keep shadow semantics;
    /// only additive counters opt into this explicit merge.
    #[cfg(test)]
    pub(crate) fn vault_meta_counter_components(
        &self,
        key: &[u8],
    ) -> Result<VaultMetaCounterComponents> {
        let overlay = match self
            .entry
            .overlay
            .snapshot()?
            .lookup_single(OverlayKeyspace::VaultMeta, key)
        {
            SnapshotLookup::Present(value) => Some(value),
            SnapshotLookup::Passthrough | SnapshotLookup::Tombstone => None,
        };
        let rtxn = self.vault.store.env.read_txn()?;
        let base = self
            .vault
            .store
            .vault_meta
            .get(&rtxn, key)?
            .map(|raw| raw.to_vec());
        Ok((base, overlay))
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
