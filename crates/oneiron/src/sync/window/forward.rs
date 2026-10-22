//! Forward rematerialization of window state into the CRDT doc.
//!
//! The orchestrator below pins the pass order (snapshot markers, entities,
//! edges, tombstones, settle); the three passes live in the child modules.

mod calendar;
mod edge_pass;
mod entity_pass;
mod tombstone_pass;

use std::collections::HashSet;

use super::bridge::Materializer;
use super::loro_support::TombstoneIndex;
use super::quarantine;
use super::queue::scrub_receiver_outbox_on_remote_hard_delete_in_txn;
use super::types::WindowKey;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use loro::{LoroDoc, LoroMap};

/// Shared read-only context for the rematerialization passes.
struct RematCtx<'a> {
    vault: &'a Vault,
    doc: &'a LoroDoc,
    window_key: &'a WindowKey,
    lease_vault_id: u64,
    trusted: Option<&'a crate::recovery::CanonicalSnapshot>,
    entities_map: LoroMap,
    edges_map: LoroMap,
    /// The tombstones map indexed once for every pass of this rematerialization (H15).
    tombstones: &'a TombstoneIndex,
}

/// Cross-pass mutable ledgers: the `marked` snapshot plus the accumulators
/// every pass reads or extends.
struct RematLedger {
    marked: HashSet<String>,
    healed: Vec<EntityId>,
    terminal_quarantines: Vec<EntityId>,
    pending_entity_dependencies: HashSet<EntityId>,
    pending_dag_parent_sources: HashSet<EntityId>,
    /// Delete-protected rows the entity pass admitted: the ingest step already
    /// refused every tombstone naming them, so the tombstone pass records
    /// each such tombstone once, not twice.
    protected_admissions: HashSet<EntityId>,
    count: u32,
}

/// The forward pass's version, which a sealed window's landed mark names
/// beside the mirror's (FIX 6509): bump it whenever a change to the pass
/// changes which rows it lands or drops, so every window lands again once.
pub(crate) const FORWARD_PASS_VERSION: u64 = 1;

pub fn forward_rematerialize(
    vault: &Vault,
    doc: &LoroDoc,
    materializer: &Materializer,
    window_key: &WindowKey,
) -> Result<u32> {
    forward_with_recovery(vault, doc, materializer, window_key, None)
}

#[cfg(test)]
pub(crate) fn forward_recovery(
    vault: &Vault,
    doc: &LoroDoc,
    materializer: &Materializer,
    window_key: &WindowKey,
    snapshot: &crate::recovery::CanonicalSnapshot,
) -> Result<u32> {
    let mut run = ForwardRun::open_recovery(vault, doc, materializer, window_key, snapshot)?;
    loop {
        if let Some(count) =
            run.recovery_page(vault, doc, materializer, window_key, snapshot, usize::MAX)?
        {
            return Ok(count);
        }
    }
}

/// One rematerialization in one go, as every window open runs it: the pass
/// order and the materializer lock held throughout.
fn forward_with_recovery(
    vault: &Vault,
    doc: &LoroDoc,
    materializer: &Materializer,
    window_key: &WindowKey,
    trusted: Option<&crate::recovery::CanonicalSnapshot>,
) -> Result<u32> {
    // The rows this pass writes came from the doc: the live mirror must not
    // rewrite a carrier with them.
    let _import = crate::sync::manager::import_scope();
    let (tombstones, native_documents) = open(vault, doc, window_key, trusted)?;
    let _guard = materializer.lock();
    let mut run = ForwardRun::begin(
        vault,
        doc,
        materializer,
        window_key,
        trusted,
        tombstones,
        native_documents,
    )?;
    loop {
        if let Some(count) = run.page(vault, doc, window_key, trusted, usize::MAX)? {
            return Ok(count);
        }
    }
}

/// One forward rematerialization between its pages (FIX 8821): the passes
/// in their pinned order (entities, edges, tombstones, then the settle),
/// each run a page of rows at a time from its plan, with the cross-pass
/// ledgers, the tombstone index and the tombstone outcomes kept from page to
/// page. A recovery runs it a page per turn on the vault's task-work line;
/// a window open runs every page at once.
pub(crate) struct ForwardRun {
    lease_vault_id: u64,
    tombstones: TombstoneIndex,
    native_documents: Option<crate::sync::note::State>,
    ledger: RematLedger,
    outcome: tombstone_pass::TombstonePassOutcome,
    stage: Stage,
}

/// Where a forward run stands: the pass and its next row, or its count.
enum Stage {
    Entities {
        plan: entity_pass::EntityPlan,
        next: usize,
    },
    Edges {
        keys: Vec<String>,
        next: usize,
    },
    Tombstones {
        entries: Vec<(String, Vec<u8>)>,
        next: usize,
    },
    Done(u32),
}

fn remat_ctx<'a>(
    vault: &'a Vault,
    doc: &'a LoroDoc,
    window_key: &'a WindowKey,
    trusted: Option<&'a crate::recovery::CanonicalSnapshot>,
    lease_vault_id: u64,
    tombstones: &'a TombstoneIndex,
) -> RematCtx<'a> {
    RematCtx {
        vault,
        doc,
        window_key,
        lease_vault_id,
        trusted,
        entities_map: doc.get_map("entities"),
        edges_map: doc.get_map("edges"),
        tombstones,
    }
}

/// The checks before any write: retained world witnesses, native NOTE
/// documents, and no NOTE recovery carrier in a peer window.
fn open(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
    trusted: Option<&crate::recovery::CanonicalSnapshot>,
) -> Result<(TombstoneIndex, Option<crate::sync::note::State>)> {
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    if window_key.world().is_some() {
        let mut witnesses = Vec::new();
        doc.get_map("retained_claim_worlds").for_each(|raw, value| {
            if let loro::ValueOrContainer::Value(loro::LoroValue::Binary(bytes)) = value {
                witnesses.push((raw.to_owned(), bytes.to_vec()));
            }
        });
        for (raw, value) in witnesses {
            let id = EntityId::from_hex(&raw)?;
            if value.as_slice() != window_key.world().expect("world key").as_bytes() {
                return Err(crate::Error::InvalidConfig(
                    "foreign retained world witness".into(),
                ));
            }
            let Some(blob) =
                crate::sync::loro_support::map_get_bytes(&doc.get_map("entities"), &raw)
            else {
                return Err(crate::Error::InvalidConfig(
                    "orphan retained world witness".into(),
                ));
            };
            let txn = vault.store.env.read_txn()?;
            if !crate::sync::types::retained_world_shell_belongs_to_window(
                vault,
                &txn,
                doc,
                &tombstones,
                &id,
                &blob,
                window_key,
                trusted.is_some(),
            )? {
                return Err(crate::Error::InvalidConfig(
                    "unproven retained world witness".into(),
                ));
            }
        }
    }
    let native_notes = crate::sync::note::is_native(doc);
    let native_documents = native_notes
        .then(|| crate::sync::note::validate(doc))
        .transpose()?;
    if trusted.is_none() && !native_notes {
        for name in [
            "documents",
            "entity_documents",
            "document_heads",
            "head_move_receipts",
            "note_forks",
            "note_proposals",
        ] {
            if !doc.get_map(name).is_empty() {
                return Err(crate::note::documents::invalid(
                    "peer window cannot authorize NOTE recovery",
                ));
            }
        }
    }
    Ok((tombstones, native_documents))
}

impl ForwardRun {
    /// Opens a recovery's forward run over `doc`, the window rebuilt from
    /// `snapshot`, to run a page at a time ([`Self::recovery_page`]).
    pub(crate) fn open_recovery(
        vault: &Vault,
        doc: &LoroDoc,
        materializer: &Materializer,
        window_key: &WindowKey,
        snapshot: &crate::recovery::CanonicalSnapshot,
    ) -> Result<Self> {
        snapshot.validate()?;
        if snapshot.window != window_key.as_str() {
            return Err(crate::Error::InvalidConfig(
                "recovery window key mismatch".into(),
            ));
        }
        let _import = crate::sync::manager::import_scope();
        let (tombstones, native_documents) = open(vault, doc, window_key, Some(snapshot))?;
        let _guard = materializer.lock();
        Self::begin(
            vault,
            doc,
            materializer,
            window_key,
            Some(snapshot),
            tombstones,
            native_documents,
        )
    }

    /// Runs the next page of a recovery's forward run under the
    /// materializer lock: at most `page` rows of the pass it stands in, and
    /// the stage between passes when its pass ends. The count once done.
    pub(crate) fn recovery_page(
        &mut self,
        vault: &Vault,
        doc: &LoroDoc,
        materializer: &Materializer,
        window_key: &WindowKey,
        snapshot: &crate::recovery::CanonicalSnapshot,
        page: usize,
    ) -> Result<Option<u32>> {
        let _import = crate::sync::manager::import_scope();
        let _guard = materializer.lock();
        self.page(vault, doc, window_key, Some(snapshot), page)
    }

    /// The pass a run stands in, and the key of its next row, for a
    /// continuation's cursor.
    pub(crate) fn position(&self) -> (&'static str, Option<String>) {
        match &self.stage {
            Stage::Entities { plan, next } => ("entities", plan.key(*next).map(str::to_owned)),
            Stage::Edges { keys, next } => ("edges", keys.get(*next).cloned()),
            Stage::Tombstones { entries, next } => {
                ("tombstones", entries.get(*next).map(|(key, _)| key.clone()))
            }
            Stage::Done(_) => ("settled", None),
        }
    }

    /// The NOTE preflight, the marker snapshot and the window's cutoffs,
    /// then the entity plan. The caller holds the materializer lock.
    fn begin(
        vault: &Vault,
        doc: &LoroDoc,
        materializer: &Materializer,
        window_key: &WindowKey,
        trusted: Option<&crate::recovery::CanonicalSnapshot>,
        tombstones: TombstoneIndex,
        native_documents: Option<crate::sync::note::State>,
    ) -> Result<Self> {
        if let Some(documents) = trusted {
            let txn = vault.store.env.read_txn()?;
            documents.preflight_note_recovery(vault, &txn)?;
        }
        let lease_vault_id = materializer.lease_vault_id();

        // Entity-scoped retry markers pending for this window, loaded up front:
        // the entity/edge passes discharge a marker only via an actual healing
        // write (ONE-1147); the tombstone pass only via that entity's own
        // replay success (ONE-1124). Malformed marker rows never match a
        // canonical `to_hex()` and so are never discharged here (fail closed).
        let marked: HashSet<String> =
            quarantine::pending_remat_entities(vault, window_key.as_str())?
                .into_iter()
                .collect();
        let ledger = RematLedger {
            marked,
            healed: Vec::new(),
            terminal_quarantines: Vec::new(),
            pending_entity_dependencies: HashSet::new(),
            pending_dag_parent_sources: HashSet::new(),
            protected_admissions: HashSet::new(),
            count: 0u32,
        };

        // OF-013: the withdrawn cutoffs the window carries are staged first, so
        // the entity pass refuses a withdrawn body whichever carrier won its key.
        crate::sync::withdrawn_cutoffs::apply_withdrawn_cutoff_map(
            vault,
            doc,
            window_key.as_str(),
        )?;
        let plan = entity_pass::plan(&remat_ctx(
            vault,
            doc,
            window_key,
            trusted,
            lease_vault_id,
            &tombstones,
        ))?;
        Ok(Self {
            lease_vault_id,
            tombstones,
            native_documents,
            ledger,
            outcome: tombstone_pass::TombstonePassOutcome::default(),
            stage: Stage::Entities { plan, next: 0 },
        })
    }

    /// Runs at most `page` rows of the pass the run stands in, and the stage
    /// between passes when its pass ends: pass order is pinned. The count
    /// once the run settled. The caller holds the materializer lock.
    fn page(
        &mut self,
        vault: &Vault,
        doc: &LoroDoc,
        window_key: &WindowKey,
        trusted: Option<&crate::recovery::CanonicalSnapshot>,
        page: usize,
    ) -> Result<Option<u32>> {
        let page = page.max(1);
        let ctx = remat_ctx(
            vault,
            doc,
            window_key,
            trusted,
            self.lease_vault_id,
            &self.tombstones,
        );
        let after = match &mut self.stage {
            Stage::Entities { plan, next } => {
                let end = next.saturating_add(page).min(plan.rows());
                entity_pass::run_page(&ctx, &mut self.ledger, plan, *next..end)?;
                *next = end;
                if end == plan.rows() {
                    after_entities(&ctx, &mut self.ledger, self.native_documents.take())?;
                    let keys = edge_pass::order(&ctx);
                    Some(Stage::Edges { keys, next: 0 })
                } else {
                    None
                }
            }
            Stage::Edges { keys, next } => {
                let end = next.saturating_add(page).min(keys.len());
                edge_pass::run_page(&ctx, &mut self.ledger, &keys[*next..end])?;
                *next = end;
                if end == keys.len() {
                    after_edges(&ctx);
                    // A SESSION/SpawnedBy or ChildOf in this window can satisfy a bounded
                    // Parent obligation left by a different window whose doc is not loaded.
                    vault.with_write_txn_grouped(|txn| super::bridge::retry_in_txn(vault, txn))?;
                    let entries = tombstone_pass::entries(&ctx);
                    Some(Stage::Tombstones { entries, next: 0 })
                } else {
                    None
                }
            }
            Stage::Tombstones { entries, next } => {
                let end = next.saturating_add(page).min(entries.len());
                let outcome =
                    tombstone_pass::run_page(&ctx, &mut self.ledger, &entries[*next..end]);
                *next = end;
                // The first error stops the pass: no later tombstone replays.
                let stopped = absorb(&mut self.outcome, outcome);
                if stopped || end == entries.len() {
                    let outcome = std::mem::take(&mut self.outcome);
                    Some(Stage::Done(settle(&ctx, &mut self.ledger, outcome)?))
                } else {
                    None
                }
            }
            Stage::Done(_) => None,
        };
        if let Some(stage) = after {
            self.stage = stage;
        }
        Ok(match self.stage {
            Stage::Done(count) => Some(count),
            _ => None,
        })
    }
}

/// Adds one page's tombstone outcome to the run's. Returns whether the
/// page stopped the pass on an error.
fn absorb(
    run: &mut tombstone_pass::TombstonePassOutcome,
    page: tombstone_pass::TombstonePassOutcome,
) -> bool {
    run.purge_failures.extend(page.purge_failures);
    run.unapplied.extend(page.unapplied);
    run.cleared.extend(page.cleared);
    run.receiver_scrub_candidates
        .extend(page.receiver_scrub_candidates);
    if run.deferred_error.is_none() {
        run.deferred_error = page.deferred_error;
    }
    run.deferred_error.is_some()
}

/// What follows the entity pass, before the edge pass.
fn after_entities(
    ctx: &RematCtx<'_>,
    ledger: &mut RematLedger,
    native_documents: Option<crate::sync::note::State>,
) -> Result<()> {
    let (vault, doc, window_key, trusted) = (ctx.vault, ctx.doc, ctx.window_key, ctx.trusted);
    // A redaction can arrive after its attribution in this same entity pass;
    // clear the now-dominated live carrier and force history-free egress.
    super::egress::scrub_redacted_attribution_carriers(vault, window_key, doc)?;
    if let Some(documents) = native_documents {
        ledger.healed.extend(crate::sync::note::apply(
            vault,
            doc,
            documents,
            window_key.as_str(),
        )?);
    }
    if window_key.world().is_some() {
        let witnesses = doc.get_map("retained_claim_worlds");
        let mut rows = Vec::new();
        witnesses.for_each(|raw, _| rows.push(raw.to_owned()));
        vault.with_write_txn_grouped(|txn| {
            for raw in &rows {
                let id = EntityId::from_hex(raw)?;
                let Some(blob) =
                    crate::sync::loro_support::map_get_bytes(&doc.get_map("entities"), raw)
                else {
                    return Err(crate::Error::InvalidConfig(
                        "orphan retained world witness".into(),
                    ));
                };
                if !crate::sync::types::retained_world_shell_belongs_to_window(
                    vault,
                    txn,
                    doc,
                    ctx.tombstones,
                    &id,
                    &blob,
                    window_key,
                    trusted.is_some(),
                )? {
                    return Err(crate::Error::InvalidConfig(
                        "unproven retained world witness".into(),
                    ));
                }
                vault.store.sync_state.put(
                    txn,
                    &format!("m:dw:{raw}"),
                    window_key.as_str().as_bytes(),
                )?;
            }
            Ok(())
        })?;
    }
    crate::recovery::materialize_retained_shells(vault, doc, ctx.tombstones)?;
    if let Some(snapshot) = trusted.filter(|_| window_key.world().is_some()) {
        // The validated canonical artifact binds every retained soft shell
        // to this world. Persist that address before the edge pass and the
        // next ordinary reopen consult the same durable proof.
        vault.with_write_txn_grouped(|txn| {
            for shell in &snapshot.retained_claim_worlds {
                let id = EntityId::from_bytes(shell.id)?;
                vault.store.sync_state.put(
                    txn,
                    &format!("m:dw:{}", id.to_hex()),
                    window_key.as_str().as_bytes(),
                )?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// What follows the edge pass, before the tombstone pass.
fn after_edges(ctx: &RematCtx<'_>) {
    let (vault, doc, window_key) = (ctx.vault, ctx.doc, ctx.window_key);
    // OF-422: the owner-signed custody transitions the window carries.
    crate::sync::custody::apply_custody_map(vault, doc, window_key);
    // OF-522: the room turn rows the window carries, before its tombstones,
    // so a room deleted in this window takes its rows with it.
    crate::sync::room_turns::apply_room_turn_map(vault, doc, window_key);
    // FIX 1794: the room side rows it carries, after the turn rows their
    // responses name.
    crate::sync::room_facts::apply_room_fact_map(vault, doc, window_key);
    // FIX 853: the MESSAGE documents and document quote pins it carries,
    // after the MESSAGE rows and before the tombstones, so an erased message
    // takes them. A document lands before the pins that quote it.
    crate::sync::message_docs::apply_message_doc_map(vault, doc, window_key);
    crate::sync::document_pins::apply_document_pin_map(vault, doc, window_key);
}

/// The settle after the tombstone pass: the marker bookkeeping, the
/// tombstone pass's deferred error, the documents of a recovery, and the
/// calendar.
fn settle(
    ctx: &RematCtx<'_>,
    ledger: &mut RematLedger,
    outcome: tombstone_pass::TombstonePassOutcome,
) -> Result<u32> {
    let (vault, window_key) = (ctx.vault, ctx.window_key);
    // An edge outcome is not proof that its source claim's missing actor or
    // subject arrived. Keep that replay pending; a successful tombstone purge may
    // still discharge it through `cleared`, with delete-safety precedence.
    // A ChildOf write for a deferred Parent's SOURCE is not evidence that
    // the Parent landed: its TARGET membership may still be missing. Keep
    // the source-scoped retry until the exact Parent is written or receives
    // a terminal rejection, never discharge it via an unrelated edge heal.
    {
        let RematLedger {
            healed,
            terminal_quarantines,
            pending_entity_dependencies,
            pending_dag_parent_sources,
            ..
        } = &mut *ledger;
        healed.retain(|id| {
            !pending_entity_dependencies.contains(id) && !pending_dag_parent_sources.contains(id)
        });
        terminal_quarantines.retain(|id| {
            !pending_entity_dependencies.contains(id) && !pending_dag_parent_sources.contains(id)
        });
    }
    if !outcome.purge_failures.is_empty()
        || !outcome.cleared.is_empty()
        || !ledger.healed.is_empty()
        || !ledger.terminal_quarantines.is_empty()
        || !outcome.receiver_scrub_candidates.is_empty()
    {
        let marker_result = vault.with_write_txn_grouped(|wtxn| {
            // Clear BEFORE set so set wins: an id that both succeeded and
            // failed in one pass (case-shifted tombstone aliases with
            // divergent reasons) must KEEP its marker — losing it would
            // silently drop a pending hard purge (fail closed). The
            // ONE-1147 `healed` discharges (entity/edge healing writes,
            // structurally disjoint from tombstoned ids — both passes are
            // tombstone-gated). ONE-1167 terminal quarantine may discharge
            // only replay/quarantine-origin markers whose provenance sidecar
            // already proves they are not delete-safety retries; legacy or
            // purge-failure markers stay pending until their own tombstone
            // goal state holds.
            let mut success_seen = HashSet::new();
            // Delete-safety invariant: the `cleared` side has this entity's
            // own tombstone goal state above, while the `healed` side is
            // safe only because tombstone-gating keeps entity/edge healing
            // disjoint from unproven delete-safety `rm:` markers. A
            // tombstoned id cannot reach `healed`; if a refactor weakens
            // that gate or reorders this bookkeeping, the debug assert below
            // catches the healed-clear regression before an unproven purge
            // retry can be silently discharged.
            #[cfg(debug_assertions)]
            for id in &ledger.healed {
                let has_unproven_marker = quarantine::unproven_remat_marker_exists_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    id,
                )
                .unwrap_or_else(|err| {
                    panic!("delete-safety invariant: failed to read rm: marker state: {err}")
                });
                debug_assert!(
                    !has_unproven_marker,
                    "delete-safety invariant: healed ids must be disjoint from unproven rm: markers"
                );
            }
            let tombstone_cleared: HashSet<_> = outcome.cleared.iter().copied().collect();
            for id in ledger.healed.iter().chain(outcome.cleared.iter()) {
                if !success_seen.insert(*id) {
                    continue;
                }
                if !tombstone_cleared.contains(id)
                    && super::bridge::has_pending_source_in_txn(
                        vault,
                        wtxn,
                        window_key.as_str(),
                        id,
                    )?
                {
                    continue;
                }
                quarantine::clear_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            let mut terminal_seen = HashSet::new();
            for id in &ledger.terminal_quarantines {
                if !terminal_seen.insert(*id)
                    || super::bridge::has_pending_source_in_txn(
                        vault,
                        wtxn,
                        window_key.as_str(),
                        id,
                    )?
                {
                    continue;
                }
                let cleared = quarantine::clear_replay_remat_marker_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    id,
                )?;
                if !cleared {
                    tracing::debug!(
                        entity = %id.to_hex(),
                        window = %window_key,
                        "forward remat: terminal quarantine left unproven rm: marker pending"
                    );
                }
            }
            // Delete-safety invariant: `purge_failures` MUST be applied LAST,
            // after healed/cleared clears and terminal-quarantine clears.
            // Tombstone/delete-safety dominance requires a failed purge to win
            // over every clear in this txn: a terminal quarantine may remove
            // replay provenance for non-delete markers, but a simultaneous
            // purge failure must restore the unproven `rm:` retry so the
            // delete-safety provenance is not silently removed.
            for id in &outcome.purge_failures {
                quarantine::set_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            for (id, value) in &outcome.unapplied {
                vault.fence_unapplied_delete_in_txn(wtxn, id, value)?;
            }
            if !outcome.receiver_scrub_candidates.is_empty() {
                scrub_receiver_outbox_on_remote_hard_delete_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                )?;
            }
            Ok(())
        });
        match marker_result {
            Err(err) if outcome.receiver_scrub_candidates.is_empty() => return Err(err),
            Err(err) => {
                tracing::error!(
                    window = %window_key,
                    purge_failures = outcome.purge_failures.len(),
                    receiver_scrub_candidates = outcome.receiver_scrub_candidates.len(),
                    error = %err,
                    "forward remat: receiver outbox scrub/bookkeeping txn FAILED after hard tombstone replay; flagging entity-scoped rm: markers for durable retry"
                );
                vault.with_write_txn_grouped(|wtxn| {
                    for id in outcome
                        .purge_failures
                        .iter()
                        .chain(outcome.receiver_scrub_candidates.iter())
                    {
                        quarantine::set_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
                    }
                    for (id, value) in &outcome.unapplied {
                        vault.fence_unapplied_delete_in_txn(wtxn, id, value)?;
                    }
                    Ok(())
                })?;
            }
            Ok(()) => {}
        }
    }
    if let Some(err) = outcome.deferred_error {
        return Err(err);
    }
    if quarantine::pending_remat_windows(vault)?
        .iter()
        .any(|window| window == window_key.as_str())
    {
        // Markers survive the pass when a purge failed above, when a
        // flagged entity has neither a healing write nor a proven non-delete
        // terminal x: row in the loaded doc (stale/cross-window state), or
        // when a marker row no longer parses. Clearing any of them here
        // would vacuously discharge a GDPR retry — keep them (fail closed)
        // and keep ERROR-grade visibility.
        tracing::error!(
            window = %window_key,
            "forward remat: rm: markers still pending after tombstone pass — hard-deleted content may be live (GDPR SLA breach signal)"
        );
    }

    if let Some(documents) = ctx.trusted {
        crate::recovery::materialize_window_documents(vault, ctx.doc, documents)?;
    }
    calendar::reconcile(ctx)?;
    Ok(ledger.count)
}
