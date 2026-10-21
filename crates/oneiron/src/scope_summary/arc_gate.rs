//! An Arc's surprise gate and owed state (FIX 7509 P8, ARCH-0026 #gate):
//! "It compares the new material against the projection it already holds",
//! and "a wake with nothing new writes nothing".
//!
//! The material is the statements of the sittings' summary lines below the
//! Arc ([`crate::dreamer_wake::statement_material`]), as generated words.
//! It is compared with the set the Arc's last summary was written from, and
//! only that one, never a union of every earlier set and never the Arc's own
//! words: the row keeps digests and source-set ids, no prose.
//!
//! A first Arc, a stale one (material or a sitting's summary lost, its own
//! summary gone) and one dirty for the nightly cadence are due. Otherwise the
//! owner's `arc_min_new_statements` row admits it; below it the Arc stays
//! dirty and owed until its backstop. An unchanged successful set writes
//! nothing, and sources that do not read never count as nothing new.

use super::arc::ARC_PURPOSE;
use super::arc_sources::{ArcSources, sources_in_txn};
use super::arc_work::ArcManifest;
use super::codec::invalid;
use super::derivation::{
    PROJECTION, Projection, current_in_txn, declaration, decode, encode, projection_key,
};
use super::request::{
    ScopeSummaryRequest, ScopeSummaryTarget, decode_request, enqueue_with_lineage_in_txn,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::ClaimSource;
use crate::error::Result;
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Why an Arc is still owed (FIX 7509 P8, PR3): typed, on its row, never a
/// silent hold. A failure is retried at the backstop; work in progress
/// keeps its queued attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ArcPendingCause {
    /// A closed sitting below the Arc has no summary yet.
    #[serde(rename = "arc_lower_pending")]
    LowerPending { session: String },
    /// A TURN the Arc must read could not be opened, by its full id.
    #[serde(rename = "arc_source_unavailable")]
    SourceUnavailable { handle: String },
    /// The Arc composes in parts (PR3): the id of its work generation, whose
    /// queued attempt goes on at its next wake. Never written smaller.
    #[serde(rename = "arc_composition_pending")]
    CompositionPending { work_id: String },
    /// The model's window holds the call's frame and not one character of
    /// a source beside it.
    #[serde(rename = "arc_window_too_small")]
    WindowTooSmall { window: u64, frame_tokens: u64 },
}

impl ArcPendingCause {
    /// The cause's static code, for logs.
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::LowerPending { .. } => "arc_lower_pending",
            Self::SourceUnavailable { .. } => "arc_source_unavailable",
            Self::CompositionPending { .. } => "arc_composition_pending",
            Self::WindowTooSmall { .. } => "arc_window_too_small",
        }
    }
}

/// An Arc's gate state on its projection row: digests and ids only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ArcState {
    /// The source set and material the gate last read.
    pending_set: Option<[u8; 32]>,
    pending_material: Vec<[u8; 32]>,
    /// The source set, material and sittings' summaries the Arc's last
    /// summary was written from.
    success_set: Option<[u8; 32]>,
    success_material: Vec<[u8; 32]>,
    success_lower: Vec<String>,
    /// When the Arc first went dirty since its last summary.
    dirty_since: Option<u64>,
    stale: bool,
    /// When the backstop takes it. `None` while clean, or while its queued
    /// attempt owns its next wake.
    due_at: Option<u64>,
    queued: Option<[u8; 16]>,
    cause: Option<ArcPendingCause>,
    /// The work generation the Arc last composed in parts (PR3), kept past
    /// its landing and a requeue so a newer one deletes its rows.
    work: Option<String>,
}

impl ArcState {
    /// Dirty since its first mark, due a nightly cadence after it, at once
    /// when stale. A later mark never postpones it.
    fn mark(&mut self, now: u64, nightly_secs: u64, stale: bool) {
        let since = *self.dirty_since.get_or_insert(now);
        self.stale |= stale;
        let due = if self.stale {
            now
        } else {
            since.saturating_add(nightly_secs)
        };
        self.due_at = Some(self.due_at.map_or(due, |at| at.min(due)));
    }

    fn aged(&self, gate: Gate) -> bool {
        self.dirty_since
            .is_some_and(|since| since.saturating_add(gate.nightly_secs) <= gate.now)
    }

    /// Nothing is owed: the sources are the last summary's, or none.
    fn settle(&mut self) {
        self.pending_set = None;
        self.pending_material.clear();
        self.dirty_since = None;
        self.stale = false;
        self.due_at = None;
        self.queued = None;
        self.cause = None;
    }

    /// Owed for `cause`, retried at the next backstop.
    fn owe(&mut self, cause: ArcPendingCause, gate: Gate) {
        self.cause = Some(cause);
        self.queued = None;
        self.dirty_since.get_or_insert(gate.now);
        self.due_at = Some(gate.now.saturating_add(gate.nightly_secs));
    }

    /// Whether the attempt the gate queued has not ended.
    fn queued_open(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
        let Some(queued) = self.queued else {
            return Ok(false);
        };
        let row = AttemptQueue::from_store(&vault.store)
            .get_in_txn(txn, AttemptId::from_bytes(&queued)?)?;
        Ok(row.is_some_and(|row| !row.state.is_terminal()))
    }
}

/// How the gate is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    /// A sitting below it landed or was reused.
    Dirty,
    /// The backstop reads it.
    Sweep,
}

/// The owner's rows the gate reads, and its clock.
#[derive(Debug, Clone, Copy)]
struct Gate {
    threshold: u32,
    nightly_secs: u64,
    now: u64,
}

impl Gate {
    fn in_txn(vault: &Vault, txn: &RoTxn<'_>, now: u64) -> Result<Self> {
        let (threshold, nightly_secs) = crate::dreamer_wake::arc_policy_in_txn(vault, txn)?;
        Ok(Self {
            threshold,
            nightly_secs,
            now,
        })
    }
}

/// Sittings landed in `txn` (or an exact reuse stood): the Arc of each of
/// `conversations` is marked dirty and its gate runs. Rows the gate cannot
/// read are logged and leave the sitting's landing as it is.
pub(super) fn sittings_landed_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    conversations: &BTreeSet<EntityId>,
    now: u64,
) -> Result<()> {
    let gate = match Gate::in_txn(vault, txn, now) {
        Ok(gate) => gate,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "the arc gate's rows did not read; arcs were not marked");
            return Ok(());
        }
    };
    for conversation in conversations {
        let request = super::arc::conversation_arc(*conversation)?;
        evaluate_in_txn(vault, txn, &request, Mark::Dirty, gate, (None, None))?;
    }
    Ok(())
}

/// Marks `request`'s Arc and runs its gate in `txn`, queueing its attempt
/// under `lineage` when it is due. Only an unreadable store fails it: a
/// source that does not read leaves the Arc owed.
fn evaluate_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    request: &ScopeSummaryRequest,
    mark: Mark,
    gate: Gate,
    lineage: (Option<AttemptId>, Option<&str>),
) -> Result<()> {
    let key = projection_key(request, ARC_PURPOSE)?;
    let mut row = match PROJECTION.get(&vault.store, txn, &key)? {
        Some(row) => row,
        None => Projection {
            request: encode(&declaration(request, ARC_PURPOSE, None))?,
            current: None,
            observed: [0; 32],
            arc: None,
        },
    };
    let mut state = row.arc.take().unwrap_or_default();
    if mark == Mark::Dirty || state.dirty_since.is_some() || state.stale {
        state.mark(gate.now, gate.nightly_secs, false);
    }
    if state.queued_open(vault, txn)? {
        // Its queued attempt owns its next wake.
        state.due_at = None;
    } else {
        decide_in_txn(vault, txn, request, &mut state, gate, lineage)?;
    }
    row.arc = Some(state);
    PROJECTION.put(&vault.store, txn, &key, &row)
}

fn decide_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    request: &ScopeSummaryRequest,
    state: &mut ArcState,
    gate: Gate,
    (parent, run_id): (Option<AttemptId>, Option<&str>),
) -> Result<()> {
    let ScopeSummaryTarget::Arc { scope } = &request.target else {
        return Err(invalid("the arc gate reads only an arc"));
    };
    let due = match sources_in_txn(vault, txn, scope, request.requester) {
        Ok((_, arc)) => {
            if (state.success_set == Some(arc.source_set) && !state.stale)
                || (arc.lower.is_empty() && arc.owed.is_empty())
            {
                state.settle();
                return Ok(());
            }
            let material = material(&arc);
            let success: BTreeSet<[u8; 32]> = state.success_material.iter().copied().collect();
            let lower: BTreeSet<String> = arc
                .lower
                .iter()
                .map(|lower| lower.summary.to_hex())
                .collect();
            // A statement or a sitting's summary the last Arc was written
            // from that is gone now is a correction: the Arc is stale.
            if !success.is_subset(&material)
                || state.success_lower.iter().any(|id| !lower.contains(id))
            {
                state.stale = true;
            }
            state.pending_set = Some(arc.source_set);
            state.pending_material = material.iter().copied().collect();
            // A sitting whose summary is owed keeps the Arc owed: its landing
            // runs this gate again, and the backstop after.
            if let Some(session) = arc.owed.first() {
                tracing::info!(
                    cause = "arc_lower_pending",
                    owed = arc.owed.len(),
                    "an arc waits on a sitting's summary"
                );
                state.owe(
                    ArcPendingCause::LowerPending {
                        session: session.to_hex(),
                    },
                    gate,
                );
                return Ok(());
            }
            let new = material.difference(&success).count() as u64;
            state.success_set.is_none()
                || state.stale
                || state.aged(gate)
                || new >= u64::from(gate.threshold)
        }
        // Sources that do not read are never "nothing new": the Arc stays
        // dirty, and is queued when due, its attempt reporting the refusal.
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "an arc's sources did not read; it stays owed");
            state.success_set.is_none() || state.stale || state.aged(gate)
        }
    };
    if !due {
        return Ok(());
    }
    let previous = current_in_txn(vault, txn, request, ARC_PURPOSE)?;
    let queued = enqueue_with_lineage_in_txn(
        vault,
        txn,
        declaration(request, ARC_PURPOSE, previous),
        parent,
        run_id,
        gate.now,
    )?;
    state.queued = Some(*queued.attempt.as_bytes());
    state.due_at = None;
    state.cause = None;
    Ok(())
}

/// The Arc's material: every statement of the lower lines it reads, as
/// generated words.
fn material(arc: &ArcSources) -> BTreeSet<[u8; 32]> {
    let mut material = BTreeSet::new();
    for lower in &arc.lower {
        for line in &lower.lines {
            material.extend(crate::dreamer_wake::statement_material::statements(
                &line.words,
                Some(ClaimSource::Generated),
            ));
        }
    }
    material
}

/// A declaration's projection key, its request and its purpose.
pub(super) fn row_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    input: &[u8],
) -> Result<([u8; 32], ScopeSummaryRequest, String)> {
    let input = decode(input)?;
    let request = decode_request(vault, txn, &input)?;
    let purpose = input
        .as_map()
        .and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("purpose"))
        })
        .and_then(|(_, value)| value.as_str())
        .ok_or_else(|| invalid("arc declaration has no purpose"))?
        .to_owned();
    Ok((projection_key(&request, &purpose)?, request, purpose))
}

/// An Arc landed, or its exact composition was reused: the set it was
/// written from is its last successful set, and nothing is owed.
pub(super) fn succeeded_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    input: &[u8],
    arc: &ArcSources,
) -> Result<()> {
    let (key, _, _) = row_in_txn(vault, txn, input)?;
    let Some(mut row) = PROJECTION.get(&vault.store, txn, &key)? else {
        return Ok(());
    };
    let mut state = row.arc.take().unwrap_or_default();
    state.success_set = Some(arc.source_set);
    state.success_material = material(arc).into_iter().collect();
    state.success_lower = arc
        .lower
        .iter()
        .map(|lower| lower.summary.to_hex())
        .collect();
    state.settle();
    row.arc = Some(state);
    PROJECTION.put(&vault.store, txn, &key, &row)
}

/// The Arc's summary is withdrawn: its row stays, owed again and due now.
pub(super) fn withdrawn_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    key: &[u8; 32],
    mut projection: Projection,
) -> Result<()> {
    projection.current = None;
    let mut state = projection.arc.take().unwrap_or_default();
    state.mark(vault.store.clock.now_recorded_at(), 0, true);
    projection.arc = Some(state);
    PROJECTION.put(&vault.store, txn, key, &projection)
}

/// At the commit boundary an Arc is only marked: stale and due when its
/// summary is gone. Nothing is read or queued, and nothing is written for
/// one whose summary stands.
pub(super) fn on_commit_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    key: &[u8; 32],
    projection: Projection,
) -> Result<()> {
    let Some(current) = projection.current.as_deref() else {
        return Ok(());
    };
    let current = EntityId::from_hex(current)?;
    let state = crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, &current)?;
    if !state.deleted && vault.archive_tombstone_in_txn(txn, &current)?.is_none() {
        return Ok(());
    }
    withdrawn_in_txn(vault, txn, key, projection)
}

/// The backstop (ARCH-0026: "The nightly sweep is the backstop only"): each
/// Arc due by now, and each whose queued attempt ended with it still owed,
/// runs its gate under `lineage`. With `reconcile`, each conversation a
/// sitting's standing summary covers turns in gets its Arc when it has none,
/// so a lost landing event is recovered.
pub(crate) fn sweep_due_arcs_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    lineage: (Option<AttemptId>, Option<&str>),
    now: u64,
    reconcile: bool,
) -> Result<()> {
    let gate = Gate::in_txn(vault, txn, now)?;
    let rows = PROJECTION
        .iter_from(&vault.store, txn, b"")?
        .collect::<Result<Vec<_>>>()?;
    let mut sittings = Vec::new();
    for (_, row) in rows {
        let input = decode(&row.request)?;
        let Some(state) = row.arc else {
            if reconcile && super::session::is_session_declaration(&input) {
                sittings.extend(row.current);
            }
            continue;
        };
        let owed = state.dirty_since.is_some() || state.stale;
        let due = match state.due_at {
            Some(at) => at <= now,
            None => owed && (state.stale || state.aged(gate)) && !state.queued_open(vault, txn)?,
        };
        if due {
            let request = decode_request(vault, txn, &input)?;
            evaluate_in_txn(vault, txn, &request, Mark::Sweep, gate, lineage)?;
        }
    }
    let mut conversations = BTreeSet::new();
    for summary in sittings {
        conversations.extend(covered_conversations_in_txn(vault, txn, &summary));
    }
    for conversation in conversations {
        let request = super::arc::conversation_arc(conversation)?;
        if PROJECTION
            .get(&vault.store, txn, &projection_key(&request, ARC_PURPOSE)?)?
            .is_none()
        {
            evaluate_in_txn(vault, txn, &request, Mark::Dirty, gate, lineage)?;
        }
    }
    Ok(())
}

/// The conversations a sitting's standing summary covers turns in; none
/// when it does not read.
fn covered_conversations_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    summary: &str,
) -> BTreeSet<EntityId> {
    let covers = EntityId::from_hex(summary)
        .and_then(|summary| super::doors::summary_in_txn(vault, txn, &summary))
        .map(|body| body.covers)
        .unwrap_or_default();
    covers
        .iter()
        .filter_map(|turn| crate::conversation_dag::conversation_of(&vault.store, txn, turn).ok())
        .collect()
}

/// The earliest instant an Arc is due at (Unix seconds), from the rows'
/// own due times: one whose attempt is queued is that queue's to wake.
pub(crate) fn next_arc_due_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Option<u64>> {
    let mut next: Option<u64> = None;
    for row in PROJECTION.iter_from(&vault.store, txn, b"")? {
        let (_, projection) = row?;
        if let Some(at) = projection.arc.and_then(|state| state.due_at) {
            next = Some(next.map_or(at, |next| next.min(at)));
        }
    }
    Ok(next)
}

impl Vault {
    /// Records why the Arc `input` declares stays owed (FIX 7509 P8), on its
    /// row, retried at the next backstop. Its attempt then ends with no
    /// summary written, never a smaller one.
    pub(crate) fn record_arc_pending(&self, input: &[u8], cause: ArcPendingCause) -> Result<()> {
        let now = self.store.clock.now_recorded_at();
        tracing::info!(cause = cause.code(), "an arc stays owed");
        self.with_write_txn_grouped(|txn| {
            let (key, request, purpose) = row_in_txn(self, txn, input)?;
            let mut row = match PROJECTION.get(&self.store, txn, &key)? {
                Some(row) => row,
                None => Projection {
                    request: encode(&declaration(&request, &purpose, None))?,
                    current: None,
                    observed: [0; 32],
                    arc: None,
                },
            };
            let gate = Gate::in_txn(self, txn, now)?;
            let mut state = row.arc.take().unwrap_or_default();
            state.owe(cause, gate);
            row.arc = Some(state);
            PROJECTION.put(&self.store, txn, &key, &row)
        })
    }

    /// The progress writer of an Arc composed in parts (FIX 7509 PR3): its
    /// row points at generation `work` (`arc_composition_pending`), its
    /// queued attempt stays its own and nothing is due at the backstop. With
    /// `manifest` the generation begins anew from it. A generation the row
    /// pointed at before is deleted.
    pub(crate) fn record_arc_progress(
        &self,
        input: &[u8],
        work: &[u8; 32],
        manifest: Option<&ArcManifest>,
    ) -> Result<()> {
        let work = crate::entity_id::bytes_to_hex_lower(work);
        tracing::info!(
            cause = "arc_composition_pending",
            fresh = manifest.is_some(),
            "an arc composes in parts"
        );
        self.with_write_txn_grouped(|txn| {
            let (key, request, purpose) = row_in_txn(self, txn, input)?;
            let mut row = match PROJECTION.get(&self.store, txn, &key)? {
                Some(row) => row,
                None => Projection {
                    request: encode(&declaration(&request, &purpose, None))?,
                    current: None,
                    observed: [0; 32],
                    arc: None,
                },
            };
            let mut state = row.arc.take().unwrap_or_default();
            if let Some(old) = state.work.take()
                && old != work
            {
                super::arc_work_store::delete_generation_in_txn(self, txn, &old)?;
            }
            if let Some(manifest) = manifest {
                super::arc_work_store::delete_generation_in_txn(self, txn, &work)?;
                super::arc_work_store::put_manifest_in_txn(self, txn, &work, manifest)?;
            }
            state.work = Some(work.clone());
            state.cause = Some(ArcPendingCause::CompositionPending {
                work_id: work.clone(),
            });
            state.due_at = None;
            row.arc = Some(state);
            PROJECTION.put(&self.store, txn, &key, &row)
        })
    }
}
