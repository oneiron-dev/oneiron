//! ONE-1453 per-actor burst breaker.
//!
//! A durable, per-`(dreamer_run_id, provenance actor)` velocity-to-review
//! conversion layered on the ONE-1452 consent-bundle path. It is NOT a denial
//! mechanism: an agent run that outruns its window keeps every claim it
//! authored and loses only its ability to land those claims automatically —
//! a would-be-`Auto` write becomes `Proposed` and joins the run's existing
//! consent bundle.
//!
//! Three properties carry the design:
//!
//! * **Fail-closed.** Demotion, never denial and never discard. A tripped row
//!   parks work for the owner instead of dropping it.
//! * **Durable.** The trip flag survives time passing, event-log pruning, a
//!   manifest edit, a vault reopen, and a later quiet period. Nothing in this
//!   module clears it.
//! * **One door out.** The owner-authenticated
//!   [`crate::Vault::resolve_gate_consent_bundle`] — approve OR decline —
//!   deletes every row for the run inside its own write transaction. There is
//!   no public clear, reset, resume, or untrip verb, and no third owner action.
//!
//! Storage is one small strict-versioned row per actor/run in the existing
//! `vault_meta` database. No entity, no LMDB database, no second decision
//! ledger: the synthetic trip receipt is an ordinary [`GateDecisionRecord`].

use std::borrow::Cow;

use heed::{RoTxn, RwTxn};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::vault::Vault;

use super::resolution::PolicyManifestResolution;

/// Encoding version of the durable `vault_meta` breaker row.
pub(crate) const GATE_BREAKER_ROW_SCHEMA_VERSION: u8 = 1;

/// Engine-default event budget inside one rolling window.
pub const GATE_BREAKER_DEFAULT_MAX_EVENTS: u32 = 30;

/// Engine-default rolling window, in seconds.
pub const GATE_BREAKER_WINDOW_SECS: u64 = 600;

/// Optional policy-manifest key carrying the two-field threshold override.
pub(crate) const GATE_BREAKER_POLICY_KEY: &str = "actor_burst_breaker";

/// Manifest field naming the per-window event budget.
const GATE_BREAKER_MAX_EVENTS_KEY: &str = "max_events";

/// Manifest field naming the rolling-window width in seconds.
const GATE_BREAKER_WINDOW_SECS_KEY: &str = "window_secs";

/// Gate `content_kind` of the synthetic trip receipt.
pub(crate) const GATE_BREAKER_CONTENT_KIND: &str = "circuit_breaker";

/// Ledger outcome of the synthetic trip receipt.
pub(crate) const GATE_BREAKER_OUTCOME_TRIPPED: &str = "breaker_tripped";

/// Record-level reason code stamped on the synthetic trip receipt. The
/// receipt is not a claim verdict, so its raw `gate.`-prefixed string rides
/// [`GateDecisionRecord::reason_codes`] rather than the typed vocabulary.
pub(crate) const GATE_BREAKER_REASON_TRIPPED: &str = "gate.breaker.tripped";

/// Exact-value anchor for the demoted decision's typed reason. Production
/// decision construction uses [`super::decision::GateReasonCode`]; this
/// constant exists so tests can pin the wire string in one place.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const GATE_BREAKER_REASON_PENDING: &str = "gate.pending.actor_burst_breaker";

/// `vault_meta` key family of the durable breaker rows.
const GATE_BREAKER_META_PREFIX: &[u8] = b"gate.breaker.v1:";

/// Domain separator binding a trip receipt's `diff_handle` to its exact trip.
const GATE_BREAKER_RECEIPT_DOMAIN: &[u8] = b"oneiron/gate/actor-burst-breaker-receipt/v1";

/// The resolved per-window event budget applied to one breaker evaluation.
///
/// Engine defaults apply unless a policy manifest carries exactly one distinct
/// valid `actor_burst_breaker` override; see
/// [`parse_gate_breaker_thresholds`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateBreakerThresholds {
    pub max_events: u32,
    pub window_secs: u64,
}

impl Default for GateBreakerThresholds {
    fn default() -> Self {
        Self {
            max_events: GATE_BREAKER_DEFAULT_MAX_EVENTS,
            window_secs: GATE_BREAKER_WINDOW_SECS,
        }
    }
}

/// Read-only projection of one run's durable breaker state.
///
/// This is a PROJECTION, never a control door: it scans the run's key prefix,
/// decodes each row through the same decoder writes use, and reports whether
/// any of them is durably tripped. Time-based event pruning never changes the
/// answer, and there is no companion `clear`, `resume`, `reset`, or `untrip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GateBreakerRunProjection {
    pub gate_breaker_paused: bool,
}

/// The durable per-actor/run row.
///
/// `thresholds` is the snapshot the row's LATEST untripped evaluation used.
/// Once `tripped_at` is set the snapshot freezes with it: a manifest edit can
/// neither relax nor clear an already-tripped row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GateBreakerRowV1 {
    schema_version: u8,
    thresholds: GateBreakerThresholds,
    event_timestamps: Vec<u64>,
    tripped_at: Option<u64>,
}

impl GateBreakerRowV1 {
    /// A fresh row under `thresholds`, with an empty log and no trip.
    fn new(thresholds: GateBreakerThresholds) -> Self {
        Self {
            schema_version: GATE_BREAKER_ROW_SCHEMA_VERSION,
            thresholds,
            event_timestamps: Vec::new(),
            tripped_at: None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn tripped_at(&self) -> Option<u64> {
        self.tripped_at
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn thresholds(&self) -> GateBreakerThresholds {
        self.thresholds
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn event_timestamps(&self) -> &[u64] {
        &self.event_timestamps
    }
}

/// The ordinary outcome one gate event would otherwise land, restricted to
/// the two the breaker counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateBreakerCandidate {
    Auto,
    Proposed,
}

/// One pure rolling-window transition. Storage I/O and decision mutation stay
/// outside so the boundary rules are table-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateBreakerTransition {
    row: GateBreakerRowV1,
    outcome: GateBreakerCandidate,
    tripped_now: bool,
    event_count: u32,
    /// Whether the row bytes changed. An already-tripped short-circuit leaves
    /// the row exactly as stored, so its write is skipped entirely.
    rewritten: bool,
}

/// What breaker accounting did to ONE original gate event.
///
/// The trip FACTS — run, actor, post-append count, threshold snapshot, trip
/// instant — are not duplicated here: the durable row holds them and the
/// synthetic receipt binds them. What the caller needs back is only what it
/// cannot see for itself, which is how the event's own decision must change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateBreakerApplied {
    /// The event must land pending rather than automatically.
    pub(crate) decision_is_proposed: bool,
    /// The typed breaker-pending reason belongs on this decision. False for an
    /// event that was ALREADY `Proposed` for another cause: it counted, but
    /// its own pending reason set is not rewritten.
    pub(crate) add_pending_reason: bool,
    /// A would-be-`Auto` event the breaker converted to `Proposed`.
    pub(crate) breaker_demoted: bool,
    /// `(row_key, prior raw row bytes, trip receipt id)`. Rollback metadata
    /// for the preflight selective-error path, never a second persisted
    /// record. `None` prior bytes means the cleanup deletes a row this event
    /// created.
    pub(crate) breaker_undo: Option<GateBreakerUndo>,
}

/// Byte-exact restore instructions for one event's breaker mutation.
pub(crate) type GateBreakerUndo = (Vec<u8>, Option<Vec<u8>>, Option<GateDecisionId>);

/// A duplicate, absent, or malformed override never disables the breaker:
/// it contributes no candidate, so the resolver uses the engine defaults.
pub(super) fn decode_gate_breaker_override(
    entries: &[(Value, Value)],
) -> Option<GateBreakerThresholds> {
    let mut values = entries.iter().filter_map(|(key, value)| {
        (key.as_str() == Some(GATE_BREAKER_POLICY_KEY)).then_some(value)
    });
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    parse_gate_breaker_thresholds(value)
}

/// The optional resolved `actor_burst_breaker` manifest override.
///
/// A valid override is an object with EXACTLY the two positive integral fields
/// `max_events` (fitting `u32`) and `window_secs` (fitting `u64`). Zero,
/// negative, fractional, missing, duplicate, unknown, string, array, and
/// overflowed values all make the whole override malformed, and a malformed
/// override is NOT a candidate — it never disables accounting, never yields a
/// zero threshold, and never preserves a permissive partial field.
pub(super) fn parse_gate_breaker_thresholds(value: &Value) -> Option<GateBreakerThresholds> {
    let Value::Map(entries) = value else {
        return None;
    };
    let mut max_events = None;
    let mut window_secs = None;
    for (key, value) in entries {
        match key.as_str()? {
            GATE_BREAKER_MAX_EVENTS_KEY => {
                if max_events.is_some() {
                    return None;
                }
                max_events = Some(u32::try_from(positive_integer(value)?).ok()?);
            }
            GATE_BREAKER_WINDOW_SECS_KEY => {
                if window_secs.is_some() {
                    return None;
                }
                window_secs = Some(positive_integer(value)?);
            }
            _ => return None,
        }
    }
    Some(GateBreakerThresholds {
        max_events: max_events?,
        window_secs: window_secs?,
    })
}

/// A strictly positive MessagePack integer. `Value::as_u64` already refuses
/// floats, strings, arrays, booleans and negatives, so the only extra rule is
/// that zero is not a threshold.
fn positive_integer(value: &Value) -> Option<u64> {
    let integer = value.as_u64()?;
    (integer > 0).then_some(integer)
}

/// Folds every manifest's candidate into the ONE resolved dial.
///
/// A malformed override contributed no candidate upstream. If exactly one
/// distinct valid value exists it applies; two or more distinct valid values
/// are an ambiguity nothing downstream could resolve, so the resolved dial
/// falls back to engine defaults — as does the zero-candidate case.
pub(super) fn resolve_gate_breaker_thresholds(
    candidates: &[GateBreakerThresholds],
) -> Option<GateBreakerThresholds> {
    let mut distinct: Option<GateBreakerThresholds> = None;
    for candidate in candidates {
        match distinct {
            None => distinct = Some(*candidate),
            Some(existing) if existing == *candidate => {}
            Some(_) => return None,
        }
    }
    distinct
}

/// `b"gate.breaker.v1:" || u32_be(len(run)) || run`.
///
/// The length prefix is what lets bundle resolution delete every actor row for
/// ONE run without scanning unrelated metadata, and keeps a run id that is a
/// prefix of another from colliding with it.
fn gate_breaker_run_prefix(dreamer_run_id: &str) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(GATE_BREAKER_META_PREFIX.len() + 4 + dreamer_run_id.len() + 16);
    key.extend_from_slice(GATE_BREAKER_META_PREFIX);
    key.extend_from_slice(&be_len(dreamer_run_id.len()));
    key.extend_from_slice(dreamer_run_id.as_bytes());
    key
}

/// `run_prefix || canonical_actor_entity_id_bytes`.
///
/// Actor bytes come from the already-validated provenance actor entity
/// reference. Identity is NEVER derived from a display label, actor class
/// string, owner principal string, connector key, or agent name, and there is
/// no `unknown` actor row.
fn gate_breaker_row_key(dreamer_run_id: &str, actor_ref: &EntityId) -> Vec<u8> {
    let mut key = gate_breaker_run_prefix(dreamer_run_id);
    key.extend_from_slice(actor_ref.as_bytes());
    key
}

/// Length prefix that keeps the variable-width run id unambiguous.
fn be_len(len: usize) -> [u8; 4] {
    u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes()
}

fn encode_gate_breaker_row(row: &GateBreakerRowV1) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row)
        .map_err(|_| Error::InvariantViolation("gate breaker row encode failed"))
}

pub(crate) fn decode_gate_breaker_row(raw: &[u8]) -> Result<GateBreakerRowV1> {
    let row: GateBreakerRowV1 =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("gate breaker row"))?;
    if row.schema_version != GATE_BREAKER_ROW_SCHEMA_VERSION
        || row.thresholds.max_events == 0
        || row.thresholds.window_secs == 0
        || row
            .event_timestamps
            .windows(2)
            .any(|pair| pair[0] > pair[1])
    {
        return Err(Error::CorruptedIndex("gate breaker row"));
    }
    Ok(row)
}

/// The pure rolling-window transition. See the module docs for why the order
/// below is exact.
pub(crate) fn evaluate_gate_breaker_event(
    row: Option<GateBreakerRowV1>,
    live_thresholds: GateBreakerThresholds,
    candidate: GateBreakerCandidate,
    now: u64,
) -> GateBreakerTransition {
    // 0. Already tripped: nothing is refreshed, pruned, appended, or
    //    rewritten. The candidate is demoted and the reported count is pinned
    //    to the stored log length so the path stays deterministic.
    if let Some(row) = row.as_ref()
        && row.tripped_at.is_some()
    {
        let event_count = log_len(row);
        return GateBreakerTransition {
            row: row.clone(),
            outcome: GateBreakerCandidate::Proposed,
            tripped_now: false,
            event_count,
            rewritten: false,
        };
    }

    // 1. Create a missing row. 2. Refresh an untripped row's snapshot to the
    //    current valid-or-default manifest thresholds.
    let mut row = row.unwrap_or_else(|| GateBreakerRowV1::new(live_thresholds));
    row.thresholds = live_thresholds;

    // 3. Prune against the row snapshot. A timestamp EXACTLY one window old is
    //    expired.
    let window_secs = row.thresholds.window_secs;
    row.event_timestamps
        .retain(|timestamp| timestamp.saturating_add(window_secs) > now);

    // 4. Append `max(now, last)`. The clamp preserves the nondecreasing codec
    //    invariant under clock rollback: the row never stores a timestamp
    //    earlier than its predecessor.
    let appended = row
        .event_timestamps
        .last()
        .copied()
        .map_or(now, |last| now.max(last));
    row.event_timestamps.push(appended);

    // 5. Strict comparison on the POST-APPEND count: with a budget of 30,
    //    events 1..=30 do not trip and event 31 does. The timestamp that
    //    caused the trip stays in the row.
    let event_count = log_len(&row);
    if event_count > row.thresholds.max_events {
        row.tripped_at = Some(now);
        return GateBreakerTransition {
            row,
            outcome: GateBreakerCandidate::Proposed,
            tripped_now: true,
            event_count,
            rewritten: true,
        };
    }

    // 6. Otherwise the ordinary outcome stands.
    GateBreakerTransition {
        row,
        outcome: candidate,
        tripped_now: false,
        event_count,
        rewritten: true,
    }
}

fn log_len(row: &GateBreakerRowV1) -> u32 {
    u32::try_from(row.event_timestamps.len()).unwrap_or(u32::MAX)
}

/// Binds a trip receipt's `diff_handle` to the exact trip without minting an
/// entity. Every trip fact — run, actor, post-append count, snapshot — rides
/// this hash; the record's own `actor_ref` carries the actor.
pub(crate) fn gate_breaker_trip_handle(
    dreamer_run_id: &str,
    actor_ref: &EntityId,
    tripped_at: u64,
    event_count: u32,
    thresholds: GateBreakerThresholds,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GATE_BREAKER_RECEIPT_DOMAIN);
    hasher.update(be_len(dreamer_run_id.len()));
    hasher.update(dreamer_run_id.as_bytes());
    hasher.update(actor_ref.as_bytes());
    hasher.update(tripped_at.to_be_bytes());
    hasher.update(event_count.to_be_bytes());
    hasher.update(thresholds.max_events.to_be_bytes());
    hasher.update(thresholds.window_secs.to_be_bytes());
    hasher.finalize().into()
}

/// Books ONE original agent-run gate event against its actor/run row, inside
/// the caller's write transaction.
///
/// The caller has already established every precondition the breaker's scope
/// depends on: a nonempty run id, a validated provenance actor entity
/// reference, an agent (non-owner) actor, an ordinary `Auto`/`Proposed`
/// result, and an original event that is neither the synthetic trip receipt
/// nor an owner-authenticated bundle replay.
#[expect(
    clippy::too_many_arguments,
    reason = "the trip receipt binds the triggering decision's own manifest version and frontier, which are not derivable here"
)]
pub(crate) fn apply_gate_breaker_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    dreamer_run_id: &str,
    actor_ref: &EntityId,
    actor_class: &str,
    candidate: GateBreakerCandidate,
    policy: &PolicyManifestResolution,
    policy_manifest_version: &str,
    read_frontier_hash: [u8; 32],
    now: u64,
) -> Result<GateBreakerApplied> {
    let row_key = gate_breaker_row_key(dreamer_run_id, actor_ref);
    let prior_row_bytes = store.vault_meta.get(&*wtxn, &row_key)?.map(Cow::into_owned);
    let row = prior_row_bytes
        .as_deref()
        .map(decode_gate_breaker_row)
        .transpose()?;

    // The already-resolved snapshot that produced the ordinary decision. The
    // manifest is never reopened between policy evaluation, this accounting,
    // the ordinary receipt, and the trip receipt.
    let live_thresholds = policy.actor_burst_breaker_thresholds();
    let transition = evaluate_gate_breaker_event(row, live_thresholds, candidate, now);

    if transition.rewritten {
        store
            .vault_meta
            .put(wtxn, &row_key, &encode_gate_breaker_row(&transition.row)?)?;
    }

    // ONLY the `None` -> `Some(now)` transition appends a receipt. Later
    // demotions while tripped append no second one, and the receipt itself is
    // never recursively counted as a breaker event.
    let trip_receipt_id = if transition.tripped_now {
        let tripped_at = transition.row.tripped_at.ok_or(Error::InvariantViolation(
            "gate breaker trip transition lost its trip instant",
        ))?;
        let mut record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::now(),
            created_at: now,
            outcome: GATE_BREAKER_OUTCOME_TRIPPED.to_owned(),
            reason_codes: vec![GATE_BREAKER_REASON_TRIPPED.to_owned()],
            // The store's receipt-reason allowlist admits no breaker family,
            // and the record carries no system notice: every trip fact rides
            // `diff_handle` and `actor_ref` instead.
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: actor_class.to_owned(),
            actor_ref: Some(actor_ref.to_hex()),
            content_kind: GATE_BREAKER_CONTENT_KIND.to_owned(),
            policy_manifest_version: policy_manifest_version.to_owned(),
            claim_id: None,
            grant_ref: None,
            diff_handle: gate_breaker_trip_handle(
                dreamer_run_id,
                actor_ref,
                tripped_at,
                transition.event_count,
                transition.row.thresholds,
            )
            .to_vec(),
            read_frontier_hash,
            redacted_at: None,
        };
        store.append_fresh_gate_decision_in_txn(wtxn, &mut record)?;
        Some(record.decision_id)
    } else {
        None
    };

    let decision_is_proposed = transition.outcome == GateBreakerCandidate::Proposed;
    let breaker_demoted = decision_is_proposed && candidate == GateBreakerCandidate::Auto;
    Ok(GateBreakerApplied {
        decision_is_proposed,
        // An event already `Proposed` for another cause keeps its own pending
        // reason set; the separate trip receipt records the transition.
        add_pending_reason: breaker_demoted,
        breaker_demoted,
        breaker_undo: (transition.rewritten || trip_receipt_id.is_some()).then_some((
            row_key,
            prior_row_bytes,
            trip_receipt_id,
        )),
    })
}

/// Reverses ONE staged event's breaker mutation, byte-exactly.
///
/// Restores the observed prior bytes, or deletes the row this event created,
/// then removes the trip receipt it appended. Callers walk their staged
/// decisions in REVERSE staging order, which is what makes a shared actor/run
/// row land back on the byte state before the first staged claim.
pub(crate) fn undo_gate_breaker_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    undo: &GateBreakerUndo,
) -> Result<()> {
    let (row_key, prior_row_bytes, trip_receipt_id) = undo;
    match prior_row_bytes {
        Some(prior) => store.vault_meta.put(wtxn, row_key, prior)?,
        None => {
            store.vault_meta.delete(wtxn, row_key)?;
        }
    }
    if let Some(trip_receipt_id) = trip_receipt_id {
        store.delete_gate_decision_in_txn(wtxn, *trip_receipt_id)?;
    }
    Ok(())
}

/// Deletes every breaker row under ONE run's length-prefixed key prefix.
///
/// The only caller is [`crate::Vault::resolve_gate_consent_bundle`], AFTER it
/// has validated the live bundle and BEFORE it replays or declines a member.
/// A later failure in that transaction rolls the deletes back with everything
/// else, so an unresolved bundle never leaves the run unpaused.
pub(crate) fn clear_gate_breaker_rows_for_run_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    dreamer_run_id: &str,
) -> Result<()> {
    let prefix = gate_breaker_run_prefix(dreamer_run_id);
    let mut keys = Vec::new();
    for row in store.vault_meta.prefix_iter(&*wtxn, &prefix)? {
        let (key, _) = row?;
        keys.push(key.to_vec());
    }
    for key in &keys {
        store.vault_meta.delete(wtxn, key)?;
    }
    Ok(())
}

/// Every breaker row under one run, in key order. Read-only.
fn gate_breaker_rows_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    dreamer_run_id: &str,
) -> Result<Vec<GateBreakerRowV1>> {
    let prefix = gate_breaker_run_prefix(dreamer_run_id);
    let mut rows = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (_, value) = row?;
        rows.push(decode_gate_breaker_row(&value)?);
    }
    Ok(rows)
}

impl Vault {
    /// Whether ANY actor on `dreamer_run_id` is durably paused by the burst
    /// breaker.
    ///
    /// Read-only and NOT a control door: it scans only this run's key prefix,
    /// validates row versions through the same decoder writes use, and never
    /// mutates. Time passing, event-log pruning, a manifest edit, and a vault
    /// reopen all leave the answer unchanged; only an owner-authenticated
    /// [`Vault::resolve_gate_consent_bundle`] clears it.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] when a row under this run's prefix is not a
    /// decodable schema-v1 breaker row, plus storage failures.
    pub fn gate_breaker_run_projection(
        &self,
        dreamer_run_id: &str,
    ) -> Result<GateBreakerRunProjection> {
        let rtxn = self.store.env.read_txn()?;
        let rows = gate_breaker_rows_in_txn(&self.store, &rtxn, dreamer_run_id)?;
        Ok(GateBreakerRunProjection {
            gate_breaker_paused: rows.iter().any(|row| row.tripped_at.is_some()),
        })
    }
}

/// Test-only reader for one exact actor/run row's raw bytes.
#[cfg(test)]
pub(crate) fn gate_breaker_row_bytes_for_test(
    store: &Store,
    txn: &RoTxn<'_>,
    dreamer_run_id: &str,
    actor_ref: &EntityId,
) -> Result<Option<Vec<u8>>> {
    let key = gate_breaker_row_key(dreamer_run_id, actor_ref);
    Ok(store.vault_meta.get(txn, &key)?.map(Cow::into_owned))
}

/// Test-only writer that seeds one exact actor/run row.
///
/// It exists so a durability test can present a row whose event log is many
/// windows old WITHOUT a clock hook: back-dating the stored timestamps is
/// exactly what "engine time advanced past the whole window" looks like from
/// the row's side.
#[cfg(test)]
pub(crate) fn put_gate_breaker_row_for_test(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    dreamer_run_id: &str,
    actor_ref: &EntityId,
    row: &GateBreakerRowV1,
) -> Result<()> {
    let key = gate_breaker_row_key(dreamer_run_id, actor_ref);
    store
        .vault_meta
        .put(wtxn, &key, &encode_gate_breaker_row(row)?)
}

/// Test-only reader for one exact actor/run row.
#[cfg(test)]
pub(crate) fn gate_breaker_row_for_test(
    store: &Store,
    txn: &RoTxn<'_>,
    dreamer_run_id: &str,
    actor_ref: &EntityId,
) -> Result<Option<GateBreakerRowV1>> {
    gate_breaker_row_bytes_for_test(store, txn, dreamer_run_id, actor_ref)?
        .as_deref()
        .map(decode_gate_breaker_row)
        .transpose()
}

/// Test-only count of the rows one run holds.
#[cfg(test)]
pub(crate) fn gate_breaker_run_row_count_for_test(
    store: &Store,
    txn: &RoTxn<'_>,
    dreamer_run_id: &str,
) -> Result<usize> {
    Ok(gate_breaker_rows_in_txn(store, txn, dreamer_run_id)?.len())
}

/// Test-only constructor for the pure transition's table tests.
#[cfg(test)]
pub(crate) fn gate_breaker_row_for_transition_test(
    thresholds: GateBreakerThresholds,
    event_timestamps: Vec<u64>,
    tripped_at: Option<u64>,
) -> GateBreakerRowV1 {
    GateBreakerRowV1 {
        schema_version: GATE_BREAKER_ROW_SCHEMA_VERSION,
        thresholds,
        event_timestamps,
        tripped_at,
    }
}

#[cfg(test)]
impl GateBreakerTransition {
    pub(crate) fn row(&self) -> &GateBreakerRowV1 {
        &self.row
    }

    pub(crate) fn outcome(&self) -> GateBreakerCandidate {
        self.outcome
    }

    pub(crate) fn tripped_now(&self) -> bool {
        self.tripped_now
    }

    pub(crate) fn event_count(&self) -> u32 {
        self.event_count
    }

    pub(crate) fn rewritten(&self) -> bool {
        self.rewritten
    }
}
