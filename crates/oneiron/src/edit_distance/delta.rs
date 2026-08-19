//! ED-01 (ARCH-0056 §2, ONE-1757): the amendment-Δ schema, its two capture
//! lanes, and the chooser every production caller rides.
//!
//! # What a Δ is
//!
//! [`AmendmentDelta`] answers "how much did the decider change, and how do I
//! find both ends?" for one proposal→outcome window. It is TELEMETRY: the
//! edit-distance loop mines it, and no door blocks on it. That single fact
//! shapes the module — capture failure is reported, never raised into the
//! approval path (see [`capture_delta_best`]'s callers).
//!
//! # Two lanes, one precedence
//!
//! * [`DeltaSource::RecordedOps`] — ED-00's finalized op window
//!   ([`FinalizedProposalText`]) replayed per change. It sees CHURN (text
//!   typed then retyped) that an endpoint comparison cannot, which is why it
//!   outranks the others.
//! * [`DeltaSource::FieldDiff`] — two canonical-MessagePack bodies (claim
//!   bodies, identity-topology op amendments) walked as trees, counting
//!   changed leaves. Cheaper and far more legible than op replay for
//!   structured payloads, where "the survivor field changed" beats "eleven
//!   characters moved".
//! * [`DeltaSource::Reconstructed`] — two endpoint TEXTS diffed line by line
//!   ([`crate::edit_distance::myers`], ED-02). The lane of last resort: it is
//!   the only one that works when an edit arrived out of band, with no op log
//!   and no structured body, and the only one that can report a MOVE.
//!
//! [`capture_delta_best`] pins the precedence `recorded_ops > field_diff >
//! reconstructed` HERE, so no caller hand-picks a lane.
//!
//! # The Δ's own bytes
//!
//! [`AmendmentDelta::encode`] serializes through the house canonical JSON
//! (`crate::llm::canonical_json_bytes`) — sorted keys, so a receipt's Δ
//! payload is stable bytes across processes and orderings.
//!
//! # Where a Δ lives
//!
//! Receipts are PROJECTIONS, not stored rows, so a Δ cannot be stamped onto
//! one after the fact. It lives in its own `vault_meta` row keyed by the
//! RECEIPT ID it belongs to, and `attach_amendment_deltas` folds it into
//! the reserved `amendment_delta` slot as every receipt query projects. The
//! producer artifact the Δ was computed FROM (`amended_body`, ONE-1747) is
//! never touched: two slots, two meanings.
//!
//! A capture that FAILS writes that same row as
//! `AMENDMENT_DELTA_UNCAPTURED_ROW` and projects its own receipt marker.
//! Non-fatal, but never silent: an approval whose Δ could not be measured
//! must not look identical to one nothing has measured yet.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::edit_distance::FinalizedProposalText;
use crate::edit_distance::myers::{MOVE_DISCOUNT, myers_line_diff};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::receipt::{
    FIELD_AMENDMENT_DELTA, FIELD_AMENDMENT_DELTA_UNCAPTURED, MAX_RECEIPT_QUERY_SCAN, ReceiptKind,
    ReceiptQuery, ReceiptRecord, proposal_outcome_amended_body,
};

/// `vault_meta` prefix for the Δ side-ledger. Keyed by receipt id, which is
/// what the reader joins on — deriving the key from the receipt projector's
/// own id keeps writer and reader from drifting apart.
const AMENDMENT_DELTA_KEY_PREFIX: &[u8] = b"edit_distance/amendment_delta/v1\0";

/// Row value standing for "capture was ATTEMPTED here and failed". A Δ row is
/// canonical JSON, which always opens `{`, so a bare token can never be read
/// as one.
///
/// The row is what makes the failure honest: without it, a receipt whose
/// capture failed is byte-for-byte indistinguishable from one the projection
/// pass never visited.
const AMENDMENT_DELTA_UNCAPTURED_ROW: &[u8] = b"uncaptured";

/// The outcome token a Δ-carrying receipt reports. Both amendment doors
/// (identity-topology resolution, ONE-1747; the inbox approve-with-edit door
/// below) stamp it, which is what makes ONE attach pass serve both.
pub(crate) const OUTCOME_APPROVED_AMENDED: &str = "approved_amended";

/// `trigger_ref` prefix a proposal-outcome receipt carries for its proposal.
const PROPOSAL_TRIGGER_PREFIX: &str = "event:";

/// Traversal depth cap for [`delta_from_field_diff`]. Past it, a subtree is
/// compared as one opaque leaf: a Δ is telemetry, and no telemetry number is
/// worth a stack overflow on a body whose nesting the caller did not choose.
const MAX_FIELD_DIFF_DEPTH: u32 = 64;

/// How an [`AmendmentDelta`] was measured. Ordered by precedence, and the
/// token is pinned: a receipt's Δ payload carries it on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaSource {
    /// Replayed from ED-00's recorded op window.
    RecordedOps,
    /// Structured per-field diff of two canonical-MessagePack bodies.
    FieldDiff,
    /// Reconstructed after the fact by diffing the two endpoint texts.
    Reconstructed,
}

impl DeltaSource {
    /// The pinned on-disk token for this lane.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordedOps => "recorded_ops",
            Self::FieldDiff => "field_diff",
            Self::Reconstructed => "reconstructed",
        }
    }
}

/// The edit mass behind a Δ, in the unit its lane counts: CHARACTERS for
/// [`DeltaSource::RecordedOps`], LEAVES for [`DeltaSource::FieldDiff`], LINES
/// for [`DeltaSource::Reconstructed`].
///
/// `moved` is the discount channel: a producer that DETECTS a move records
/// the relocated units here and leaves them out of `ins`/`del`, so relocated
/// content is charged once and cheaply instead of twice at full price. Only
/// the reconstructed lane detects moves; the other two report `0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsSummary {
    /// Units inserted.
    pub ins: u32,
    /// Units deleted.
    pub del: u32,
    /// Units the amendment left standing.
    pub kept: u32,
    /// Units relocated rather than rewritten (see the type docs).
    pub moved: u32,
    /// Whether the producer hit its own cost cap, leaving these counts an
    /// upper BOUND rather than an exact script.
    ///
    /// Only the reconstructed lane can set it (its Myers trace is the only
    /// capped work in the module). It rides the Δ onto disk because a
    /// consumer reading a capped diff as exact is the one way this telemetry
    /// lies.
    pub approx: bool,
}

impl OpsSummary {
    /// `clamp(edit_mass / (len_before + len_after), 0, 1)` — the ONE ratified
    /// ED metric, with `edit_mass = ins + del + 2 · MOVE_DISCOUNT · moved`.
    ///
    /// Every producer normalizes HERE so no two lanes can drift into
    /// different numbers. Two properties the callers depend on:
    ///
    /// * The denominator SUMS the two lengths rather than taking the max,
    ///   because a rewritten unit is one deletion AND one insertion: a full
    ///   replacement scores exactly `1`, where a max denominator would score
    ///   it `2`.
    /// * A zero-length window scores `0`. Nothing changed, because there was
    ///   nothing to change.
    #[must_use]
    pub fn d_norm(self, len_before: u32, len_after: u32) -> f32 {
        let window = len_before.saturating_add(len_after);
        if window == 0 {
            return 0.0;
        }
        let ratio = self.edit_mass() / f64::from(window);
        ratio.clamp(0.0, 1.0) as f32
    }

    /// The edit mass `d_norm` normalizes. A relocated unit costs
    /// `2 · MOVE_DISCOUNT` where the delete-plus-insert it stands in for
    /// would cost `2`.
    fn edit_mass(self) -> f64 {
        let relocated = f64::from(2.0 * MOVE_DISCOUNT) * f64::from(self.moved);
        f64::from(self.ins) + f64::from(self.del) + relocated
    }
}

/// The six ARCH-0056 §2 Δ fields, serialized into ONE-1747's reserved
/// `amendment_delta` receipt slot.
///
/// `proposed_ref` / `final_ref` are read THROUGH `source`: the recorded-ops
/// lane carries encoded Loro `Frontiers` (directly replayable), the
/// field-diff and reconstructed lanes carry the blake3 of each side (directly
/// verifiable). One string type, two meanings, disambiguated by a field that
/// is already in the struct.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AmendmentDelta {
    /// Handle for the window's proposed end.
    pub proposed_ref: String,
    /// Handle for the window's finalized end.
    pub final_ref: String,
    /// Which lane measured this Δ.
    pub source: DeltaSource,
    /// [`OpsSummary::d_norm`] — the ONE pinned formula every ED producer
    /// uses, so a downstream consumer never sees mixed metrics.
    pub d_norm: f32,
    /// The edit mass behind `d_norm`.
    pub ops_summary: OpsSummary,
    /// Engine version that measured it, stamped at the encode site.
    pub engine_ver: String,
}

impl AmendmentDelta {
    /// Canonical bytes for the reserved receipt slot.
    ///
    /// # Errors
    ///
    /// Serialization failure — reachable only for a hand-built Δ whose
    /// `d_norm` is not finite (JSON has no NaN). Every constructor here
    /// clamps, so the engine's own Δs cannot hit it.
    pub fn encode(&self) -> Result<Vec<u8>> {
        crate::llm::canonical_json_bytes(self)
            .map_err(|_| Error::InvariantViolation("amendment delta encode"))
    }

    /// Reads back an encoded Δ.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] when the payload is not a Δ this engine
    /// wrote.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| Error::CorruptedIndex("amendment delta"))
    }
}

// ---------------------------------------------------------------------------
// Lane 1 — recorded ops
// ---------------------------------------------------------------------------

/// Measures a Δ by replaying ED-00's finalized op window.
///
/// `ins`/`del` sum the changed region of EVERY recorded change, so text the
/// decider typed and then replaced is counted twice — deliberately. That
/// churn is the recorded-ops lane's whole advantage over comparing the two
/// endpoints, and it is what the miner reads as effort.
///
/// `kept` is measured at the ENDPOINTS instead (the proposal text still
/// standing at finalize), because summing per-change survivals would count
/// the untouched remainder once per change.
///
/// The per-change region is the span between the common prefix and the
/// common suffix — one contiguous edit. A change that scatters edits across
/// a line reads as one wider region, which under-counts `kept` and never
/// under-counts `ins`/`del`; ED-02's Myers pass (ONE-1758) is what resolves
/// scattered changes exactly.
#[must_use]
pub fn delta_from_recorded_ops(finalized: &FinalizedProposalText) -> AmendmentDelta {
    let mut ins: u32 = 0;
    let mut del: u32 = 0;
    for (_, span) in &finalized.ops_by_actor {
        let affix = CharAffix::between(&span.before_text, &span.after_text);
        del = del.saturating_add(affix.removed());
        ins = ins.saturating_add(affix.added());
    }
    let window = CharAffix::between(&finalized.proposed_text, &finalized.final_text);
    let ops_summary = OpsSummary {
        ins,
        del,
        kept: window.common(),
        moved: 0,
        approx: false,
    };
    AmendmentDelta {
        proposed_ref: bytes_to_hex_lower(finalized.proposed_ref.as_bytes()),
        final_ref: bytes_to_hex_lower(finalized.final_ref.as_bytes()),
        source: DeltaSource::RecordedOps,
        d_norm: ops_summary.d_norm(window.before_len, window.after_len),
        ops_summary,
        engine_ver: engine_ver(),
    }
}

/// Two strings split at their common prefix and suffix, in CHARACTERS —
/// bytes would let a multi-byte edit report a fractional change.
struct CharAffix {
    prefix: u32,
    suffix: u32,
    before_len: u32,
    after_len: u32,
}

impl CharAffix {
    fn between(before: &str, after: &str) -> Self {
        let before: Vec<char> = before.chars().collect();
        let after: Vec<char> = after.chars().collect();
        let prefix = before
            .iter()
            .zip(&after)
            .take_while(|(left, right)| left == right)
            .count();
        // The prefix and suffix must not overlap on the shorter side, or a
        // repeated run ("aaa" -> "aaaaa") would report negative change.
        let overlap_budget = before.len().min(after.len()) - prefix;
        let suffix = before
            .iter()
            .rev()
            .zip(after.iter().rev())
            .take(overlap_budget)
            .take_while(|(left, right)| left == right)
            .count();
        Self {
            prefix: u32_saturating(prefix),
            suffix: u32_saturating(suffix),
            before_len: u32_saturating(before.len()),
            after_len: u32_saturating(after.len()),
        }
    }

    const fn common(&self) -> u32 {
        self.prefix.saturating_add(self.suffix)
    }

    const fn removed(&self) -> u32 {
        self.before_len.saturating_sub(self.common())
    }

    const fn added(&self) -> u32 {
        self.after_len.saturating_sub(self.common())
    }
}

// ---------------------------------------------------------------------------
// Lane 2 — field diff
// ---------------------------------------------------------------------------

/// Measures a Δ by walking two canonical-MessagePack bodies as trees and
/// counting changed LEAVES.
///
/// A leaf at the same path that differs is one deletion AND one insertion —
/// the field was rewritten, not merely touched — so a body where every field
/// changed scores `d_norm == 1`, matching the character lane's full-rewrite
/// score.
///
/// Arrays are compared POSITIONALLY: a reordered list reads as changes until
/// a move-detecting producer lands (see [`OpsSummary`]). Identity-topology
/// bodies canonicalize their arrays at the encode door, so their order is
/// meaning, not accident.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] when either side is not decodable MessagePack.
pub fn delta_from_field_diff(proposed: &[u8], finalized: &[u8]) -> Result<AmendmentDelta> {
    let before = decode_body(proposed)?;
    let after = decode_body(finalized)?;
    let mut counts = LeafCounts::default();
    diff_values(&before, &after, 0, &mut counts);
    let ops_summary = OpsSummary {
        ins: counts.ins,
        del: counts.del,
        kept: counts.kept,
        moved: 0,
        approx: false,
    };
    Ok(AmendmentDelta {
        proposed_ref: bytes_to_hex_lower(blake3::hash(proposed).as_bytes()),
        final_ref: bytes_to_hex_lower(blake3::hash(finalized).as_bytes()),
        source: DeltaSource::FieldDiff,
        d_norm: ops_summary.d_norm(counts.before, counts.after),
        ops_summary,
        engine_ver: engine_ver(),
    })
}

fn decode_body(bytes: &[u8]) -> Result<Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::CorruptedIndex("amendment delta body"))?;
    if cursor.is_empty() {
        Ok(value)
    } else {
        Err(Error::CorruptedIndex("amendment delta body"))
    }
}

#[derive(Default)]
struct LeafCounts {
    ins: u32,
    del: u32,
    kept: u32,
    before: u32,
    after: u32,
}

impl LeafCounts {
    /// Charges a whole subtree present only on the before side.
    fn removed_subtree(&mut self, value: &Value) {
        let leaves = leaf_count(value);
        self.del = self.del.saturating_add(leaves);
        self.before = self.before.saturating_add(leaves);
    }

    /// Charges a whole subtree present only on the after side.
    fn added_subtree(&mut self, value: &Value) {
        let leaves = leaf_count(value);
        self.ins = self.ins.saturating_add(leaves);
        self.after = self.after.saturating_add(leaves);
    }
}

fn diff_values(before: &Value, after: &Value, depth: u32, counts: &mut LeafCounts) {
    if depth < MAX_FIELD_DIFF_DEPTH {
        match (before, after) {
            (Value::Map(left), Value::Map(right)) => {
                diff_maps(left, right, depth, counts);
                return;
            }
            (Value::Array(left), Value::Array(right)) => {
                diff_arrays(left, right, depth, counts);
                return;
            }
            _ => {}
        }
    }
    if before == after {
        counts.kept = counts.kept.saturating_add(1);
        counts.before = counts.before.saturating_add(1);
        counts.after = counts.after.saturating_add(1);
    } else {
        counts.removed_subtree(before);
        counts.added_subtree(after);
    }
}

fn diff_maps(
    left: &[(Value, Value)],
    right: &[(Value, Value)],
    depth: u32,
    counts: &mut LeafCounts,
) {
    for (key, value) in left {
        match right.iter().find(|(other, _)| other == key) {
            Some((_, other)) => diff_values(value, other, depth + 1, counts),
            None => counts.removed_subtree(value),
        }
    }
    for (key, value) in right {
        if !left.iter().any(|(other, _)| other == key) {
            counts.added_subtree(value);
        }
    }
}

fn diff_arrays(left: &[Value], right: &[Value], depth: u32, counts: &mut LeafCounts) {
    let shared = left.len().min(right.len());
    for index in 0..shared {
        diff_values(&left[index], &right[index], depth + 1, counts);
    }
    for value in &left[shared..] {
        counts.removed_subtree(value);
    }
    for value in &right[shared..] {
        counts.added_subtree(value);
    }
}

/// Leaves under `value`. An empty map or array has none: adding one changes
/// no field, and charging it as change would score a no-op body rewrite.
fn leaf_count(value: &Value) -> u32 {
    match value {
        Value::Map(entries) => entries.iter().fold(0, |total: u32, (_, value)| {
            total.saturating_add(leaf_count(value))
        }),
        Value::Array(values) => values.iter().fold(0, |total: u32, value| {
            total.saturating_add(leaf_count(value))
        }),
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Lane 3 — reconstructed
// ---------------------------------------------------------------------------

/// Measures a Δ by diffing the two endpoint TEXTS line by line, for an edit
/// that arrived with no op log and no structured body — a human editing
/// outside the gated proposal flow.
///
/// Last in precedence for a reason: the endpoints are all it has, so churn
/// (text typed and then replaced) is invisible to it, and a rewrite that
/// happens to land back on the proposed text scores zero. What it can do that
/// neither other lane can is recognize a MOVE: relocated lines land in
/// [`OpsSummary::moved`] at [`MOVE_DISCOUNT`] rather than being charged twice
/// as a deletion and an insertion.
///
/// The refs are the two texts' own blake3 hashes, so a consumer can verify
/// the pair it was handed — the same contract the field-diff lane keeps.
#[must_use]
pub fn delta_from_reconstructed(before: &str, after: &str) -> AmendmentDelta {
    let diff = myers_line_diff(before, after);
    AmendmentDelta {
        proposed_ref: bytes_to_hex_lower(blake3::hash(before.as_bytes()).as_bytes()),
        final_ref: bytes_to_hex_lower(blake3::hash(after.as_bytes()).as_bytes()),
        source: DeltaSource::Reconstructed,
        d_norm: diff.d_norm,
        ops_summary: diff.ops,
        engine_ver: engine_ver(),
    }
}

// ---------------------------------------------------------------------------
// Chooser
// ---------------------------------------------------------------------------

/// What a caller can offer the chooser — every lane it could measure, not the
/// one it wants. Picking is [`capture_delta_best`]'s job, and keeping that
/// choice out of the caller is the whole point of the type.
pub struct DeltaCaptureContext<'a> {
    /// ED-00's finalized op window, when the artifact rode one.
    pub recorded: Option<&'a FinalizedProposalText>,
    /// `(proposed, finalized)` canonical-MessagePack bodies.
    pub bodies: Option<(&'a [u8], &'a [u8])>,
    /// `(before, after)` endpoint texts, for an edit that rode neither.
    pub texts: Option<(&'a str, &'a str)>,
}

impl<'a> DeltaCaptureContext<'a> {
    /// Context for two structured bodies.
    #[must_use]
    pub const fn from_bodies(proposed: &'a [u8], finalized: &'a [u8]) -> Self {
        Self {
            recorded: None,
            bodies: Some((proposed, finalized)),
            texts: None,
        }
    }

    /// Context for two endpoint texts — the out-of-band edit.
    #[must_use]
    pub const fn from_texts(before: &'a str, after: &'a str) -> Self {
        Self {
            recorded: None,
            bodies: None,
            texts: Some((before, after)),
        }
    }
}

/// Captures the best Δ the context supports: `recorded_ops > field_diff >
/// reconstructed` (ruling r2 — Myers is never preferred when ops exist).
///
/// # Errors
///
/// [`Error::DeltaCaptureUnavailable`] when the context offers no lane at all.
/// Callers treat it as telemetry loss, never as a failed approval.
pub fn capture_delta_best(ctx: &DeltaCaptureContext<'_>) -> Result<AmendmentDelta> {
    if let Some(recorded) = ctx.recorded {
        return Ok(delta_from_recorded_ops(recorded));
    }
    if let Some((proposed, finalized)) = ctx.bodies {
        return delta_from_field_diff(proposed, finalized);
    }
    if let Some((before, after)) = ctx.texts {
        return Ok(delta_from_reconstructed(before, after));
    }
    Err(Error::DeltaCaptureUnavailable("context offers no lane"))
}

// ---------------------------------------------------------------------------
// Δ side-ledger + receipt attachment
// ---------------------------------------------------------------------------

fn amendment_delta_key(receipt_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(AMENDMENT_DELTA_KEY_PREFIX.len() + receipt_id.len());
    key.extend_from_slice(AMENDMENT_DELTA_KEY_PREFIX);
    key.extend_from_slice(receipt_id.as_bytes());
    key
}

/// Records `delta` against the receipt it describes, returning whether a row
/// was written.
///
/// **First writer wins.** A Δ is a measurement of a window that is already
/// closed, so a later pass re-measuring it (under a newer `engine_ver`, say)
/// has nothing new to say about what the decider did. Overwriting would make
/// a receipt's Δ drift under a reader who quoted it.
pub(crate) fn put_amendment_delta_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_id: &str,
    delta: &AmendmentDelta,
) -> Result<bool> {
    put_amendment_row_in_txn(vault, wtxn, receipt_id, &delta.encode()?)
}

/// The write-once side-ledger row itself — a Δ payload or
/// [`AMENDMENT_DELTA_UNCAPTURED_ROW`]. Both outcomes are measurements of the
/// same closed window, so both take the same first-writer-wins law.
fn put_amendment_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_id: &str,
    row: &[u8],
) -> Result<bool> {
    let key = amendment_delta_key(receipt_id);
    if vault.store.vault_meta.get(&*wtxn, &key)?.is_some() {
        return Ok(false);
    }
    vault.store.vault_meta.put(wtxn, &key, row)?;
    Ok(true)
}

/// The Δ recorded for `receipt_id`, if one was captured.
///
/// `None` covers both "never measured" and "measured and failed" — this
/// accessor answers for the Δ, and there is none either way. The RECEIPT is
/// where the two part company: attachment projects
/// `FIELD_AMENDMENT_DELTA_UNCAPTURED` for the second.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on an undecodable row.
pub fn amendment_delta(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentDelta>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(row) = amendment_delta_in_txn(vault, &rtxn, receipt_id)? else {
        return Ok(None);
    };
    if row == AMENDMENT_DELTA_UNCAPTURED_ROW {
        return Ok(None);
    }
    AmendmentDelta::decode(&row).map(Some)
}

fn amendment_delta_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    receipt_id: &str,
) -> Result<Option<Vec<u8>>> {
    Ok(vault
        .store
        .vault_meta
        .get(rtxn, &amendment_delta_key(receipt_id))?
        .map(std::borrow::Cow::into_owned))
}

/// Whether this engine recorded an AMENDMENT against `receipt_id` — the
/// durable mark that a decider approved-and-changed, on the caller's snapshot.
///
/// Both row shapes answer `true`: a measured Δ and an
/// [`FIELD_AMENDMENT_DELTA_UNCAPTURED`] marker differ on whether the
/// measurement succeeded, not on whether the amendment happened. Every writer
/// of either row is gated on an `approved_amended` outcome
/// ([`project_identity_amendment_deltas`], `inbox`'s amend-accept), so the
/// presence of a row is the engine's own record that the outcome was
/// adjudicated — which is why [`record_amendment_evidence`] refuses a receipt
/// without one, and why a projection over amendments can gate on it rather
/// than re-deriving adjudication from receipt fields.
///
/// [`record_amendment_evidence`]: super::attribution::record_amendment_evidence
///
/// # Errors
///
/// Storage errors.
pub(crate) fn amendment_recorded_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    receipt_id: &str,
) -> Result<bool> {
    Ok(vault
        .store
        .vault_meta
        .get(rtxn, &amendment_delta_key(receipt_id))?
        .is_some())
}

/// Folds recorded Δs into the reserved `amendment_delta` slot of every
/// amended receipt in `records`, and a failed capture into its own
/// [`FIELD_AMENDMENT_DELTA_UNCAPTURED`] marker.
///
/// Two fields, because the two facts are different: a Δ says how much the
/// decider changed, the marker says the engine looked and could not tell. A
/// receipt carrying NEITHER has simply not been projected yet — which is a
/// third fact, and the reason the marker is written at all.
///
/// The `approved_amended` filter is the point: an unamended outcome has no Δ
/// by definition, so the common query pays no lookups at all.
pub(crate) fn attach_amendment_deltas(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    records: &mut [ReceiptRecord],
) -> Result<()> {
    for record in records
        .iter_mut()
        .filter(|record| record.outcome == OUTCOME_APPROVED_AMENDED)
    {
        let Some(row) = amendment_delta_in_txn(vault, rtxn, &record.receipt_id)? else {
            continue;
        };
        let (field, value) = if row == AMENDMENT_DELTA_UNCAPTURED_ROW {
            (FIELD_AMENDMENT_DELTA_UNCAPTURED, "true".to_owned())
        } else {
            (FIELD_AMENDMENT_DELTA, bytes_to_hex_lower(&row))
        };
        record.fields.insert(field.to_owned(), value);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Identity-topology projection pass
// ---------------------------------------------------------------------------

/// Measures and records the Δ for every identity-topology amendment that has
/// none yet, returning how many rows this pass wrote.
///
/// Post-hoc BY DESIGN. The resolve door lives in the identity-topology spine
/// (ONE-1747) and already emits everything a Δ needs: the proposal it ruled
/// on (`trigger_ref`) and the amended body verbatim (`amended_body`). Reading
/// those two back beats reaching into another module's write path, and it is
/// what makes ONE-1747's two-slot contract hold — the producer artifact stays
/// byte-identical, the RESERVED slot is what this fills.
///
/// A receipt with no measurable PAIR — nothing amended, no resolvable
/// proposal — is SKIPPED, not raised: it stays eligible for a later pass, and
/// one unreadable proposal must not deny every other amendment its telemetry.
/// A receipt whose pair EXISTS and whose measurement fails is recorded as
/// `ProjectedDelta::Uncaptured` instead, because "capture failed" and "never
/// ran" are different facts a reader is entitled to tell apart. A Δ written
/// for a resolution the fold later suppresses is inert — attachment only
/// visits receipts that projected.
///
/// # Errors
///
/// Storage errors.
pub fn project_identity_amendment_deltas(vault: &Vault) -> Result<usize> {
    let mut query = ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN);
    query.kinds.insert(ReceiptKind::ProposalOutcome);
    query.outcome = Some(OUTCOME_APPROVED_AMENDED.to_owned());

    let mut pending: Vec<(String, ProjectedDelta)> = Vec::new();
    for receipt in vault.receipts(query)? {
        // Either marker means this receipt has already been measured. The
        // uncaptured one is what stops a failed capture from being retried by
        // every later pass: its cause is the stored bytes, which do not heal.
        if receipt.fields.contains_key(FIELD_AMENDMENT_DELTA)
            || receipt
                .fields
                .contains_key(FIELD_AMENDMENT_DELTA_UNCAPTURED)
        {
            continue;
        }
        if let Some(projected) = identity_amendment_delta(vault, &receipt)? {
            pending.push((receipt.receipt_id, projected));
        }
    }
    if pending.is_empty() {
        return Ok(0);
    }

    vault.with_write_txn(|wtxn| {
        let mut written = 0;
        for (receipt_id, projected) in &pending {
            let wrote = match projected {
                ProjectedDelta::Captured(delta) => {
                    put_amendment_delta_in_txn(vault, wtxn, receipt_id, delta)?
                }
                ProjectedDelta::Uncaptured => put_amendment_row_in_txn(
                    vault,
                    wtxn,
                    receipt_id,
                    AMENDMENT_DELTA_UNCAPTURED_ROW,
                )?,
            };
            if wrote {
                written += 1;
            }
        }
        Ok(written)
    })
}

/// What the projection measured for a receipt whose amendment window has both
/// ends in hand.
enum ProjectedDelta {
    /// The Δ between the proposal and the body the decider approved.
    Captured(AmendmentDelta),
    /// The measurement failed. Recorded rather than dropped: a receipt saying
    /// its Δ is missing is worth more than one silently without, and the
    /// projection pass is resumable only because a visited row leaves a trace.
    Uncaptured,
}

/// The Δ between a resolved proposal's proposed op and the body the decider
/// approved, or `None` when this receipt does not carry a measurable pair.
fn identity_amendment_delta(
    vault: &Vault,
    receipt: &ReceiptRecord,
) -> Result<Option<ProjectedDelta>> {
    let Some(amended) = proposal_outcome_amended_body(receipt) else {
        return Ok(None);
    };
    let Some(proposal_hex) = receipt
        .trigger_ref
        .as_deref()
        .and_then(|trigger| trigger.strip_prefix(PROPOSAL_TRIGGER_PREFIX))
    else {
        return Ok(None);
    };
    let Ok(proposal_id) = EntityId::from_hex(proposal_hex) else {
        return Ok(None);
    };

    let rtxn = vault.store.env.read_txn()?;
    let Some(record) = vault.identity_topology_event_in_txn(&rtxn, &proposal_id)? else {
        return Ok(None);
    };
    drop(rtxn);

    let crate::identity_topology::IdentityTopologyAction::Apply(proposed_op) =
        record.action.to_fold_action()
    else {
        return Ok(None);
    };
    // Past this point BOTH ends of the window exist, so every remaining exit
    // is a measurement that failed, not a pair that was never there.
    //
    // The proposed side is re-encoded through the SAME door the amended body
    // rode (`encode_identity_op_amendment`), so the two trees are comparable
    // shapes rather than an event record against an op body.
    let Ok(proposed) = crate::identity_topology::encode_identity_op_amendment(&proposed_op) else {
        return Ok(Some(ProjectedDelta::Uncaptured));
    };
    Ok(Some(
        match capture_delta_best(&DeltaCaptureContext::from_bodies(&proposed, &amended)) {
            Ok(delta) => ProjectedDelta::Captured(delta),
            Err(_) => ProjectedDelta::Uncaptured,
        },
    ))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// House pattern (cf. `gate.rs`): the version is stamped from the manifest at
/// the measurement site, never written as a literal that outlives its bump.
fn engine_ver() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Shared with the reconstructed lane's line counts.
pub(super) fn u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests;
