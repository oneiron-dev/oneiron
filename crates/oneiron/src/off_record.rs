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
//! * **Defer-sync** — fenced entities and incident edges are held out of
//!   both window-packing paths until explicit promotion. The fence remains
//!   device-local; promoting one turn lifts only that turn's fence, so only
//!   that turn joins ordinary sync.
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
//!
//!   **MUST (caller discipline):** every retrieval run executed FOR an
//!   off-record session MUST be registered via
//!   [`Vault::note_off_record_context_receipt`] with the run id the
//!   pipeline returned (`run_with_telemetry`). The retrieval-telemetry
//!   write path has no session ref, so the engine CANNOT auto-register —
//!   one forgotten call permanently leaks the room's activated-memory ids
//!   in a durable retrieval-run row.
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
//!
//! # Known limitations (OFRC-2 scope)
//!
//! Ticketed follow-ups pending an owner design pass — deliberately named
//! here, not silently absent:
//!
//! * **Whole-vault export refuses while a session is live.** The export seam
//!   checks the durable session family before it writes an artifact, returning
//!   a typed error naming the open session rather than producing a bundle that
//!   could outlive close with fenced content.
//! * **Context-receipt registration is caller discipline.** See the MUST
//!   above — auto-registration needs session plumbing at the
//!   retrieval-telemetry seam (e.g. a session ref on `PipelineBuilder`)
//!   that does not exist today.

use std::{cell::Cell, collections::BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::deletion::DeleteReason;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::SessionLocalReceiptLog;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::store::{RetrievalRunId, Store};

/// `vault_meta` key prefix for off-record session records.
const OFF_RECORD_SESSION_KEY_PREFIX: &[u8] = b"offrecord_session:v0:";
/// `vault_meta` key prefix for per-entity fence rows (value = session ref).
const OFF_RECORD_FENCE_KEY_PREFIX: &[u8] = b"offrecord_fence:v0:";
/// `vault_meta` key prefix for inherited-fence sidecars. The key suffix is
/// the carrier id and the value is the sorted set of direct fenced root ids.
/// Unlike CRDT window state this row is node-local, so a carrier discovered
/// in one source window remains fenced when it appears in another window.
const OFF_RECORD_INHERITED_FENCE_KEY_PREFIX: &[u8] = b"offrecord_inherited_fence:v0:";
/// `vault_meta` key prefix for durable promote receipts (survive close).
const OFF_RECORD_PROMOTE_KEY_PREFIX: &[u8] = b"offrecord_promote:v0:";
/// Value replacing a tag-before-write fence after close. An empty value can
/// never be a live session ref (`vet_off_record_session_ref` rejects empty),
/// so it preserves the closed write door without retaining session metadata.
const OFF_RECORD_CLOSED_FENCE_VALUE: &[u8] = b"";

thread_local! {
    /// One-shot raw-delete capability held only while close synchronously
    /// invokes the ordinary deletion pipeline for this exact root/carrier.
    static OFF_RECORD_CLOSE_DELETE_ID: Cell<Option<EntityId>> = const { Cell::new(None) };
}

const OFF_RECORD_SESSION_RECORD_VERSION: u8 = 0;
const OFF_RECORD_PROMOTE_RECEIPT_VERSION: u8 = 0;

/// Longest accepted session ref, in bytes (session refs are caller-supplied
/// opaque ids; they become `vault_meta` key suffixes).
const OFF_RECORD_SESSION_REF_MAX_LEN: usize = 256;
/// Hard cap on fenced turns tracked by one session record.
const OFF_RECORD_MAX_FENCED_TURNS: usize = 65_536;
/// Hard cap on fresh executor-created conversation shells tracked for close.
const OFF_RECORD_MAX_CONVERSATION_SHELLS: usize = 65_536;
/// Hard cap on session-local context receipts tracked by one session record.
const OFF_RECORD_MAX_CONTEXT_RECEIPTS: usize = 65_536;
/// Hard cap on session-scoped code-run replay/raw-output rows.
const OFF_RECORD_MAX_CODE_RUN_ARTIFACTS: usize = 65_536;
/// Backstop for one inherited-fence graph walk. Cycles terminate through the
/// visited set; exceeding this bound with an unexplored carrier fails closed.
const OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES: usize = 65_536;
/// Close enumerates reverse inheritance edges in bounded pages. Unit tests
/// lower the effective page size so the page-boundary regression stays fast.
#[cfg(not(test))]
const OFF_RECORD_CLOSE_CARRIER_PAGE_SIZE: usize = 4_096;
#[cfg(test)]
const OFF_RECORD_CLOSE_CARRIER_PAGE_SIZE: usize = 4;

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
    /// Fresh CONVERSATION containers reserved by off-record executor
    /// witnesses. They carry a direct fence and are deleted at close unless
    /// promotion releases a turn that belongs to the container.
    #[serde(default)]
    pub conversation_shells: Vec<[u8; 16]>,
    /// Turns promoted out of the fence; close keeps them.
    pub promoted_turns: Vec<[u8; 16]>,
    /// Session-local context receipts (retrieval runs) deleted at close.
    pub context_receipt_runs: Vec<RetrievalRunId>,
    /// Exact `vault_meta` keys for session-scoped code-run replay and raw
    /// output rows. Every key is removed atomically with the session row.
    #[serde(default)]
    pub code_run_artifact_keys: Vec<Vec<u8>>,
    /// Set by the first close transaction. While `true`, every mutator
    /// (tag, promote, note-context-receipt, mode flip) rejects with
    /// [`Error::OffRecordSessionClosing`] — close's multi-transaction
    /// deletion pass must never race a record mutation (a stale snapshot
    /// could hard-delete a just-promoted, user-consented turn).
    #[serde(default)]
    pub closing: bool,
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
    /// Authenticated owner principal that explicitly approved the promotion.
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
    /// Sessionless closed-fence rows kept for turns that were MISSING at
    /// delete time (tag-before-write where the write had not landed). The
    /// retained marker rejects a late entity write without keeping session
    /// metadata. Includes both missing turns and missing reserved
    /// conversation shells.
    pub fence_rows_retained: usize,
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

fn off_record_inherited_fence_key(id: &EntityId) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(OFF_RECORD_INHERITED_FENCE_KEY_PREFIX.len() + id.as_bytes().len());
    key.extend_from_slice(OFF_RECORD_INHERITED_FENCE_KEY_PREFIX);
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

pub(crate) fn vet_off_record_session_ref(session_ref: &str) -> Result<()> {
    if session_ref.is_empty() || session_ref.len() > OFF_RECORD_SESSION_REF_MAX_LEN {
        return Err(Error::InvalidConfig(format!(
            "off-record session ref must be 1..={OFF_RECORD_SESSION_REF_MAX_LEN} bytes, got {}",
            session_ref.len()
        )));
    }
    Ok(())
}

pub(crate) fn direct_off_record_fence_active(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    const PREFIX_LEN: usize = OFF_RECORD_FENCE_KEY_PREFIX.len();
    let mut key = [0_u8; PREFIX_LEN + 16];
    key[..PREFIX_LEN].copy_from_slice(OFF_RECORD_FENCE_KEY_PREFIX);
    key[PREFIX_LEN..].copy_from_slice(id.as_bytes());
    Ok(store.vault_meta.get(rtxn, &key)?.is_some())
}

/// Cheap, uniform visibility probe for public entity/edge readers.
///
/// Direct roots carry `offrecord_fence:v0:<id>` and inherited MESSAGE /
/// SUMMARY carriers carry `offrecord_inherited_fence:v0:<id>`. Both are
/// point lookups in `vault_meta`; public reads never walk the entity graph.
pub(crate) fn off_record_visibility_hidden(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if direct_off_record_fence_active(store, rtxn, id)? {
        return Ok(true);
    }
    Ok(store
        .vault_meta
        .get(rtxn, &off_record_inherited_fence_key(id))?
        .is_some())
}

fn decode_inherited_off_record_fence_roots(bytes: &[u8]) -> Result<BTreeSet<EntityId>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(16) {
        return Err(Error::CorruptedIndex("off-record inherited fence row"));
    }
    let mut roots = BTreeSet::new();
    for bytes in bytes.chunks_exact(16) {
        let root = EntityId::from_bytes(
            bytes
                .try_into()
                .map_err(|_| Error::CorruptedIndex("off-record inherited fence row"))?,
        )
        .map_err(|_| Error::CorruptedIndex("off-record inherited fence row"))?;
        if !roots.insert(root) {
            return Err(Error::CorruptedIndex("off-record inherited fence row"));
        }
        if roots.len() > OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES {
            return Err(Error::CorruptedIndex(
                "off-record inherited fence roots exceed bound",
            ));
        }
    }
    Ok(roots)
}

fn encode_inherited_off_record_fence_roots(roots: &BTreeSet<EntityId>) -> Result<Vec<u8>> {
    if roots.is_empty() || roots.len() > OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES {
        return Err(Error::InvariantViolation(
            "off-record inherited fence roots must be non-empty and bounded",
        ));
    }
    let mut bytes = Vec::with_capacity(roots.len() * 16);
    for root in roots {
        bytes.extend_from_slice(root.as_bytes());
    }
    Ok(bytes)
}

pub(crate) fn inherited_off_record_fence_roots_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<BTreeSet<EntityId>> {
    let Some(bytes) = store
        .vault_meta
        .get(rtxn, &off_record_inherited_fence_key(id))?
    else {
        return Ok(BTreeSet::new());
    };
    decode_inherited_off_record_fence_roots(bytes)
}

/// Returns every durable inherited-fence carrier. Window scrubs include this
/// inventory even when the current CRDT doc no longer contains the body or
/// inheritance edge, making retries repair the legacy post-commit/pre-purge
/// crash state.
pub(crate) fn inherited_off_record_fence_carriers(store: &Store) -> Result<BTreeSet<EntityId>> {
    let rtxn = store.env.read_txn()?;
    let mut carriers = BTreeSet::new();
    for row in store
        .vault_meta
        .prefix_iter(&rtxn, OFF_RECORD_INHERITED_FENCE_KEY_PREFIX)?
    {
        let (key, value) = row?;
        let suffix = key
            .strip_prefix(OFF_RECORD_INHERITED_FENCE_KEY_PREFIX)
            .ok_or(Error::CorruptedIndex("off-record inherited fence key"))?;
        let carrier = EntityId::from_bytes(
            suffix
                .try_into()
                .map_err(|_| Error::CorruptedIndex("off-record inherited fence key"))?,
        )
        .map_err(|_| Error::CorruptedIndex("off-record inherited fence key"))?;
        decode_inherited_off_record_fence_roots(value)?;
        if !carriers.insert(carrier) || carriers.len() > OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES {
            return Err(Error::CorruptedIndex(
                "off-record inherited fence carriers exceed bound",
            ));
        }
    }
    Ok(carriers)
}

pub(crate) fn put_inherited_off_record_fence_roots_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    carrier: &EntityId,
    roots: &BTreeSet<EntityId>,
) -> Result<()> {
    if roots.is_empty() {
        return Err(Error::InvariantViolation(
            "cannot persist an empty inherited off-record fence",
        ));
    }
    let key = off_record_inherited_fence_key(carrier);
    let mut merged = store
        .vault_meta
        .get(&*wtxn, &key)?
        .map(decode_inherited_off_record_fence_roots)
        .transpose()?
        .unwrap_or_default();
    merged.extend(roots.iter().copied());
    let mut live_roots = BTreeSet::new();
    for root in merged {
        if direct_off_record_fence_active(store, &*wtxn, &root)? {
            live_roots.insert(root);
        }
    }
    if live_roots.is_empty() {
        store.vault_meta.delete(wtxn, &key)?;
    } else {
        store.vault_meta.put(
            wtxn,
            &key,
            &encode_inherited_off_record_fence_roots(&live_roots)?,
        )?;
    }
    Ok(())
}

/// Removes one promoted/deleted direct root from every inherited-fence row.
/// This runs in the same LMDB transaction that lifts the direct fence, so a
/// carrier can never observe the root as released while its durable sidecar
/// still names it (or vice versa).
fn remove_inherited_off_record_fence_root_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    root: &EntityId,
) -> Result<()> {
    let mut updates = Vec::new();
    for row in store
        .vault_meta
        .prefix_iter(&*wtxn, OFF_RECORD_INHERITED_FENCE_KEY_PREFIX)?
    {
        let (key, value) = row?;
        let mut roots = decode_inherited_off_record_fence_roots(value)?;
        if roots.remove(root) {
            updates.push((key.to_vec(), roots));
        }
        if updates.len() > OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES {
            return Err(Error::CorruptedIndex(
                "off-record inherited fence cleanup exceeds bound",
            ));
        }
    }
    for (key, roots) in updates {
        if roots.is_empty() {
            store.vault_meta.delete(wtxn, &key)?;
        } else {
            store.vault_meta.put(
                wtxn,
                &key,
                &encode_inherited_off_record_fence_roots(&roots)?,
            )?;
        }
    }
    Ok(())
}

fn off_record_fence_roots_impl(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    include_durable_inheritance: bool,
) -> Result<BTreeSet<EntityId>> {
    let mut roots = BTreeSet::new();
    let mut visited = BTreeSet::from([*id]);
    let mut pending = vec![*id];
    while let Some(current) = pending.pop() {
        if direct_off_record_fence_active(store, rtxn, &current)? {
            roots.insert(current);
        }
        if include_durable_inheritance {
            roots.extend(inherited_off_record_fence_roots_in_txn(
                store, rtxn, &current,
            )?);
        }
        if roots.len() > OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES {
            return Err(Error::CorruptedIndex(
                "off-record inherited fence roots exceed bound",
            ));
        }

        let Some(raw) = store.entities.get(rtxn, current.as_bytes())? else {
            continue;
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let inherited_edge = match header.entity_type {
            ENTITY_TYPE_MESSAGE => EdgeKind::PartOf,
            ENTITY_TYPE_SUMMARY => EdgeKind::DerivedFrom,
            _ => continue,
        };
        let prefix = crate::vault::edge_kind_prefix(&current, inherited_edge);
        for row in store.edges_out.prefix_iter(rtxn, &prefix)? {
            let (key, value) = row?;
            let parent = crate::vault::parse_edge_record(key, value)?.target;
            if visited.contains(&parent) {
                continue;
            }
            if visited.len() >= OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES {
                return Err(Error::CorruptedIndex(
                    "off-record fence inheritance graph exceeds bound",
                ));
            }
            visited.insert(parent);
            pending.push(parent);
        }
    }
    Ok(roots)
}

pub(crate) fn off_record_fence_roots(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<BTreeSet<EntityId>> {
    off_record_fence_roots_impl(store, rtxn, id, true)
}

/// Graph-only probe used by orphan purge. Durable sidecars are deliberately
/// excluded: the purge transaction writes the sidecar before deleting the
/// orphan, and treating that new row as local graph truth would skip the body.
pub(crate) fn off_record_graph_fence_active(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(!off_record_fence_roots_impl(store, rtxn, id, false)?.is_empty())
}

/// THE FENCE probe consulted by every retrieval/extraction candidate filter.
///
/// Fence-establishing batches and tag-time reverse closure persist inherited
/// sidecars, while window scrubs backfill cross-window carriers. Visibility is
/// therefore exactly the uniform two-point-lookup rule used by edge readers:
/// a direct fence row OR an inherited sidecar row hides the entity.
pub(crate) fn off_record_fence_active(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    off_record_visibility_hidden(store, rtxn, id)
}

/// Persists `root` on every already-materialized MESSAGE/SUMMARY descendant.
///
/// Tagging an existing TURN must switch public visibility atomically with the
/// direct fence row. The reverse walk is mutation-time work; readers retain
/// the two-point-lookup fast path. Rows are collected before any sidecar write
/// so no LMDB iterator remains live while `vault_meta` is mutated.
fn persist_existing_inherited_carriers_for_root_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    root: &EntityId,
) -> Result<()> {
    let mut visited = BTreeSet::from([*root]);
    let mut pending = vec![*root];
    let mut carriers = Vec::new();
    while let Some(parent) = pending.pop() {
        for (kind, entity_type) in [
            (EdgeKind::PartOf, ENTITY_TYPE_MESSAGE),
            (EdgeKind::DerivedFrom, ENTITY_TYPE_SUMMARY),
        ] {
            let prefix = crate::vault::edge_kind_prefix(&parent, kind);
            for row in store.edges_in.prefix_iter(&*wtxn, &prefix)? {
                let (key, value) = row?;
                let child = crate::vault::parse_edge_record(key, value)?.target;
                if visited.contains(&child) {
                    continue;
                }
                let raw = store.entities.get(&*wtxn, child.as_bytes())?;
                if let Some(raw) = raw {
                    let header = EntityMetadataHeader::parse(raw)
                        .ok_or(Error::CorruptedIndex("entity header"))?;
                    if header.entity_type != entity_type {
                        continue;
                    }
                }
                if visited.len() >= OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES {
                    return Err(Error::CorruptedIndex(
                        "off-record fence inheritance graph exceeds bound",
                    ));
                }
                // An inheritance edge may predate its source entity. Persist
                // the pending sidecar now so a later MESSAGE/SUMMARY put is
                // hidden immediately, and keep walking raw inbound edges so
                // an entirely edge-first descendant chain is covered too.
                visited.insert(child);
                pending.push(child);
                carriers.push(child);
            }
        }
    }

    let roots = BTreeSet::from([*root]);
    for carrier in carriers {
        put_inherited_off_record_fence_roots_in_txn(store, wtxn, &carrier, &roots)?;
    }
    Ok(())
}

/// Snapshots every carrier that inherits `root`'s fence. The closing flag has
/// already frozen new inheritance edges, so this closure cannot grow while the
/// multi-transaction PolicyDelete cascade runs. Discovery order is parent to
/// child; callers delete it in reverse so descendants never become visible
/// merely because deleting an ancestor removed their inheritance edge.
fn inherited_off_record_carriers_for_close(
    vault: &Vault,
    root: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut visited = BTreeSet::from([*root]);
    let mut pending = vec![*root];
    let mut carriers = Vec::new();
    while let Some(parent) = pending.pop() {
        for (kind, entity_type) in [
            (EdgeKind::PartOf, ENTITY_TYPE_MESSAGE),
            (EdgeKind::DerivedFrom, ENTITY_TYPE_SUMMARY),
        ] {
            let mut after = None;
            loop {
                let page = vault.sources_page_unfiltered(
                    &parent,
                    kind,
                    Some(entity_type),
                    after.as_ref(),
                    OFF_RECORD_CLOSE_CARRIER_PAGE_SIZE,
                )?;
                let page_len = page.len();
                for child in page {
                    after = Some(child);
                    if visited.contains(&child) {
                        continue;
                    }
                    if visited.len() >= OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES {
                        return Err(Error::CorruptedIndex(
                            "off-record close inheritance graph exceeds bound",
                        ));
                    }
                    visited.insert(child);
                    pending.push(child);
                    carriers.push(child);
                }
                if page_len < OFF_RECORD_CLOSE_CARRIER_PAGE_SIZE {
                    break;
                }
            }
        }
    }
    Ok(carriers)
}

/// Finds session-owned fresh conversation shells reached by MESSAGE rows in one
/// materialized turn. Promotion uses the raw graph inside its write
/// transaction so releasing the turn, carriers, and container fence is
/// atomic and cannot race close.
fn conversation_shells_for_turn_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    turn_id: &EntityId,
    registered_shells: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    if registered_shells.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut messages = BTreeSet::new();
    let part_of_prefix = crate::vault::edge_kind_prefix(turn_id, EdgeKind::PartOf);
    for row in store.edges_in.prefix_iter(rtxn, &part_of_prefix)? {
        let (key, value) = row?;
        let message = crate::vault::parse_edge_record(key, value)?.target;
        if messages.len() >= OFF_RECORD_MAX_FENCE_INHERITANCE_ENTITIES {
            return Err(Error::CorruptedIndex(
                "off-record promoted turn message set exceeds bound",
            ));
        }
        messages.insert(message);
    }

    let mut shells = BTreeSet::new();
    for message in messages {
        let belongs_to_prefix = crate::vault::edge_kind_prefix(&message, EdgeKind::BelongsTo);
        for row in store.edges_out.prefix_iter(rtxn, &belongs_to_prefix)? {
            let (key, value) = row?;
            let conversation = crate::vault::parse_edge_record(key, value)?.target;
            if registered_shells.contains(&conversation) {
                shells.insert(conversation);
            }
        }
    }
    Ok(shells)
}

/// Returns whether the vault has any fence rows at all. Retrieval channels use
/// this once-per-query probe to preserve their fence-free fast path before
/// checking returned candidates individually.
pub(crate) fn off_record_fences_present(store: &Store, rtxn: &RoTxn<'_>) -> Result<bool> {
    if store
        .vault_meta
        .prefix_iter(rtxn, OFF_RECORD_FENCE_KEY_PREFIX)?
        .next()
        .transpose()?
        .is_some()
    {
        return Ok(true);
    }
    Ok(store
        .vault_meta
        .prefix_iter(rtxn, OFF_RECORD_INHERITED_FENCE_KEY_PREFIX)?
        .next()
        .transpose()?
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

/// Returns the first durable off-record session ref, if any. Session rows are
/// the source of truth for the export gate: a session remains open until its
/// close transaction removes the row, including while the close `closing`
/// flag is stamped. LMDB's key ordering makes the result deterministic when a
/// caller has (incorrectly) left more than one session open.
fn first_open_off_record_session_in_txn(store: &Store, rtxn: &RoTxn<'_>) -> Result<Option<String>> {
    if let Some(row) = store
        .vault_meta
        .prefix_iter(rtxn, OFF_RECORD_SESSION_KEY_PREFIX)?
        .next()
    {
        let (key, bytes) = row?;
        let suffix = key
            .strip_prefix(OFF_RECORD_SESSION_KEY_PREFIX)
            .ok_or(Error::CorruptedIndex("off-record session key"))?;
        let session_ref = std::str::from_utf8(suffix)
            .map_err(|_| Error::CorruptedIndex("off-record session key"))?;
        let record = decode_off_record_session(bytes)?;
        if record.session_ref != session_ref {
            return Err(Error::CorruptedIndex("off-record session record"));
        }
        return Ok(Some(session_ref.to_owned()));
    }
    Ok(None)
}

/// Fail-closed entity materialization door for off-record fences.
///
/// Every ordinary, typed, claim-candidate, and replicated entity put reaches
/// this probe through `batch::apply_put` before it can stage entity or index
/// bytes. A live fence permits the first local tag-before-write materialization;
/// a materialized root reaches this strict door only for a non-exact retry and
/// is rejected. Replicated writes and closing, closed, malformed, or mismatched
/// fences also reject with a typed error. The retained post-close marker is
/// sessionless, so this guard never needs to surface or preserve an evaporated
/// session ref.
pub(crate) fn guard_off_record_entity_put(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    replicated: bool,
) -> Result<()> {
    guard_off_record_entity_put_preflight(store, wtxn, id, replicated)?;
    if direct_off_record_fence_active(store, wtxn, id)?
        && store.entities.get(wtxn, id.as_bytes())?.is_some()
    {
        return Err(Error::OffRecordFencedTurnWriteRejected {
            turn_ref: id.to_hex(),
        });
    }
    Ok(())
}

/// Early gate-receipt preflight for entity puts.
///
/// The caller-controlled entity bytes are not encoded at this phase, so a
/// live direct fence is validated without deciding whether a materialized
/// root is an exact retry. `batch::apply_put` performs that byte comparison
/// and calls the strict materialization door above for every non-retry.
pub(crate) fn guard_off_record_entity_put_preflight(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    replicated: bool,
) -> Result<()> {
    guard_direct_off_record_entity_write(store, wtxn, id, replicated)?;
    if inherited_off_record_fence_roots_in_txn(store, wtxn, id)?.is_empty() {
        return Ok(());
    }
    // A pending sidecar can predate its carrier (tag-time backfill covers
    // edge-first children). The carrier's first LOCAL put materializes it
    // hidden under that sidecar; replicated puts and re-puts of an already
    // materialized carrier keep rejecting.
    if !replicated && store.entities.get(wtxn, id.as_bytes())?.is_none() {
        return Ok(());
    }
    Err(Error::OffRecordFencedTurnWriteRejected {
        turn_ref: id.to_hex(),
    })
}

/// Direct-fence state validation shared by entity and edge writers.
///
/// Edges need this narrower probe because the edge preflight separately
/// admits byte-identical retries and the one fence-establishing PartOf write.
pub(crate) fn guard_direct_off_record_entity_write(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    replicated: bool,
) -> Result<()> {
    let fence_key = off_record_fence_key(id);
    let Some(fence_value) = store.vault_meta.get(wtxn, &fence_key)? else {
        return Ok(());
    };

    let rejected = || Error::OffRecordFencedTurnWriteRejected {
        turn_ref: id.to_hex(),
    };
    let Some(session_ref) = std::str::from_utf8(fence_value)
        .ok()
        .filter(|session_ref| !session_ref.is_empty())
    else {
        return Err(rejected());
    };
    let Some(record) = session_record_in_txn(store, wtxn, session_ref)? else {
        return Err(rejected());
    };
    if replicated
        || record.closing
        || !(record.fenced_turns.contains(id.as_bytes())
            || record.conversation_shells.contains(id.as_bytes()))
    {
        return Err(rejected());
    }
    Ok(())
}

/// Rejects ordinary deletion of any direct or inherited fenced entity.
/// Close temporarily authorizes one exact id so it can keep using the full
/// PolicyDelete/audit pipeline without opening a general raw deletion door.
pub(crate) fn guard_off_record_entity_delete(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if !off_record_visibility_hidden(store, rtxn, id)? {
        return Ok(());
    }
    let close_authorized = OFF_RECORD_CLOSE_DELETE_ID.with(|slot| slot.get() == Some(*id));
    if close_authorized {
        return Ok(());
    }
    // Crash-retry compatibility: once close has durably frozen every root
    // named by this row, a resumed PolicyDelete may re-enter through the
    // ordinary deletion pipeline before the in-memory exact-id capability is
    // re-established. No live/mutable session receives this fallback.
    if off_record_delete_roots_are_closing(store, rtxn, id)? {
        return Ok(());
    }
    Err(Error::OffRecordFencedTurnWriteRejected {
        turn_ref: id.to_hex(),
    })
}

/// Lower deindex guard. A closing-state fallback must also prove that the
/// ordinary deletion pipeline staged a PolicyDelete marker; this prevents a
/// batch delete (which has no marker) or another hard-delete reason from
/// borrowing close's crash-retry allowance.
pub(crate) fn guard_off_record_entity_deindex(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if !off_record_visibility_hidden(store, rtxn, id)? {
        return Ok(());
    }
    if OFF_RECORD_CLOSE_DELETE_ID.with(|slot| slot.get() == Some(*id)) {
        return Ok(());
    }
    let marker_key = crate::deletion::local_hard_delete_key(id);
    let policy_delete_staged = store
        .sync_state
        .get(rtxn, &marker_key)?
        .is_some_and(|value| {
            value.first().copied()
                == Some(crate::deletion::TombstoneReason::PolicyDelete.wire_byte())
        });
    if policy_delete_staged && off_record_delete_roots_are_closing(store, rtxn, id)? {
        return Ok(());
    }
    Err(Error::OffRecordFencedTurnWriteRejected {
        turn_ref: id.to_hex(),
    })
}

fn off_record_delete_roots_are_closing(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let mut roots = inherited_off_record_fence_roots_in_txn(store, rtxn, id)?;
    if direct_off_record_fence_active(store, rtxn, id)? {
        roots.insert(*id);
    }
    Ok(!roots.is_empty()
        && roots.iter().all(|root| {
            let Ok(Some(value)) = store.vault_meta.get(rtxn, &off_record_fence_key(root)) else {
                return false;
            };
            let Ok(session_ref) = std::str::from_utf8(value) else {
                return false;
            };
            session_record_in_txn(store, rtxn, session_ref)
                .ok()
                .flatten()
                .is_some_and(|record| record.closing)
        }))
}

fn with_off_record_close_delete<T>(id: &EntityId, delete: impl FnOnce() -> Result<T>) -> Result<T> {
    struct RestoreCloseDeleteId(Option<EntityId>);

    impl Drop for RestoreCloseDeleteId {
        fn drop(&mut self) {
            OFF_RECORD_CLOSE_DELETE_ID.with(|slot| slot.set(self.0));
        }
    }

    let previous = OFF_RECORD_CLOSE_DELETE_ID.with(|slot| slot.replace(Some(*id)));
    let _restore = RestoreCloseDeleteId(previous);
    delete()
}

/// Loads the record for a mutator: errors when the session is unknown, and
/// rejects typed once close has stamped the closing flag — no record
/// mutation may interleave with close's multi-transaction deletion pass.
fn mutable_session_record_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    session_ref: &str,
) -> Result<OffRecordSessionRecord> {
    let record = session_record_in_txn(store, rtxn, session_ref)?.ok_or_else(|| {
        Error::OffRecordSessionNotFound {
            session_ref: session_ref.to_owned(),
        }
    })?;
    if record.closing {
        return Err(Error::OffRecordSessionClosing {
            session_ref: session_ref.to_owned(),
        });
    }
    Ok(record)
}

/// Registers an exact code-run artifact key in the same transaction that
/// writes it. Only the two pinned code-run key families are accepted, so a
/// malformed internal caller cannot turn close into an arbitrary metadata
/// deletion primitive.
pub(crate) fn register_code_run_artifact_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    session_ref: &str,
    artifact_key: &[u8],
) -> Result<()> {
    vet_off_record_session_ref(session_ref)?;
    if !(artifact_key.starts_with(b"code_run:replay:v1:")
        || artifact_key.starts_with(b"code_run:raw_output:v1:"))
    {
        return Err(Error::InvariantViolation(
            "off-record code-run artifact key has unknown family",
        ));
    }
    let mut record = mutable_session_record_in_txn(store, wtxn, session_ref)?;
    if record.mode != OffRecordMode::OffRecord {
        return Err(Error::InvariantViolation(
            "off-record code-run artifact requires the session to be in off-record mode",
        ));
    }
    if record
        .code_run_artifact_keys
        .iter()
        .any(|key| key.as_slice() == artifact_key)
    {
        return Ok(());
    }
    if record.code_run_artifact_keys.len() >= OFF_RECORD_MAX_CODE_RUN_ARTIFACTS {
        return Err(Error::InvariantViolation(
            "off-record session code-run artifact capacity exceeded",
        ));
    }
    record.code_run_artifact_keys.push(artifact_key.to_vec());
    store.vault_meta.put(
        wtxn,
        &off_record_session_key(session_ref),
        &encode_off_record_session(&record)?,
    )?;
    Ok(())
}

impl Vault {
    /// Refuses whole-vault export while any off-record session row remains
    /// live. The row is retained through the close `closing` phase, so an
    /// export cannot race a partially completed delete-at-close pass.
    pub(crate) fn ensure_no_open_off_record_session(&self) -> Result<()> {
        let rtxn = self.store.env.read_txn()?;
        if let Some(session_ref) = first_open_off_record_session_in_txn(&self.store, &rtxn)? {
            return Err(Error::OffRecordExportRefused { session_ref });
        }
        Ok(())
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
        vet_off_record_session_ref(session_ref)?;
        let record = OffRecordSessionRecord {
            version: OFF_RECORD_SESSION_RECORD_VERSION,
            session_ref: session_ref.to_owned(),
            mode: OffRecordMode::OffRecord,
            backend,
            entered_at: crate::unix_seconds_now(),
            fenced_turns: Vec::new(),
            conversation_shells: Vec::new(),
            promoted_turns: Vec::new(),
            context_receipt_runs: Vec::new(),
            code_run_artifact_keys: Vec::new(),
            closing: false,
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

    /// Reads the off-record session record for `session_ref`, if any. A ref
    /// that fails the session-ref length bound cannot name a session (enter
    /// enforces the same bound), so it reads as `None` without building a
    /// key — arbitrary caller-supplied refs never drive allocation size.
    pub fn off_record_session(&self, session_ref: &str) -> Result<Option<OffRecordSessionRecord>> {
        if vet_off_record_session_ref(session_ref).is_err() {
            return Ok(None);
        }
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
        vet_off_record_session_ref(session_ref)?;
        self.with_write_txn(|wtxn| {
            let mut record = mutable_session_record_in_txn(&self.store, wtxn, session_ref)?;
            record.mode = mode;
            self.store.vault_meta.put(
                wtxn,
                &off_record_session_key(session_ref),
                &encode_off_record_session(&record)?,
            )?;
            Ok(record)
        })
    }

    /// Reserves a fresh executor witness CONVERSATION for close-time sweep.
    ///
    /// The reservation and direct fence commit before the witness batch. If
    /// the id already materializes, it is an ordinary existing conversation
    /// and needs no registration. A missing id becomes a session-owned shell:
    /// its local tag-before-write put remains legal, public readers hide it,
    /// and close either deletes it or retains a closed fence if witness never
    /// lands. Returns whether this session owns the fresh shell.
    pub(crate) fn register_off_record_conversation_shell(
        &self,
        session_ref: &str,
        conversation_id: &EntityId,
    ) -> Result<bool> {
        vet_off_record_session_ref(session_ref)?;
        self.with_write_txn(|wtxn| {
            let mut record = mutable_session_record_in_txn(&self.store, wtxn, session_ref)?;
            if record.mode != OffRecordMode::OffRecord {
                return Err(Error::InvariantViolation(
                    "off-record conversation shell requires the session to be in off-record mode",
                ));
            }
            if self
                .store
                .entities
                .get(&*wtxn, conversation_id.as_bytes())?
                .is_some()
            {
                return Ok(false);
            }
            if record
                .conversation_shells
                .contains(conversation_id.as_bytes())
            {
                return Ok(true);
            }
            if record.fenced_turns.contains(conversation_id.as_bytes()) {
                return Err(Error::InvariantViolation(
                    "off-record conversation shell collides with a fenced turn",
                ));
            }
            let fence_key = off_record_fence_key(conversation_id);
            if self.store.vault_meta.get(&*wtxn, &fence_key)?.is_some() {
                return Err(Error::InvariantViolation(
                    "off-record conversation shell id is already fenced",
                ));
            }
            if record.conversation_shells.len() >= OFF_RECORD_MAX_CONVERSATION_SHELLS {
                return Err(Error::InvariantViolation(
                    "off-record session conversation-shell capacity exceeded",
                ));
            }
            record.conversation_shells.push(*conversation_id.as_bytes());
            self.store
                .vault_meta
                .put(wtxn, &fence_key, session_ref.as_bytes())?;
            self.store.vault_meta.put(
                wtxn,
                &off_record_session_key(session_ref),
                &encode_off_record_session(&record)?,
            )?;
            #[cfg(feature = "sync")]
            crate::sync::queue::scrub_outbox_for_off_record_fence_in_txn(self, wtxn)?;
            Ok(true)
        })
    }

    /// Tags one turn off-record: writes the fence row and adds the turn to
    /// the session's delete-at-close set. Requires the session to currently
    /// be in [`OffRecordMode::OffRecord`] (turns written after a flip back
    /// on-record are ordinary turns). The turn entity may not exist yet —
    /// tagging BEFORE the turn write closes the race against a concurrent
    /// extraction pass. Idempotent for a turn already fenced by this session.
    pub fn tag_turn_off_record(&self, session_ref: &str, turn_id: &EntityId) -> Result<()> {
        vet_off_record_session_ref(session_ref)?;
        self.with_write_txn(|wtxn| {
            let mut record = mutable_session_record_in_txn(&self.store, wtxn, session_ref)?;
            if record.mode != OffRecordMode::OffRecord {
                return Err(Error::InvariantViolation(
                    "off-record tag requires the session to be in off-record mode",
                ));
            }
            // A promoted turn's durable receipt pins its survival past
            // close; silently re-fencing it would let close delete it.
            if record.promoted_turns.contains(turn_id.as_bytes()) {
                return Err(Error::InvariantViolation(
                    "off-record tag targeted a promoted turn",
                ));
            }
            // Fail early on entity kinds the close-path PolicyDelete would
            // refuse anyway (delete-protected engine records).
            if let Some(raw) = self.store.entities.get(wtxn, turn_id.as_bytes())?
                && let Some(&entity_type) = raw.first()
                && crate::deletion::is_delete_protected_engine_record(entity_type)
            {
                return Err(Error::MaintenanceKindNotWritable(entity_type));
            }
            let fence_key = off_record_fence_key(turn_id);
            if let Some(existing) = self.store.vault_meta.get(wtxn, &fence_key)? {
                if existing == session_ref.as_bytes() {
                    // Repair legacy/pre-sidecar fences and any interrupted
                    // migration idempotently. Public readers no longer walk
                    // the graph, so an existing direct row is not sufficient
                    // unless every already-materialized descendant also has
                    // its durable inherited-fence sidecar.
                    persist_existing_inherited_carriers_for_root_in_txn(
                        &self.store,
                        wtxn,
                        turn_id,
                    )?;
                    #[cfg(feature = "sync")]
                    crate::sync::queue::scrub_outbox_for_off_record_fence_in_txn(self, wtxn)?;
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
            persist_existing_inherited_carriers_for_root_in_txn(&self.store, wtxn, turn_id)?;
            self.store.vault_meta.put(
                wtxn,
                &off_record_session_key(session_ref),
                &encode_off_record_session(&record)?,
            )?;
            #[cfg(feature = "sync")]
            crate::sync::queue::scrub_outbox_for_off_record_fence_in_txn(self, wtxn)?;
            Ok(())
        })?;

        // The fence is durable before touching the CRDT. If this turn was
        // already present in a registry-owned window, scrub its body and
        // incident edges now instead of waiting for a later packing pass.
        // Export paths also run the same scrub as a fail-closed backstop; a
        // refresh failure therefore must not turn the committed tag into an
        // ambiguous error response.
        #[cfg(feature = "sync")]
        if let Err(error) = self.scrub_tagged_turn_in_live_window(turn_id) {
            tracing::warn!(
                turn = %turn_id.to_hex(),
                error = %error,
                "off-record fence committed but live-window carrier scrub deferred to export"
            );
        }

        Ok(())
    }

    /// Scrubs a newly fenced turn from every registry-owned live window.
    /// Incident edges live in their source entity's month, which can differ
    /// from the fenced target's month. This never faults a closed window into
    /// memory; persistence/VV export performs the same whole-doc backstop.
    #[cfg(feature = "sync")]
    fn scrub_tagged_turn_in_live_window(&self, _turn_id: &EntityId) -> Result<()> {
        use crate::sync::window::scrub_off_record_fenced_carriers;

        for window in self.live_windows() {
            scrub_off_record_fenced_carriers(self, &window.key, &window.doc)?;
        }
        Ok(())
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
        vet_off_record_session_ref(session_ref)?;
        self.with_write_txn(|wtxn| {
            let mut record = mutable_session_record_in_txn(&self.store, wtxn, session_ref)?;
            // Mirrors the tag mode-check: after a flip back on-record the
            // session's retrieval runs belong to on-record turns whose
            // receipts must persist — registering them for delete-at-close
            // would erase the audit trail of surviving emits.
            if record.mode != OffRecordMode::OffRecord {
                return Err(Error::InvariantViolation(
                    "off-record context receipt requires the session to be in off-record mode",
                ));
            }
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

    /// Promotes exactly ONE fenced turn into witness after authenticating the
    /// explicit consent actor against the authority layer's vault-owner ref.
    /// The owner ref is caller-supplied because `Vault` deliberately carries
    /// no ad-hoc principal field; the server/runtime must resolve it from its
    /// existing `VaultIdentity` authority source. Authentication happens
    /// before the write transaction begins. Fence removal, session mutation,
    /// and the durable receipt then commit atomically.
    pub fn promote_off_record_turn(
        &self,
        session_ref: &str,
        turn_id: &EntityId,
        owner_ref: &str,
        actor: &crate::genui::ConsentActorIdentity,
    ) -> Result<OffRecordPromoteReceipt> {
        vet_off_record_session_ref(session_ref)?;
        if !actor.authenticates_principal(owner_ref) {
            return Err(Error::InvariantViolation(
                "off-record promotion actor does not authenticate the vault owner",
            ));
        }
        let initiator = actor.actor_ref().to_owned();
        let receipt = self.with_write_txn(|wtxn| {
            let mut record = mutable_session_record_in_txn(&self.store, wtxn, session_ref)?;
            let position = record
                .fenced_turns
                .iter()
                .position(|bytes| bytes == turn_id.as_bytes())
                .ok_or_else(|| Error::OffRecordTurnNotFenced {
                    session_ref: session_ref.to_owned(),
                    turn_ref: turn_id.to_hex(),
                })?;
            let raw_turn = self.store.entities.get(&*wtxn, turn_id.as_bytes())?.ok_or(
                Error::InvariantViolation("off-record promotion requires a materialized TURN body"),
            )?;
            let turn_header = EntityMetadataHeader::parse(raw_turn)
                .ok_or(Error::CorruptedIndex("entity header"))?;
            if turn_header.entity_type != ENTITY_TYPE_TURN {
                return Err(Error::InvariantViolation(
                    "off-record promotion requires a materialized TURN body",
                ));
            }
            let registered_shells = record
                .conversation_shells
                .iter()
                .copied()
                .map(EntityId::from_bytes)
                .collect::<Result<BTreeSet<_>>>()?;
            let released_shells = conversation_shells_for_turn_in_txn(
                &self.store,
                &*wtxn,
                turn_id,
                &registered_shells,
            )?;
            record.fenced_turns.remove(position);
            record.conversation_shells.retain(|bytes| {
                !released_shells
                    .iter()
                    .any(|shell| shell.as_bytes() == bytes)
            });
            record.promoted_turns.push(*turn_id.as_bytes());
            let receipt = OffRecordPromoteReceipt {
                version: OFF_RECORD_PROMOTE_RECEIPT_VERSION,
                session_ref: session_ref.to_owned(),
                turn: *turn_id.as_bytes(),
                promoted_at: crate::unix_seconds_now(),
                initiator: initiator.clone(),
            };
            self.store
                .vault_meta
                .delete(wtxn, &off_record_fence_key(turn_id))?;
            for shell in &released_shells {
                self.store
                    .vault_meta
                    .delete(wtxn, &off_record_fence_key(shell))?;
            }
            remove_inherited_off_record_fence_root_in_txn(&self.store, wtxn, turn_id)?;
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
        })?;

        // A window that was already open deferred this turn's `pm:` marker
        // while its fence was active. Refresh that registry-owned doc after
        // the durable fence lift so the explicit promotion is visible to sync
        // immediately, rather than only after the window is unloaded and
        // opened again. The receipt/fence transaction is authoritative and
        // already committed here; a refresh failure leaves the `pm:` marker
        // durable for normal open-time recovery, so it must not turn a
        // completed user promotion into an ambiguous error response.
        #[cfg(feature = "sync")]
        if let Err(error) = self.refresh_promoted_turn_in_live_window(turn_id) {
            tracing::warn!(
                turn = %turn_id.to_hex(),
                error = %error,
                "off-record promotion committed but live-window sync refresh deferred to recovery"
            );
        }

        Ok(receipt)
    }

    /// Catches a promoted turn up in its already-loaded sync window, if any.
    ///
    /// The live window is a registry lookup only: promotion must never fault
    /// an older month into memory. `pm:` replay comes before reverse
    /// re-materialization, matching the pinned open-time recovery order.
    #[cfg(feature = "sync")]
    fn refresh_promoted_turn_in_live_window(&self, turn_id: &EntityId) -> Result<()> {
        use crate::sync::window::{replay_pending_mirrors, reverse_rematerialize};

        // The promoted body lives in its learned-at window, but incident
        // edges are packed by SOURCE window. Refresh every window that is
        // already live so a cross-month source edge appears immediately;
        // closed windows remain untouched and recover through normal open.
        for window in self.live_windows() {
            let replayed = replay_pending_mirrors(self, &window.doc, &window.key)?;
            let mirrored = reverse_rematerialize(self, &window.doc, &window.key)?;
            tracing::debug!(
                turn = %turn_id.to_hex(),
                window = %window.key,
                replayed,
                mirrored,
                "off-record promotion refreshed live sync window"
            );
        }
        Ok(())
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
    /// Every still-fenced turn is deleted through the pinned ARCH-0038
    /// contract ([`DeleteReason::PolicyDelete`]: CRDT tombstone first,
    /// active-store hard purge, opaque REDACTION_AUDIT receipt,
    /// historical-carrier sweep — the receipts are deletion provenance and
    /// persist as floor receipts). Session-local receipts follow the
    /// transcript: the durable retrieval-run context receipts are deleted,
    /// and the session's [`SessionLocalReceiptLog`] is consumed here — the
    /// one close path — so its emit-adjacent receipts drop with the room.
    /// Promoted turns and their promote receipts are kept.
    ///
    /// Concurrency contract: the FIRST transaction stamps `closing` on the
    /// record, after which every mutator rejects with
    /// [`Error::OffRecordSessionClosing`] — the multi-transaction deletion
    /// pass can never race a tag or promote (a stale snapshot must not
    /// hard-delete a just-promoted, user-consented turn). The FINAL
    /// transaction re-reads the record and fails closed on drift instead of
    /// trusting the snapshot. Fence rows for turns that were MISSING at
    /// delete time become sessionless closed-fence markers: a tag-before-write
    /// turn whose write lands after close is rejected at the entity write
    /// door instead of silently rejoining retrieval. Fence rows for deleted
    /// turns and the session record are removed LAST, so a close interrupted
    /// mid-way can simply be called again (mint a fresh empty log via
    /// [`Vault::off_record_receipt_log`] to retry).
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
        // Txn 1: stamp the closing flag. From here on the record is frozen
        // (mutators reject), so the snapshot below cannot go stale. A retry
        // of an interrupted close re-enters here idempotently.
        let record =
            self.with_write_txn(|wtxn| {
                let mut record = session_record_in_txn(&self.store, wtxn, session_ref)?
                    .ok_or_else(|| Error::OffRecordSessionNotFound {
                        session_ref: session_ref.to_owned(),
                    })?;
                if !record.closing {
                    record.closing = true;
                    self.store.vault_meta.put(
                        wtxn,
                        &off_record_session_key(session_ref),
                        &encode_off_record_session(&record)?,
                    )?;
                }
                Ok(record)
            })?;
        let receipt_close = receipt_log.close();
        debug_assert!(receipt_close.retained.is_empty());
        let emit_receipts_deleted = receipt_close.deleted;

        let mut turns_deleted = 0_usize;
        let mut missing_turns: Vec<[u8; 16]> = Vec::new();
        let mut missing_conversation_shells: Vec<[u8; 16]> = Vec::new();
        let mut redaction_receipt_ids = Vec::new();
        for bytes in &record.fenced_turns {
            let id = EntityId::from_bytes(*bytes)?;

            // MESSAGE and SUMMARY rows inherit the fence recursively through
            // PartOf and DerivedFrom. Snapshot the complete reverse closure
            // before any PolicyDelete removes graph edges, then delete child
            // carriers first so every remaining carrier stays fenced for the
            // entire cascade. `closing` makes this snapshot stable.
            let inherited_carriers = inherited_off_record_carriers_for_close(self, &id)?;
            for carrier_id in inherited_carriers.iter().rev() {
                let child_outcome = with_off_record_close_delete(carrier_id, || {
                    self.delete_entity_with_reason(carrier_id, DeleteReason::PolicyDelete)
                })?;
                if let Some(receipt_id) = child_outcome.receipt_id {
                    redaction_receipt_ids.push(receipt_id);
                }
            }

            let outcome = with_off_record_close_delete(&id, || {
                self.delete_entity_with_reason(&id, DeleteReason::PolicyDelete)
            })?;
            if outcome.existed {
                turns_deleted += 1;
            } else {
                let rtxn = self.store.env.read_txn()?;
                let already_hard_deleted =
                    self.local_hard_delete_marker_exists_in_txn(&rtxn, &id)?;
                drop(rtxn);
                if already_hard_deleted {
                    // A crash can land after PolicyDelete's purge transaction
                    // (which writes the permanent `dt:` marker) but before this
                    // close path removes the fence row. On retry the entity is
                    // absent, but it was a written turn already deleted by this
                    // close; treating it as tag-before-write would retain a
                    // permanent closed fence and misreport the outcome.
                    turns_deleted += 1;
                } else {
                    // Fully-missing id: the ARCH-0038 delete is a strict no-op
                    // (no tombstone) — remember it so its fence row is retained.
                    missing_turns.push(*bytes);
                }
            }
            if let Some(receipt_id) = outcome.receipt_id {
                redaction_receipt_ids.push(receipt_id);
            }
        }

        // Fresh executor-created CONVERSATION containers are direct-fenced
        // session shells, not turns, so sweep them without changing the
        // turn counters. Promotion removes a reached shell from this frozen
        // list before close can begin.
        for bytes in &record.conversation_shells {
            let id = EntityId::from_bytes(*bytes)?;
            let outcome = with_off_record_close_delete(&id, || {
                self.delete_entity_with_reason(&id, DeleteReason::PolicyDelete)
            })?;
            if !outcome.existed {
                let rtxn = self.store.env.read_txn()?;
                let already_hard_deleted =
                    self.local_hard_delete_marker_exists_in_txn(&rtxn, &id)?;
                drop(rtxn);
                if !already_hard_deleted {
                    missing_conversation_shells.push(*bytes);
                }
            }
            if let Some(receipt_id) = outcome.receipt_id {
                redaction_receipt_ids.push(receipt_id);
            }
        }

        for run_id in &record.context_receipt_runs {
            self.store.delete_retrieval_run(*run_id)?;
        }
        let context_receipts_deleted = record.context_receipt_runs.len();

        // Final txn: re-read and fail closed on drift (defense-in-depth —
        // the closing flag already blocks mutators), then remove fence rows
        // for DELETED turns only and drop the record. A missing turn keeps a
        // sessionless marker so every late entity write is rejected.
        self.with_write_txn(|wtxn| {
            let current =
                session_record_in_txn(&self.store, wtxn, session_ref)?.ok_or_else(|| {
                    Error::OffRecordSessionNotFound {
                        session_ref: session_ref.to_owned(),
                    }
                })?;
            if !current.closing
                || current.fenced_turns != record.fenced_turns
                || current.conversation_shells != record.conversation_shells
                || current.promoted_turns != record.promoted_turns
                || current.context_receipt_runs != record.context_receipt_runs
                || current.code_run_artifact_keys != record.code_run_artifact_keys
            {
                return Err(Error::InvariantViolation(
                    "off-record session record drifted during close",
                ));
            }
            for bytes in &record.fenced_turns {
                let id = EntityId::from_bytes(*bytes)?;
                if missing_turns.contains(bytes) {
                    // Keep the write-door denial without retaining the
                    // session ref after close (session metadata evaporates).
                    // A standalone claim preflight can have recorded a gate
                    // decision while this fence was live, before close won
                    // the race and prevented the actual entity write. That
                    // receipt names a turn which never entered the vault, so
                    // delete it with the closed-fence marker rather than
                    // leaking an off-record artifact.
                    self.store
                        .delete_gate_decisions_for_missing_off_record_turn_in_txn(wtxn, &id)?;
                    remove_inherited_off_record_fence_root_in_txn(&self.store, wtxn, &id)?;
                    self.store.vault_meta.put(
                        wtxn,
                        &off_record_fence_key(&id),
                        OFF_RECORD_CLOSED_FENCE_VALUE,
                    )?;
                    continue;
                }
                remove_inherited_off_record_fence_root_in_txn(&self.store, wtxn, &id)?;
                self.store
                    .vault_meta
                    .delete(wtxn, &off_record_fence_key(&id))?;
            }
            for bytes in &record.conversation_shells {
                let id = EntityId::from_bytes(*bytes)?;
                if missing_conversation_shells.contains(bytes) {
                    self.store.vault_meta.put(
                        wtxn,
                        &off_record_fence_key(&id),
                        OFF_RECORD_CLOSED_FENCE_VALUE,
                    )?;
                } else {
                    self.store
                        .vault_meta
                        .delete(wtxn, &off_record_fence_key(&id))?;
                }
            }
            for artifact_key in &record.code_run_artifact_keys {
                self.store.vault_meta.delete(wtxn, artifact_key)?;
            }
            self.store
                .vault_meta
                .delete(wtxn, &off_record_session_key(session_ref))?;
            Ok(())
        })?;

        Ok(OffRecordCloseOutcome {
            turns_deleted,
            turns_missing: missing_turns.len(),
            context_receipts_deleted,
            emit_receipts_deleted,
            fence_rows_retained: missing_turns.len() + missing_conversation_shells.len(),
            promoted_turns_kept: record.promoted_turns.len(),
            redaction_receipt_ids,
        })
    }
}

#[cfg(test)]
mod tests;
