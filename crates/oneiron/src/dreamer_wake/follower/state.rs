//! A follower session's rows (FIX 7510), each through a typed side table in
//! the caller's transaction: the session's state (its cursors, epoch,
//! keyframe ref, writer fence and prepared suffix), its frames (each an
//! admitted source observation as its exact rendered bytes, with its source
//! pins) and its model results (a suffix's readings with the cache evidence
//! of its call, or a keyframe's folded text).

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::dreamer_wake::sieve::follower::{
    SpanReading, apply_follower_reading_in_txn, candidates_in_txn, still_queued_in_txn,
};
use crate::dreamer_wake::{SieveSpan, SpanKind};
use crate::error::{Error, Result};
use crate::llm::{CacheCallUsage, Scope, ScopeResource};
use crate::ports::ChangeLogStoreRead;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

use super::log::{Log, quote_in};

/// A session's identity: the Dreamer authority and the read scope it reads
/// under, hashed.
pub(crate) type SessionKey = [u8; 32];
/// A result row's key: the attempt that wrote it and the session's sequence.
pub(crate) type ResultKey = (AttemptId, u64);

pub(super) const STATE: SideTable<SessionKey, FollowerState, Named> =
    SideTable::new(&side_table::DREAMER_FOLLOWER_STATE);
pub(super) const FRAMES: SideTable<(SessionKey, u64), FollowerFrame, Named> =
    SideTable::new(&side_table::DREAMER_FOLLOWER_FRAME);
/// Each chunk's first frame after the session's keyframe, and its place in
/// it (FIX 8531): what the loaded log's index answers, read by key.
const CHUNKS: SideTable<(SessionKey, (EntityId, EntityId), [u8; 32]), (u64, u32), Named> =
    SideTable::new(&side_table::DREAMER_FOLLOWER_CHUNK);
pub(super) const RESULTS: SideTable<ResultKey, FollowerResult, Named> =
    SideTable::new(&side_table::DREAMER_FOLLOWER_RESULT);

/// The try writing a session: its attempt and the lease generation within
/// that try. One writer at a time; a publish from any other is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Writer {
    pub(crate) attempt: AttemptId,
    pub(crate) generation: u32,
}

/// A document a call reads, pinned at the version it read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Pin {
    pub(crate) document: EntityId,
    pub(crate) version: String,
}

/// One session's standing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FollowerState {
    /// Moved on by every reset, so a cold resend reads apart from a warm one.
    pub(super) epoch: u64,
    /// The change the log has read through.
    pub(super) materialized_after: Option<[u8; 16]>,
    /// The ordinal the next frame takes, from 1.
    pub(super) next_frame: u64,
    /// Every frame at or below this ordinal is in the prefix.
    pub(super) applied_through: u64,
    /// The frames at or below this ordinal are folded into the keyframe.
    pub(super) covered_through: u64,
    /// The result row holding the keyframe, when one stands.
    pub(super) keyframe: Option<ResultKey>,
    /// The instruction the prefix opens with, as it was sent.
    pub(super) instruction: String,
    /// The route (model and locality) the prefix was last sent on, hashed.
    pub(super) route: [u8; 32],
    /// The cache identity the backend last reported, hashed; none until one does.
    pub(super) reported_cache: Option<[u8; 32]>,
    /// The sequence the next suffix or keyframe takes.
    pub(super) next_seq: u64,
    pub(super) writer: Option<Writer>,
    /// A keyframe is owed before the next suffix.
    pub(super) fold_due: bool,
    /// Spans handed back to their own rungs, never asked here again while
    /// they wait queued.
    pub(super) handed: Vec<[u8; 32]>,
    pub(super) suffix: Option<PreparedSuffix>,
}

/// A suffix prepared and not yet published: what it asks, over which new
/// frames and which prefix, and the digest of its question's bytes, so a
/// retry sends exactly the bytes it prepared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedSuffix {
    pub(super) seq: u64,
    /// The new frames it carries: those after `applied_through` through this.
    pub(super) frames_through: u64,
    pub(super) spans: Vec<AskedSpan>,
    pub(super) base_prefix: [u8; 32],
    pub(super) question: [u8; 32],
}

/// One span a suffix asks about: the frame and chunk its words are in, and
/// the candidates and pins it was asked over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AskedSpan {
    pub(crate) span: SieveSpan,
    pub(crate) frame: u64,
    pub(crate) chunk: u32,
    pub(crate) candidates: Vec<EntityId>,
    pub(crate) pins: Vec<Pin>,
}

/// One admitted source observation: a TURN's chunks as the follower first
/// read them, rendered once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FollowerFrame {
    pub(super) turn: EntityId,
    pub(super) chunks: Vec<FrameChunk>,
    pub(super) pins: Vec<Pin>,
    /// The change the log walk found it at; none for a span's own frame.
    pub(super) change: Option<[u8; 16]>,
    pub(super) bytes: String,
}

/// One chunk a frame holds: its source and the digest of its words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FrameChunk {
    pub(super) source: EntityId,
    pub(super) digest: [u8; 32],
}

/// A frame's bytes as the model reads them.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameView {
    frame: String,
    chunks: Vec<String>,
}

/// Renders frame `ordinal`'s chunk texts, once.
pub(super) fn render_frame(ordinal: u64, texts: &[String]) -> Result<String> {
    serde_json::to_string(&FrameView {
        frame: format!("F{ordinal}"),
        chunks: texts.to_vec(),
    })
    .map_err(|_| Error::InvalidConfig("follower frame encoding".into()))
}

/// The chunk texts a frame's bytes hold, in order.
pub(super) fn frame_texts(frame: &FollowerFrame) -> Result<Vec<String>> {
    serde_json::from_str::<FrameView>(&frame.bytes)
        .map(|view| view.chunks)
        .map_err(|_| Error::CorruptedIndex("follower frame bytes"))
}

/// What a backend may say of its cache's hold on a prefix. Nothing at this
/// head attests residency, so every record reads Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CacheResidency {
    Unknown,
}

/// What one physical model call reported (FIX 6567): its cache records, as
/// the backend gave them, and its token counts. A memo replay made no call
/// and adds no cache records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CallEvidence {
    pub(crate) step_hash: [u8; 32],
    pub(crate) memoized: bool,
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) cache_calls: Vec<CacheCallUsage>,
    pub(crate) residency: CacheResidency,
}

/// What a suffix's call read of one span, and whether the queue took it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReadingRecord {
    pub(crate) span: [u8; 32],
    pub(crate) turn: EntityId,
    pub(crate) kind: SpanKind,
    pub(crate) novel: bool,
    pub(crate) confidence: u8,
    pub(crate) entity: Option<EntityId>,
    /// False when the span left the queue, or its candidates moved, before
    /// the reading published: the span's newer form is asked again.
    pub(crate) applied: bool,
}

/// The step charge a result settles, and its run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub(crate) completed_units: u64,
    pub(crate) step_hashes: Vec<[u8; 32]>,
    pub(crate) run_id: Option<String>,
    pub(crate) at: u64,
}

/// One follower model result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FollowerResult {
    /// A suffix's batch readings.
    Readings {
        session: SessionKey,
        epoch: u64,
        frames_after: u64,
        frames_through: u64,
        base_prefix: [u8; 32],
        call: CallEvidence,
        readings: Vec<ReadingRecord>,
        receipt: Receipt,
    },
    /// A keyframe: the retained frames through `covers_through` folded.
    Keyframe {
        session: SessionKey,
        epoch: u64,
        covers_through: u64,
        /// Every TURN whose words it folds, so an erase finds it.
        turns: Vec<EntityId>,
        bytes: String,
        calls: Vec<CallEvidence>,
        receipt: Receipt,
    },
}

impl FollowerResult {
    fn receipt(&self) -> &Receipt {
        match self {
            Self::Readings { receipt, .. } | Self::Keyframe { receipt, .. } => receipt,
        }
    }
}

/// A session as one transaction holds it.
pub(super) struct Session {
    pub(super) key: SessionKey,
    pub(super) state: FollowerState,
}

/// `key`'s session, or a new one whose log starts at the changelog's head:
/// older admitted words enter only as a routed span's own frame.
pub(super) fn open_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: SessionKey,
    instruction: &str,
    route: [u8; 32],
) -> Result<Session> {
    if let Some(state) = STATE.get(&vault.store, txn, &key)? {
        return Ok(Session { key, state });
    }
    let head = vault.store.port_changelog_head(txn)?.map(|(id, _)| id);
    Ok(Session {
        key,
        state: FollowerState {
            epoch: 0,
            materialized_after: head,
            next_frame: 1,
            applied_through: 0,
            covered_through: 0,
            keyframe: None,
            instruction: instruction.to_owned(),
            route,
            reported_cache: None,
            next_seq: 1,
            writer: None,
            fold_due: false,
            handed: Vec::new(),
            suffix: None,
        },
    })
}

pub(super) fn save_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    session: &Session,
) -> Result<()> {
    STATE.put(store, txn, &session.key, &session.state)
}

/// Every session, for the erase hook.
pub(super) fn sessions_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<Session>> {
    Ok(STATE
        .scan(store, txn)?
        .into_iter()
        .map(|(key, state)| Session { key, state })
        .collect())
}

/// The session's frames after ordinal `after`, in order.
pub(super) fn frames_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &SessionKey,
    after: u64,
) -> Result<Vec<(u64, FollowerFrame)>> {
    let start = (*key, after.saturating_add(1));
    let end = (*key, u64::MAX);
    FRAMES
        .iter_range(
            store,
            txn,
            std::ops::Bound::Included(&start),
            std::ops::Bound::Included(&end),
        )?
        .map(|row| row.map(|((_, ordinal), frame)| (ordinal, frame)))
        .collect()
}

/// Appends `frame` under the session's next ordinal and returns it. Each
/// chunk it holds that no live frame after the keyframe holds yet is
/// indexed to it in the same write (FIX 8531).
pub(super) fn append_frame_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    session: &mut Session,
    frame: &FollowerFrame,
) -> Result<u64> {
    let ordinal = session.state.next_frame;
    FRAMES.put(store, txn, &(session.key, ordinal), frame)?;
    for (chunk, held) in frame.chunks.iter().enumerate() {
        let key = (session.key, (frame.turn, held.source), held.digest);
        let stale = match CHUNKS.get(store, txn, &key)? {
            None => true,
            Some((at, _)) => {
                at <= session.state.covered_through
                    || !FRAMES.contains(store, txn, &(session.key, at))?
            }
        };
        if stale {
            CHUNKS.put(store, txn, &key, &(ordinal, chunk as u32))?;
        }
    }
    session.state.next_frame = ordinal.saturating_add(1);
    Ok(ordinal)
}

/// The frame and chunk holding `span`'s words at its digest among the
/// session's frames after its keyframe, by one keyed read (FIX 8531): what
/// the loaded log's `find` answers. An index row whose frame is covered,
/// gone or holds other words there reads as none.
pub(super) fn framed_span_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    session: &Session,
    span: &SieveSpan,
) -> Result<Option<(u64, u32)>> {
    let key = (session.key, (span.turn, span.source), span.source_digest);
    let Some((ordinal, chunk)) = CHUNKS.get(store, txn, &key)? else {
        return Ok(None);
    };
    if ordinal <= session.state.covered_through {
        return Ok(None);
    }
    let Some(frame) = FRAMES.get(store, txn, &(session.key, ordinal))? else {
        return Ok(None);
    };
    let holds = frame.turn == span.turn
        && usize::try_from(chunk)
            .ok()
            .and_then(|at| frame.chunks.get(at))
            .is_some_and(|held| held.source == span.source && held.digest == span.source_digest);
    Ok(holds.then_some((ordinal, chunk)))
}

pub(super) fn result_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ResultKey,
) -> Result<Option<FollowerResult>> {
    RESULTS.get(store, txn, key)
}

/// Writes a model result through the vault, so the side-row wall masks a
/// secret it finds rather than refusing the publish.
pub(super) fn put_result_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &ResultKey,
    result: &FollowerResult,
) -> Result<()> {
    RESULTS.put(vault, txn, key, result)
}

/// Every session that still reads, for the erase hook: a state row that no
/// longer decodes goes, with every frame under it, so an erase never fails
/// on it and nothing it held is sent again.
pub(super) fn erase_sessions_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
) -> Result<Vec<Session>> {
    let rows = STATE
        .iter_raw_from(store, txn, &[])?
        .collect::<Result<Vec<_>>>()?;
    let mut sessions = Vec::with_capacity(rows.len());
    for (raw, value) in rows {
        match (
            <SessionKey as SideKey>::decode_key(&raw),
            STATE.decode_value(&value),
        ) {
            (Some(key), Ok(state)) => sessions.push(Session { key, state }),
            _ => {
                FRAMES.delete_from(store, txn, &raw)?;
                CHUNKS.delete_from(store, txn, &raw)?;
                STATE.delete_from(store, txn, &raw)?;
            }
        }
    }
    Ok(sessions)
}

/// Takes the erased TURNs' frames out of `key`'s session, in the erasing
/// transaction, and any row there that no longer reads as a frame, with
/// every chunk index row of those TURNs (FIX 8531). Returns the ordinals
/// that went; a row whose key does not read counts as 0.
pub(super) fn forget_frames_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &SessionKey,
    turns: &[EntityId],
) -> Result<Vec<u64>> {
    for turn in turns {
        let mut prefix = key.to_vec();
        prefix.extend_from_slice(turn.as_bytes());
        CHUNKS.delete_from(store, txn, &prefix)?;
    }
    let rows = FRAMES
        .iter_raw_from(store, txn, key)?
        .collect::<Result<Vec<_>>>()?;
    let mut gone = Vec::new();
    for (raw, value) in rows {
        let erased = match FRAMES.decode_value(&value) {
            Ok(frame) => turns.contains(&frame.turn),
            Err(_) => true,
        };
        if erased {
            FRAMES.delete_from(store, txn, &raw)?;
            gone.push(
                <(SessionKey, u64) as SideKey>::decode_key(&raw).map_or(0, |(_, ordinal)| ordinal),
            );
        }
    }
    Ok(gone)
}

/// Takes the erased TURNs' readings and keyframes out of the results, in
/// the erasing transaction: a keyframe that folds any of their words goes
/// whole, a suffix's result keeps its other readings, and a row that no
/// longer decodes goes, so an erase never fails on it.
pub(super) fn forget_results_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turns: &[EntityId],
) -> Result<()> {
    let rows = RESULTS
        .iter_raw_from(store, txn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (raw, value) in rows {
        let kept = match RESULTS.decode_value(&value) {
            Err(_) => None,
            Ok(FollowerResult::Keyframe { turns: folded, .. }) => {
                if !folded.iter().any(|turn| turns.contains(turn)) {
                    continue;
                }
                None
            }
            Ok(FollowerResult::Readings {
                session,
                epoch,
                frames_after,
                frames_through,
                base_prefix,
                call,
                readings,
                receipt,
            }) => {
                if !readings.iter().any(|reading| turns.contains(&reading.turn)) {
                    continue;
                }
                Some(FollowerResult::Readings {
                    session,
                    epoch,
                    frames_after,
                    frames_through,
                    base_prefix,
                    call,
                    readings: readings
                        .into_iter()
                        .filter(|reading| !turns.contains(&reading.turn))
                        .collect(),
                    receipt,
                })
            }
        };
        match (kept, <ResultKey as SideKey>::decode_key(&raw)) {
            (Some(kept), Some(key)) => RESULTS.put(store, txn, &key, &kept)?,
            _ => {
                RESULTS.delete_from(store, txn, &raw)?;
            }
        }
    }
    Ok(())
}

/// The units and step hashes `attempt`'s results charge that no settlement
/// has paid yet: a result published before a crash still settles once.
pub(crate) fn unpaid_in(vault: &Vault, attempt: AttemptId) -> Result<(u64, Vec<[u8; 32]>)> {
    let rows = {
        let txn = vault.store.env.read_txn()?;
        RESULTS.scan_from(&vault.store, &txn, attempt.as_bytes())?
    };
    let store = DreamerRunnerStore::new(vault);
    let mut units = 0_u64;
    let mut hashes = Vec::new();
    for (_, result) in rows {
        let receipt = result.receipt();
        let mut paid = !receipt.step_hashes.is_empty();
        for hash in &receipt.step_hashes {
            paid &= store.checkpoint_step_charged(attempt, hash)?;
        }
        if !paid {
            units = units.saturating_add(receipt.completed_units);
            hashes.extend_from_slice(&receipt.step_hashes);
        }
    }
    Ok((units, hashes))
}

/// The document versions a scope pins.
pub(super) fn pins_of(scope: &Scope) -> Vec<Pin> {
    scope
        .readable
        .iter()
        .filter_map(|resource| match resource {
            ScopeResource::DocumentVersion { document, version } => Some(Pin {
                document: *document,
                version: version.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// Whether `asked` still reads as it was asked: queued as it was, its turn
/// and source readable, its candidates and their versions the same.
fn current_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    log: &mut Log,
    asked: &AskedSpan,
) -> Result<bool> {
    if !still_queued_in_txn(vault, txn, &asked.span)? {
        return Ok(false);
    }
    let Some(quote) = quote_in(log, asked.frame, asked.chunk, &asked.span)? else {
        return Ok(false);
    };
    let mut scope = Scope::default();
    let Some(candidates) = candidates_in_txn(vault, txn, &asked.span, &quote, &mut scope)? else {
        return Ok(false);
    };
    Ok(candidates == asked.candidates && pins_of(&scope) == asked.pins)
}

/// A suffix's validated readings, one per asked span in order, and what its
/// call reported.
pub(crate) struct Publication<'a> {
    pub(crate) key: SessionKey,
    pub(crate) writer: Writer,
    pub(crate) seq: u64,
    pub(crate) readings: &'a [SpanReading],
    pub(crate) call: CallEvidence,
    /// The cache identity the backend reported, hashed; none when it named none.
    pub(crate) reported_cache: Option<[u8; 32]>,
    pub(crate) receipt: Receipt,
}

/// Publishes a suffix in one transaction: each reading through the
/// interest queue (a span that moved meanwhile keeps its newer form, still
/// owed), the result row with its cache evidence, the new frames promoted
/// into the prefix and the applied cursor. False, with nothing written,
/// when this writer no longer holds the session or the suffix went.
pub(crate) fn publish_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    publication: Publication<'_>,
) -> Result<bool> {
    let Some(mut session) =
        held_session_in_txn(&vault.store, txn, publication.key, publication.writer)?
    else {
        return Ok(false);
    };
    let Some(suffix) = session.state.suffix.take() else {
        return Ok(false);
    };
    if suffix.seq != publication.seq || suffix.spans.len() != publication.readings.len() {
        return Ok(false);
    }
    let mut log = Log::load_in_txn(&vault.store, txn, &session)?;
    let mut readings = Vec::with_capacity(suffix.spans.len());
    for (asked, reading) in suffix.spans.iter().zip(publication.readings) {
        let applied = current_in_txn(vault, txn, &mut log, asked)?
            && reading
                .entity
                .is_none_or(|entity| asked.candidates.contains(&entity));
        if applied {
            apply_follower_reading_in_txn(vault, txn, &asked.span, *reading)?;
        }
        readings.push(ReadingRecord {
            span: asked.span.id,
            turn: asked.span.turn,
            kind: reading.kind,
            novel: reading.novel,
            confidence: reading.confidence,
            entity: reading.entity,
            applied,
        });
    }
    let frames_after = session.state.applied_through;
    session.state.applied_through = frames_after.max(suffix.frames_through);
    // A new reported identity means the backend's cache owner changed: the
    // next call goes out cold under a new epoch. No report changes nothing.
    if let Some(reported) = publication.reported_cache {
        if session
            .state
            .reported_cache
            .is_some_and(|known| known != reported)
        {
            session.state.epoch = session.state.epoch.saturating_add(1);
        }
        session.state.reported_cache = Some(reported);
    }
    let result = FollowerResult::Readings {
        session: session.key,
        epoch: session.state.epoch,
        frames_after,
        frames_through: suffix.frames_through,
        base_prefix: suffix.base_prefix,
        call: publication.call,
        readings,
        receipt: publication.receipt,
    };
    put_result_in_txn(
        vault,
        txn,
        &(publication.writer.attempt, suffix.seq),
        &result,
    )?;
    save_in_txn(&vault.store, txn, &session)?;
    Ok(true)
}

/// The session `key`, when `writer` holds it.
pub(super) fn held_session_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: SessionKey,
    writer: Writer,
) -> Result<Option<Session>> {
    Ok(STATE
        .get(store, txn, &key)?
        .filter(|state| state.writer == Some(writer))
        .map(|state| Session { key, state }))
}
