//! The sieve audit's second population (OF-498f, FIX 486): source windows
//! the cheap rules left unflagged, so the expensive path can say what the
//! rules missed there.
//!
//! A window is a byte range of one source of a turn whose reading is whole
//! and current, in which no span of that reading lies: neither a rule's nor
//! a saved tag's. Each run of unflagged words is split into pieces of at
//! most the policy row's window bytes, cut after whitespace where it can,
//! and every piece is a window: the size splits a run, it never caps what
//! is read. A piece with no letter or digit holds no date or name and is no
//! window.
//!
//! The draw sits on top of the flagged sample, which it leaves as it was: a
//! weave with audits on draws its share of `audit_spans` again in windows.
//! Turns are walked in an order the weave's attempt seeds, each window of a
//! turn is drawn at the flagged sample's own percent, and the walk stops
//! once the draw is full. Every source is read as the sieve reads it,
//! through the Dreamer's gate: a source it may not read gives no window and
//! is never refused anew.

use std::collections::BTreeSet;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::super::recipes::WakeRecipePolicy;
use super::chunks::{self, Admission, Chunk, ChunkRef};
use super::{CONTINUE, OWED, READ, RUNG_ATTEMPT, SpanKind};
use crate::attempt_queue::AttemptId;
use crate::claim::ScopedReadActorKey;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerAttemptStatus, DreamerConsolidationScope, DreamerRunnerStore,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::{Scope, ScopeResource};
use crate::{EntityId, Error, Result, Vault};

/// A byte range of one source of a turn, read at the version
/// `source_digest`, where the turn's current reading flagged nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveAuditWindow {
    pub turn: EntityId,
    /// The MESSAGE whose text the offsets index, or the TURN for body text.
    pub source: EntityId,
    /// BLAKE3 of the source text the offsets index.
    pub source_digest: [u8; 32],
    /// UTF-8 byte offsets into that text, on character boundaries.
    pub start: u64,
    pub end: u64,
}

impl SieveAuditWindow {
    /// BLAKE3 identity of the window: its ref and the text version it
    /// indexes.
    pub fn id(&self) -> [u8; 32] {
        *blake3::Hasher::new()
            .update(b"oneiron:dreamer-sieve:audit-window:v1")
            .update(self.turn.as_bytes())
            .update(self.source.as_bytes())
            .update(&self.source_digest)
            .update(&self.start.to_be_bytes())
            .update(&self.end.to_be_bytes())
            .finalize()
            .as_bytes()
    }
}

/// What the rules expected of an audited range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SieveAuditExpectation {
    /// A rule or a saved tag flagged a span there ([`super::SieveAudit`]).
    Flagged,
    /// Nothing was flagged in the range.
    Unflagged,
}

/// One span the expensive path found in a window, by its exact bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveAuditDiscovery {
    /// UTF-8 byte offsets into the window's source text, inside the window.
    pub start: u64,
    pub end: u64,
    pub kind: SpanKind,
    /// Percent.
    pub confidence: u8,
}

/// What the expensive path found in an audited range: the rules'
/// expectation, and every span it found there, zero or more. None found is
/// a negative label: the rules missed nothing in the range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveAuditFinding {
    pub expectation: SieveAuditExpectation,
    pub window: SieveAuditWindow,
    pub discovered: Vec<SieveAuditDiscovery>,
}

/// An unflagged window's audit receipt: its finding and what it spent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveWindowAudit {
    pub finding: SieveAuditFinding,
    pub at: u64,
    pub completed_units: u64,
    pub step_hashes: Vec<[u8; 32]>,
}

/// A queued window audit: the window, and the recipe policy it was drawn
/// under.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowAuditInput {
    pub(crate) window: SieveAuditWindow,
    pub(crate) policy: WakeRecipePolicy,
}

/// A window's words as its audit reads them now, and the source grants its
/// call carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowEvidence {
    pub(crate) text: String,
    pub(crate) scope: Scope,
}

/// How a queued window audit reads now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowRead {
    Ready(WindowEvidence),
    /// The window no longer stands as it was drawn: its turn left the
    /// sieve, its source left the turn, its words changed, or a span of the
    /// turn's current reading lies in it. The audit completes with no
    /// receipt, as a flagged audit whose span went does.
    Superseded,
    /// The Dreamer may not read the source now: the audit waits.
    Withheld,
}

/// What a window audit's call found, and what it spent.
pub(crate) struct WindowOutcome {
    pub(crate) discovered: Vec<SieveAuditDiscovery>,
    pub(crate) completed_units: u64,
    pub(crate) step_hashes: Vec<[u8; 32]>,
    pub(crate) at: u64,
}

/// The windows a weave audits on top of its flagged sample, in the order
/// `seed` draws them.
pub(crate) fn audit_window_sample_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seed: AttemptId,
    policy: &WakeRecipePolicy,
) -> Result<Vec<SieveAuditWindow>> {
    let draws = window_draws(policy);
    if draws == 0 {
        return Ok(Vec::new());
    }
    let mut turns = Vec::new();
    for row in READ.iter_from(&vault.store, txn, &[])? {
        let (turn, read) = row?;
        if read.next.is_none() {
            turns.push((
                draw_rank(b"turn", seed, turn.as_bytes()),
                turn,
                read.reading,
            ));
        }
    }
    turns.sort_unstable_by_key(|(rank, ..)| *rank);
    let size = usize::try_from(policy.audit_window_bytes).unwrap_or(usize::MAX);
    let mut windows = Vec::new();
    for (_, turn, reading) in turns {
        if windows.len() >= draws {
            break;
        }
        let mut drawn: Vec<([u8; 32], SieveAuditWindow)> =
            turn_windows_in_txn(vault, txn, &turn, reading, size)?
                .into_iter()
                .filter_map(|window| {
                    let rank = draw_rank(b"window", seed, &window.id());
                    drawn_at(&rank, policy.audit_percent).then_some((rank, window))
                })
                .collect();
        drawn.sort_unstable_by_key(|(rank, _)| *rank);
        windows.extend(drawn.into_iter().map(|(_, window)| window));
    }
    windows.truncate(draws);
    Ok(windows)
}

/// How many windows a weave draws on top of the flagged sample: its share
/// of `audit_spans`, rounded up; none while the flagged sample is off.
fn window_draws(policy: &WakeRecipePolicy) -> usize {
    if policy.audit_percent == 0
        || policy.audit_spans == 0
        || policy.audit_window_share == 0
        || policy.audit_window_bytes == 0
    {
        return 0;
    }
    let draws =
        (u64::from(policy.audit_spans) * u64::from(policy.audit_window_share)).div_ceil(100);
    usize::try_from(draws).unwrap_or(usize::MAX)
}

/// The unflagged windows of `turn`, read whole at `reading`: none while its
/// reading goes on, is owed again, waits on a tagged MESSAGE away from this
/// replica, or no longer reads as the words it was read from.
fn turn_windows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    reading: [u8; 32],
    size: usize,
) -> Result<Vec<SieveAuditWindow>> {
    let store = &vault.store;
    if OWED.contains(store, txn, turn)?
        || CONTINUE.contains(store, txn, turn)?
        || crate::tagging::tagged_messages_absent_in_txn(store, txn, turn)?
        || !super::sieved_turn_in_txn(vault, txn, turn)?
    {
        return Ok(Vec::new());
    }
    let Some(read) = chunks::turn_chunks_in_txn(vault, txn, turn)? else {
        return Ok(Vec::new());
    };
    let held: Vec<ChunkRef> = read.chunks.iter().map(Chunk::held).collect();
    if chunks::reading_digest(&held) != reading {
        return Ok(Vec::new());
    }
    let history = super::recipes::history_in_txn(store, txn, turn)?;
    let mut windows = Vec::new();
    for chunk in &read.chunks {
        let mut flagged: Vec<(usize, usize)> = history
            .iter()
            .filter(|span| span.source == chunk.source && span.source_digest == chunk.digest)
            .filter_map(|span| {
                Some((
                    usize::try_from(span.start).ok()?,
                    usize::try_from(span.end).ok()?,
                ))
            })
            .collect();
        flagged.sort_unstable();
        for (start, end) in unflagged_pieces(&chunk.text, &flagged, size) {
            windows.push(SieveAuditWindow {
                turn: *turn,
                source: chunk.source,
                source_digest: chunk.digest,
                start: start as u64,
                end: end as u64,
            });
        }
    }
    Ok(windows)
}

/// The pieces of `text` outside every `flagged` range (sorted by start),
/// each at most `size` bytes but one whole character, that hold a letter or
/// a digit.
fn unflagged_pieces(text: &str, flagged: &[(usize, usize)], size: usize) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut at = 0;
    for &(start, end) in flagged {
        if start > at {
            runs.push((at, start.min(text.len())));
        }
        at = at.max(end);
    }
    if at < text.len() {
        runs.push((at, text.len()));
    }
    let mut pieces = Vec::new();
    for (start, end) in runs {
        let start = ceil_boundary(text, start);
        let Some(run) = text.get(start..text.floor_char_boundary(end)) else {
            continue;
        };
        for (from, to) in split(run, size) {
            if run
                .get(from..to)
                .is_some_and(|words| words.chars().any(char::is_alphanumeric))
            {
                pieces.push((start + from, start + to));
            }
        }
    }
    pieces
}

/// `words` in pieces of at most `size` bytes, in order, as offsets into it:
/// each cut on a character boundary, after the last whitespace in its
/// second half when it has one. A character longer than `size` is one
/// piece, whole. No byte is left out.
fn split(words: &str, size: usize) -> Vec<(usize, usize)> {
    let size = size.max(1);
    let mut pieces = Vec::new();
    let mut start = 0;
    while words.len() - start > size {
        let mut end = words.floor_char_boundary(start + size);
        if let Some(space) = words.as_bytes()[start..end]
            .iter()
            .rposition(u8::is_ascii_whitespace)
            .filter(|&space| space >= size / 2)
        {
            end = start + space + 1;
        }
        if end == start {
            end = start + words[start..].chars().next().map_or(1, char::len_utf8);
        }
        pieces.push((start, end));
        start = end;
    }
    if start < words.len() {
        pieces.push((start, words.len()));
    }
    pieces
}

/// The first character boundary of `text` at or after `at`.
fn ceil_boundary(text: &str, mut at: usize) -> usize {
    while at < text.len() && !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

fn draw_rank(domain: &[u8], seed: AttemptId, id: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(b"oneiron:sieve:audit-window-sample:v1")
        .update(domain)
        .update(seed.as_bytes())
        .update(id)
        .finalize()
        .as_bytes()
}

/// Whether `rank` falls in the first `percent` of draws, as the flagged
/// sample draws a span.
fn drawn_at(rank: &[u8; 32], percent: u8) -> bool {
    let draw = u64::from_be_bytes(rank[..8].try_into().expect("eight bytes"));
    u128::from(draw) * 100 < (u128::from(u64::MAX) + 1) * u128::from(percent)
}

pub(crate) fn enqueue_window_audit_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &mut heed::RwTxn<'_>,
    parent: &DreamerAttemptStatus,
    window: &SieveAuditWindow,
    policy: &WakeRecipePolicy,
    now: u64,
) -> Result<()> {
    let input = serde_json::to_string(&WindowAuditInput {
        window: *window,
        policy: policy.clone(),
    })
    .map_err(|_| Error::InvalidConfig("sieve window audit input encoding".into()))?;
    store.enqueue_kind_in_txn(
        txn,
        DreamerConsolidationScope::Micro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: RUNG_ATTEMPT.into(),
            input: Value::from(input),
            parent_attempt: Some(parent.attempt.id),
        },
        Some(format!(
            "sieve:audit-window:{}:{}",
            bytes_to_hex_lower(parent.attempt.id.as_bytes()),
            bytes_to_hex_lower(&window.id())
        )),
        parent.attempt.run_id.clone(),
        now,
    )?;
    Ok(())
}

/// How `input`'s window reads now, at a persisted grant clock.
pub(crate) fn window_read(vault: &Vault, input: &WindowAuditInput) -> Result<WindowRead> {
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn()?;
    window_read_in_txn(vault, &txn, input)
}

fn window_read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &WindowAuditInput,
) -> Result<WindowRead> {
    let window = &input.window;
    if !READ.contains(&vault.store, txn, &window.turn)? {
        return Ok(WindowRead::Superseded);
    }
    match chunks::admissions_in_txn(vault, txn, &[(window.turn, window.source)])?.first() {
        Some(Admission::Readable) => {}
        Some(Admission::Unreadable) => return Ok(WindowRead::Withheld),
        Some(Admission::Detached) | None => return Ok(WindowRead::Superseded),
    }
    let Some(text) = chunks::chunk_text_in_txn(vault, txn, &window.turn, &window.source)? else {
        return Ok(WindowRead::Withheld);
    };
    let words = usize::try_from(window.start)
        .ok()
        .zip(usize::try_from(window.end).ok())
        .and_then(|(start, end)| text.get(start..end))
        .filter(|_| chunk_digest(&text) == window.source_digest);
    let Some(words) = words else {
        return Ok(WindowRead::Superseded);
    };
    if flagged_in_txn(&vault.store, txn, window)? {
        return Ok(WindowRead::Superseded);
    }
    let Some(scope) = source_scope_in_txn(vault, txn, window)? else {
        return Ok(WindowRead::Withheld);
    };
    Ok(WindowRead::Ready(WindowEvidence {
        text: words.to_owned(),
        scope,
    }))
}

/// Whether a span of the turn's current reading lies in `window`.
fn flagged_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    window: &SieveAuditWindow,
) -> Result<bool> {
    Ok(super::recipes::history_in_txn(store, txn, &window.turn)?
        .iter()
        .any(|span| {
            span.source == window.source
                && span.source_digest == window.source_digest
                && span.start < window.end
                && window.start < span.end
        }))
}

/// The exact source grants a window's call carries: its turn and its source
/// at their current versions, `None` while the Dreamer may not read one.
fn source_scope_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    window: &SieveAuditWindow,
) -> Result<Option<Scope>> {
    let actor = crate::WriteActor::new(
        crate::dreamer_runner::authority::dreamer_actor_id()?,
        crate::EdgeActorClass::System,
    );
    let key = ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or(Error::InvalidConfig("sieve read actor".into()))?;
    let read = vault.scoped_read(key);
    let mut scope = Scope::default();
    for id in BTreeSet::from([window.turn, window.source]) {
        let Some(raw) = read.entity_raw_live_in(txn, &id)? else {
            return Ok(None);
        };
        scope.readable.insert(ScopeResource::DocumentVersion {
            document: id,
            version: format!(
                "blake3:{}",
                bytes_to_hex_lower(&crate::dreamer_consolidation::swarm_evidence_content_hash(
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]
                ))
            ),
        });
    }
    Ok(Some(scope))
}

/// The digest a chunk's text versions its offsets with.
fn chunk_digest(text: &str) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(b"oneiron:dreamer-sieve:chunk:v1")
        .update(text.as_bytes())
        .finalize()
        .as_bytes()
}

/// Keeps the finding as `attempt`'s audit receipt while the window reads as
/// its call read it; `false` when it no longer does, for the audit to read
/// it again.
pub(crate) fn finish_window_audit(
    vault: &Vault,
    attempt: AttemptId,
    input: &WindowAuditInput,
    evidence: &WindowEvidence,
    outcome: WindowOutcome,
) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        if !matches!(
            window_read_in_txn(vault, txn, input)?,
            WindowRead::Ready(current) if current == *evidence
        ) {
            return Ok(false);
        }
        super::recipes::put_audit_in_txn(
            &vault.store,
            txn,
            &attempt,
            &super::SieveAuditRecord::Window(SieveWindowAudit {
                finding: SieveAuditFinding {
                    expectation: SieveAuditExpectation::Unflagged,
                    window: input.window,
                    discovered: outcome.discovered,
                },
                at: outcome.at,
                completed_units: outcome.completed_units,
                step_hashes: outcome.step_hashes,
            }),
        )?;
        Ok(true)
    })
}
