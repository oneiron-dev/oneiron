//! `vault.recall` under a caller's operation id (RESEARCH-0363 p5; Engine
//! RULING L1-13-P5-NOW, 14 Nov, design (i)).
//!
//! A host that replays a handler under the same operation id (eve) needs the
//! same recall answer each time. Under (principal, operation id) the first
//! recall keeps its answer's identity and none of its text: each item's
//! entity id and served revision, the messages it quotes and its embedding
//! evidence, the first answer's retrieval accounting, a digest of the
//! request and a digest of the items. The same request under the same id
//! rebuilds those items at those revisions under the caller's CURRENT read
//! ([`Memory::recall_replay_pack`]) and answers them only when their digest
//! is the first answer's. An erase, a retraction or a narrowed read since
//! then refuses with `INVALID_STATE`; no old text is ever served. Without an
//! operation id, recall runs as before.
//!
//! The rows are runtime state: never imaged, aged out after
//! [`RECALL_REPLAY_RETENTION_SECS`], at most
//! [`RECALL_REPLAY_ROWS_PER_PRINCIPAL`] per principal, and an actor's erase
//! removes its own.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryItem, MemoryPack,
    MemoryResult, RecallEffort, RecallRequest, RetrievalMeta, ScopeHonesty,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::embedding::EmbeddingMatchEvidence;

/// The longest operation id a recall takes, in characters.
pub(crate) const RECALL_OPERATION_ID_MAX_CHARS: usize = 128;

/// The replays one principal keeps: a new operation past it drops the oldest.
pub(crate) const RECALL_REPLAY_ROWS_PER_PRINCIPAL: usize = 64;

/// How long a replay is kept, in vault seconds.
pub(crate) const RECALL_REPLAY_RETENTION_SECS: u64 = 24 * 60 * 60;

/// One item of a first answer, by identity alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RecallReplayPin {
    /// The item's record.
    pub(crate) entity: EntityId,
    /// The revision (32 hex) the first answer served it at, when it pinned one.
    pub(crate) revision: Option<String>,
    /// The messages a TURN item quoted, in order.
    pub(crate) cited: Vec<EntityId>,
    /// The item's raw embedding evidence, scores only.
    pub(crate) embedding_matches: Vec<EmbeddingMatchEvidence>,
}

/// The first answer's retrieval accounting, kept as the wire spells it.
#[derive(Serialize, Deserialize)]
struct RecallReplayAccounting {
    scope_honesty: ScopeHonesty,
    retrieval_meta: RetrievalMeta,
}

/// One operation's first answer, by identity: no memory text.
#[derive(Serialize, Deserialize)]
pub(crate) struct RecallReplayRow {
    /// blake3 of the request's JSON, its operation id left out.
    request: [u8; 32],
    /// blake3 of the first answer's items' JSON.
    items: [u8; 32],
    /// When the first answer was kept, in vault seconds.
    recorded_at: u64,
    /// The first answer's items, ranked.
    pins: Vec<RecallReplayPin>,
    /// [`RecallReplayAccounting`] as JSON.
    accounting: Vec<u8>,
}

/// Key: the principal's actor id, then blake3 of its actor class and the
/// operation id.
const RECALL_REPLAY: SideTable<(EntityId, [u8; 32]), RecallReplayRow, Named> =
    SideTable::new(&side_table::RECALL_REPLAY);

/// The recall `run` answers, under `operation`: the first time it runs and is
/// kept; each later time the same request is a replay of that first answer.
pub(crate) fn recall_under_operation(
    memory: &Memory<'_>,
    operation: &str,
    input: RecallRequest,
    run: impl FnOnce(RecallRequest) -> MemoryResult<MemoryPack>,
) -> MemoryResult<MemoryPack> {
    check_operation_request(operation, &input)?;
    let key = replay_key(memory, operation);
    let request = request_digest(&input)?;
    let vault = memory.vault;
    let now = vault.now_recorded_at();
    let kept = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        RECALL_REPLAY.get(&vault.store, &txn, &key)?
    }
    .filter(|row| !expired(row, now));
    if let Some(row) = kept {
        if row.request != request {
            return Err(MemoryError::bad_request_with(
                "this operation_id already answered another recall request",
                &["Send the operation's first request unchanged, or use a new operation_id."],
            ));
        }
        return replay(memory, &input, &row);
    }
    let pack = run(input)?;
    let row = RecallReplayRow {
        request,
        items: items_digest(&pack.items)?,
        recorded_at: now,
        pins: pins_of(&pack.items)?,
        accounting: serde_json::to_vec(&RecallReplayAccounting {
            scope_honesty: pack.scope_honesty.clone(),
            retrieval_meta: pack.retrieval_meta.clone(),
        })
        .map_err(|error| replay_internal(&error))?,
    };
    keep(vault, &key, &row, now)?;
    Ok(pack)
}

/// What an operation id recall takes: the id's alphabet and length, no
/// `format` (the rendered text holds neighbours and the L2 base, which are
/// not pinned items) and no deadline (a door answers its cut pack at one).
fn check_operation_request(operation: &str, input: &RecallRequest) -> MemoryResult<()> {
    let spelled = operation
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
    if operation.is_empty() || operation.len() > RECALL_OPERATION_ID_MAX_CHARS || !spelled {
        return Err(MemoryError::bad_request_with(
            "operation_id must be 1 to 128 characters of A-Z, a-z, 0-9, '.', '_', ':' and '-'",
            &["Send the host's operation id in that alphabet, or omit operation_id."],
        ));
    }
    if input.format.is_some() {
        return Err(MemoryError::bad_request_with(
            "an operation_id recall replays its typed items and renders no format",
            &["Omit format, or omit operation_id."],
        ));
    }
    if input.deadline_ms.is_some() || matches!(input.effort, Some(RecallEffort::Call)) {
        return Err(MemoryError::bad_request_with(
            "an operation_id recall runs to its end: it takes no deadline_ms and no call effort",
            &["Omit deadline_ms and call effort, or omit operation_id."],
        ));
    }
    Ok(())
}

/// The first answer's items again, or the refusal that says they changed.
fn replay(
    memory: &Memory<'_>,
    input: &RecallRequest,
    row: &RecallReplayRow,
) -> MemoryResult<MemoryPack> {
    let accounting: RecallReplayAccounting =
        serde_json::from_slice(&row.accounting).map_err(|error| replay_internal(&error))?;
    let scope = input.scope.clone().unwrap_or_default();
    let pack = memory.recall_replay_pack(
        &scope,
        input.as_of,
        &row.pins,
        accounting.scope_honesty,
        accounting.retrieval_meta,
    )?;
    match pack {
        Some(pack) if items_digest(&pack.items)? == row.items => Ok(pack),
        _ => Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "this operation's recall answer changed since its first answer: a record it \
             served was erased, retracted or changed, or the caller's read narrowed",
            &["Recall under a new operation_id for the current answer."],
        )),
    }
}

fn replay_key(memory: &Memory<'_>, operation: &str) -> (EntityId, [u8; 32]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.recall.replay.v1\0");
    hasher.update(&[memory.actor_class as u8]);
    hasher.update(operation.as_bytes());
    (memory.actor, *hasher.finalize().as_bytes())
}

fn request_digest(input: &RecallRequest) -> MemoryResult<[u8; 32]> {
    let request = RecallRequest {
        operation_id: None,
        ..input.clone()
    };
    let bytes = serde_json::to_vec(&request).map_err(|error| replay_internal(&error))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn items_digest(items: &[MemoryItem]) -> MemoryResult<[u8; 32]> {
    let bytes = serde_json::to_vec(items).map_err(|error| replay_internal(&error))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn pins_of(items: &[MemoryItem]) -> MemoryResult<Vec<RecallReplayPin>> {
    items
        .iter()
        .map(|item| {
            Ok(RecallReplayPin {
                entity: record_id(item.record.as_ref())?,
                revision: item.source_revision_ref.clone(),
                cited: item
                    .cited_messages
                    .iter()
                    .map(|message| record_id(message.record.as_ref()))
                    .collect::<MemoryResult<_>>()?,
                embedding_matches: item.embedding_matches.clone(),
            })
        })
        .collect()
}

fn record_id(record: Option<&crate::lens::RecordRef>) -> MemoryResult<EntityId> {
    record
        .and_then(|record| EntityId::from_hex(&record.id).ok())
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_INTERNAL,
                "a recalled item names no record id, so its operation cannot be replayed",
                &[],
            )
        })
}

fn expired(row: &RecallReplayRow, now: u64) -> bool {
    now.saturating_sub(row.recorded_at) > RECALL_REPLAY_RETENTION_SECS
}

/// Keeps `row` under `key`, dropping the principal's expired rows and, past
/// [`RECALL_REPLAY_ROWS_PER_PRINCIPAL`], its oldest.
fn keep(
    vault: &Vault,
    key: &(EntityId, [u8; 32]),
    row: &RecallReplayRow,
    now: u64,
) -> MemoryResult<()> {
    let (actor, _) = key;
    let mut txn = vault.store.env.write_txn().map_err(Error::from)?;
    let mut held = Vec::new();
    for (kept_key, kept) in RECALL_REPLAY.scan_from(&vault.store, &txn, actor.as_bytes())? {
        if kept_key == *key || expired(&kept, now) {
            RECALL_REPLAY.delete(&vault.store, &mut txn, &kept_key)?;
        } else {
            held.push((kept.recorded_at, kept_key));
        }
    }
    held.sort_by_key(|(recorded_at, _)| *recorded_at);
    let over = (held.len() + 1).saturating_sub(RECALL_REPLAY_ROWS_PER_PRINCIPAL);
    for (_, oldest) in held.into_iter().take(over) {
        RECALL_REPLAY.delete(&vault.store, &mut txn, &oldest)?;
    }
    RECALL_REPLAY.put(&vault.store, &mut txn, key, row)?;
    txn.commit().map_err(Error::from)?;
    Ok(())
}

/// An actor's erase removes the replays kept under it (FIX 3520).
pub(crate) fn erase_recall_replay_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::error::Result<()> {
    for key in RECALL_REPLAY.scan_keys(&vault.store, &*txn, actor.as_bytes())? {
        RECALL_REPLAY.delete(&vault.store, txn, &key)?;
    }
    Ok(())
}

fn replay_internal(error: &serde_json::Error) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("recall replay row: {error}"),
        &[],
    )
}
