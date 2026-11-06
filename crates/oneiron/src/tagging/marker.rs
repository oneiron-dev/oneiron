//! The marker row: its kind, payload, dedupe key, derived id and the
//! in-transaction doors that commit it.
//!
//! A marker carries the class its producer names, and is live only when it
//! was written live under this environment's open, so every marker a past
//! open left is bulk (FIX 6755). A live write promotes a pending bulk marker
//! in place, and a bulk write never demotes one.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, EnqueueAttempt, EnqueueOutcome, RetryAttempt,
};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::memory::extraction::ExtractionWork;
use crate::ports::EdgeDirection;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

pub use crate::config::tagging::TAGGING_MARKER_KIND;

const MARKER_ID_DOMAIN: &[u8] = b"oneiron.tagging.marker.v2\0";
/// Probes for a free marker id: its digest names a sequence number no other
/// marker drew, so only a chance collision needs another.
const MAX_MARKER_GENERATIONS: u32 = 16;
/// The sequence number the next marker draws: job state, never reset, so a
/// marker id is never drawn twice, not even once a settled marker has left
/// the job ledger.
const MARKER_SEQUENCE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::TAGGING_MARKER_SEQUENCE);
const RETRY_ID_DOMAIN: &[u8] = b"oneiron.tagging.retry.v1\0";
/// Probes for a free retry id: its digest names the try it retries, which
/// has one successor, so only a chance collision needs another.
const MAX_RETRY_GENERATIONS: u32 = 16;

pub(super) use crate::config::tagging::is_checkpoint;
pub use crate::config::tagging::{
    DEFAULT_LIVE_WINDOW_TOKENS, DEFAULT_TRACE_MAX_AGE_SECS, DEFAULT_TRACES_PER_TURN,
    MAX_LIVE_WINDOW_TOKENS, MAX_TRACES_PER_TURN, TaggingMarkerConfig, TaggingMode,
    TaggingTraceHistory, label_kind_admitted,
};

/// What one marker names: a turn owed one pass by one tagger checkpoint,
/// and by the stack pinned beside it, if any; and the class the pass is owed
/// at, which is no part of what it names: neither its dedupe key nor its id
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MarkerPayload {
    pub(super) turn: EntityId,
    pub(super) checkpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) stack: Option<String>,
    /// The class its producer named, or a live write promoted it to.
    pub(super) work: ExtractionWork,
    /// The open nonce of the environment a live marker was written under (the
    /// store's `open_nonce`); `None` for a bulk one.
    pub(super) open: Option<[u8; 16]>,
}

impl MarkerPayload {
    fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvariantViolation("tagging marker payload encoding"))
    }

    /// `None` for a payload this build cannot read; its marker is failed, not
    /// retried, because no pass can ever read it.
    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        rmp_serde::from_slice::<Self>(bytes).ok().filter(|payload| {
            is_checkpoint(&payload.checkpoint) && payload.stack.as_deref().is_none_or(is_checkpoint)
        })
    }

    /// Whether the marker is owed to the tagger `config` arms: its
    /// checkpoint and its pinned stack.
    pub(super) fn owed_to(&self, config: &TaggingMarkerConfig) -> bool {
        self.checkpoint == config.checkpoint && self.stack == config.stack
    }

    /// The class the marker is claimed and called at: live only when it was
    /// written live under this environment's open, so a live marker a past
    /// open left, recovered work, is bulk.
    pub(super) fn effective_work(&self, vault: &Vault) -> ExtractionWork {
        if self.work == ExtractionWork::Live && self.open == Some(vault.store.open_nonce) {
            ExtractionWork::Live
        } else {
            ExtractionWork::Bulk
        }
    }
}

/// Whether two marker payloads name one marker: the same turn, checkpoint
/// and stack, whatever class each carries, so a try a live write promoted
/// still retries the one before it. A payload this build cannot read names
/// none.
pub(crate) fn same_marker_identity(a: &[u8], b: &[u8]) -> bool {
    match (MarkerPayload::decode(a), MarkerPayload::decode(b)) {
        (Some(a), Some(b)) => {
            a.turn == b.turn && a.checkpoint == b.checkpoint && a.stack == b.stack
        }
        _ => false,
    }
}

/// A marker's dedupe key: the turn, then the tagger it is owed to, its
/// checkpoint and the stack pinned beside it.
pub(super) fn dedupe_key(turn: &EntityId, config: &TaggingMarkerConfig) -> String {
    match &config.stack {
        None => format!("{}@{}", turn.to_hex(), config.checkpoint),
        Some(stack) => format!("{}@{}+{stack}", turn.to_hex(), config.checkpoint),
    }
}

/// The marker id is the owner-retained prefix, the low seven bytes of the
/// store-clock second it was committed at, then a digest of what it names: a
/// new marker's digest names its turn, checkpoint and the marker sequence
/// number it drew, a retry's names the try it retries. No two markers draw
/// one sequence number and a try has one successor, so no id is drawn twice,
/// even after pruning, and a long retry history takes none of the ids a new
/// marker needs. Committing either draws nothing from the vault's id source,
/// so a write allocates the same entity ids with or without a tagger; the
/// readiness index still drains markers in commit order across seconds; and
/// every marker sits in the ledger's owner-retained range, which no scan of
/// another job kind reads.
fn derived_id(
    domain: &[u8],
    parts: &[&[u8]],
    recorded_at: u64,
    generation: u32,
) -> Result<AttemptId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.update(&generation.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes[0] = crate::attempt_queue::OWNER_RETAINED_ID_PREFIX;
    bytes[1..8].copy_from_slice(&recorded_at.to_be_bytes()[1..]);
    bytes[8..].copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    AttemptId::from_bytes(&bytes)
}

/// The first derived id no job row holds.
fn free_id(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    generations: u32,
    derive: impl Fn(u32) -> Result<AttemptId>,
) -> Result<AttemptId> {
    for generation in 0..generations {
        let id = derive(generation)?;
        if crate::ports::JobQueueRead::port_job_row(&vault.store, wtxn, &id)?.is_none() {
            return Ok(id);
        }
    }
    Err(Error::IndexOverflow("tagging marker generations"))
}

/// Commits a marker for `turn`, owed to the tagger `config` arms at the
/// class `work`, in the caller's write transaction, stamped at
/// `recorded_at`. A pending marker with the same key absorbs the call. A
/// live call promotes one whose effective class is bulk in place: its state,
/// instant and lease stay, so a paused one stays paused, a scheduled one
/// keeps its backoff, and a running call finishes as it began while its next
/// try is live. A bulk call never demotes one.
pub(super) fn enqueue_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    turn: EntityId,
    config: &TaggingMarkerConfig,
    recorded_at: u64,
    work: ExtractionWork,
) -> Result<EnqueueOutcome> {
    let queue = AttemptQueue::new(vault);
    let key = dedupe_key(&turn, config);
    // A pending marker absorbs the call before any id is drawn for it.
    if let Some(pending) = queue.pending_dedupe_in_txn(wtxn, TAGGING_MARKER_KIND, &key)? {
        if work == ExtractionWork::Live
            && let Some(mut payload) = MarkerPayload::decode(&pending.payload)
            && payload.effective_work(vault) == ExtractionWork::Bulk
        {
            payload.work = ExtractionWork::Live;
            payload.open = Some(vault.store.open_nonce);
            let promoted =
                queue.replace_owner_retained_payload_in_txn(wtxn, &pending, payload.encode()?)?;
            return Ok(EnqueueOutcome::Existing(promoted));
        }
        return Ok(EnqueueOutcome::Existing(pending));
    }
    let sequence = MARKER_SEQUENCE
        .get(&vault.store, wtxn, &())?
        .unwrap_or_default();
    MARKER_SEQUENCE.put(
        &vault.store,
        wtxn,
        &(),
        &sequence
            .checked_add(1)
            .ok_or(Error::IndexOverflow("tagging marker sequence"))?,
    )?;
    let id = free_id(vault, wtxn, MAX_MARKER_GENERATIONS, |generation| {
        derived_id(
            MARKER_ID_DOMAIN,
            &[
                turn.as_bytes(),
                config.checkpoint.as_bytes(),
                &sequence.to_be_bytes(),
            ],
            recorded_at,
            generation,
        )
    })?;
    let payload = MarkerPayload {
        turn,
        checkpoint: config.checkpoint.clone(),
        stack: config.stack.clone(),
        work,
        open: (work == ExtractionWork::Live).then_some(vault.store.open_nonce),
    };
    queue.enqueue_with_id_in_txn(
        wtxn,
        id,
        EnqueueAttempt {
            kind: TAGGING_MARKER_KIND.to_owned(),
            payload: payload.encode()?,
            dedupe_key: Some(key),
            run_id: None,
            now: recorded_at,
        },
    )
}

/// Retries a leased marker in the caller's write transaction, under a
/// successor id derived from the try it retries, stamped at `input.now`.
///
/// The failed tries the trace history would keep stay in the ledger behind
/// the new one: the newest [`TaggingTraceHistory::per_turn`], none older
/// than [`TaggingTraceHistory::max_age_secs`]. The others are deleted and
/// counted by the kept try behind them, so backoff and try numbers read on,
/// a turn that keeps failing holds a bounded lineage, and its settlement
/// prunes a bounded one.
pub(super) fn retry_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: RetryAttempt,
) -> Result<()> {
    let source = input.id;
    let now = input.now;
    let id = free_id(vault, wtxn, MAX_RETRY_GENERATIONS, |generation| {
        derived_id(RETRY_ID_DOMAIN, &[source.as_bytes()], now, generation)
    })?;
    let queue = AttemptQueue::new(vault);
    queue.retry_with_id_in_txn(wtxn, input, id)?;
    let history = vault
        .config
        .tagging
        .as_ref()
        .map_or_else(TaggingTraceHistory::default, |tagging| {
            tagging.trace_history
        });
    queue.compact_retry_chain_in_txn(
        wtxn,
        id,
        usize::try_from(history.per_turn).unwrap_or(usize::MAX),
        now.saturating_sub(history.max_age_secs),
    )?;
    Ok(())
}

impl Vault {
    /// The live tagging marker owed for `turn` under the configured tagger,
    /// when one is pending: queued, leased or scheduled for its retry. A
    /// settled marker has left the job ledger, so `None` beside saved tags
    /// or a settling trace reads as settled, and `None` alone as never
    /// marked under the configured checkpoint. An unarmed vault has none.
    pub fn tagging_marker(&self, turn: &EntityId) -> Result<Option<AttemptRecord>> {
        let armed = self.tagging_marker_config();
        let Some(tagging) = armed.as_ref() else {
            return Ok(None);
        };
        let queue = AttemptQueue::from_store(&self.store);
        queue.pending_dedupe(TAGGING_MARKER_KIND, &dedupe_key(turn, tagging))
    }
}

/// The turn doors' half of the outbox rule (a base witness, an off-record
/// promotion): an armed vault owes the turn a tag pass at the class `work`
/// names, committed with the turn or not at all. It only writes the marker:
/// no tagger is called or waited on.
pub(crate) fn mark_turn_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    turn: EntityId,
    work: ExtractionWork,
) -> Result<()> {
    let marker = vault.tagging_marker_config();
    let Some(tagging) = marker.as_ref() else {
        return Ok(());
    };
    // Stamped from the store clock without persisting its floor, at every
    // door: the marker writes only the job tables, and the turn's own write
    // keeps its clock policy whether the vault is armed or not.
    let recorded_at = crate::ports::job_recorded_at_in_txn(&vault.store, wtxn)?;
    enqueue_marker_in_txn(vault, wtxn, turn, tagging, recorded_at, work).map(|_| ())
}

/// The type of an entity whose document text a turn's tag pass, vector or
/// sieve read reads: a MESSAGE or a TURN. `None` for any other entity. The
/// sieve reads on every vault, so a TURN's or MESSAGE's document write
/// compares its text whatever models are configured.
pub(crate) fn text_entity_type_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<u8>> {
    Ok(
        match crate::vault::live_entity_row_in_txn(&vault.store, txn, entity)? {
            crate::vault::LiveEntityRow::Live { entity_type, .. }
                if matches!(entity_type, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN) =>
            {
                Some(entity_type)
            }
            _ => None,
        },
    )
}

/// The class a publication owes its turns: bulk. A revision published at idle
/// and a document text write are no chat or voice commit.
const PUBLICATION_WORK: ExtractionWork = ExtractionWork::Bulk;

/// The indexer's half: a publication that moved the indexed frontier of a
/// TURN, or of a MESSAGE inside one, marks that turn again in the same
/// transaction, at the publication class. Both publishers call it: an entity
/// revision published at idle, and an entity document whose text a write
/// changed.
pub(crate) fn mark_on_publication_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    entity_type: u8,
) -> Result<()> {
    if vault.tagging_marker_config().is_none() {
        return Ok(());
    }
    match entity_type {
        ENTITY_TYPE_TURN => mark_turn_in_txn(vault, wtxn, *entity, PUBLICATION_WORK),
        ENTITY_TYPE_MESSAGE => {
            let turns = vault.filtered_edge_peers(
                wtxn,
                EdgeDirection::Out,
                entity,
                EdgeKind::PartOf,
                Some(ENTITY_TYPE_TURN),
            )?;
            for turn in turns {
                mark_turn_in_txn(vault, wtxn, turn, PUBLICATION_WORK)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
