//! The marker row: its kind, payload, dedupe key, derived id and the
//! in-transaction doors that commit it.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue, EnqueueAttempt, EnqueueOutcome, RetryAttempt};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::EdgeDirection;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::{EntityId, Vault};

/// Attempt kind of a tagging marker in the job tables.
pub const TAGGING_MARKER_KIND: &str = "oneironer.tag_turn";

const CHECKPOINT_HEX_LEN: usize = 16;
const MARKER_ID_DOMAIN: &[u8] = b"oneiron.tagging.marker.v1\0";
/// Probes for a free derived id: one per earlier marker of the same turn and
/// checkpoint committed in the same second.
const MAX_MARKER_GENERATIONS: u32 = 4096;
const RETRY_ID_DOMAIN: &[u8] = b"oneiron.tagging.retry.v1\0";
/// Probes for a free retry id: its digest names the try it retries, which
/// has one successor, so only a chance collision needs another.
const MAX_RETRY_GENERATIONS: u32 = 16;

/// The live window's default size in tagger tokens: the serving runtime's
/// `LIVE_K`, the earlier context a live turn is tagged with.
pub const DEFAULT_LIVE_WINDOW_TOKENS: u32 = 256;
/// The largest live window: the serving runtime's whole input window.
pub const MAX_LIVE_WINDOW_TOKENS: u32 = 2_048;
/// Traces kept per turn by default: the turn's latest few attempts.
pub const DEFAULT_TRACES_PER_TURN: u32 = 4;
/// The most traces a turn may keep.
pub const MAX_TRACES_PER_TURN: u32 = 1_024;
/// How long a trace is kept by default, in store-clock seconds: seven days.
pub const DEFAULT_TRACE_MAX_AGE_SECS: u64 = 7 * 86_400;

/// How much tagging history a vault keeps. A settled marker leaves the job
/// ledger with every try it retried; what stays is its traces, bounded here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggingTraceHistory {
    /// Traces kept per turn, the newest; 0 keeps none.
    pub per_turn: u32,
    /// Store-clock seconds a trace is kept; an older one is pruned.
    pub max_age_secs: u64,
}

impl Default for TaggingTraceHistory {
    fn default() -> Self {
        Self {
            per_turn: DEFAULT_TRACES_PER_TURN,
            max_age_secs: DEFAULT_TRACE_MAX_AGE_SECS,
        }
    }
}

/// Arms the tagging marker on a vault ([`crate::VaultConfig::tagging`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggingMarkerConfig {
    /// The active tagger's checkpoint identity: the first 16 lowercase hex
    /// digits of the SHA-256 of its weights. Half of every marker's dedupe
    /// key, so a new checkpoint owes every turn a new pass.
    pub checkpoint: String,
    /// The live window, in the tagger's tokens: a turn is tagged with up to
    /// this much earlier text of its conversation, and never a later turn.
    /// 0 sends the turn alone.
    pub live_window_tokens: u32,
    /// The traces kept once their markers leave the job ledger.
    pub trace_history: TaggingTraceHistory,
}

impl TaggingMarkerConfig {
    /// A validated marker configuration, with the default live window and
    /// trace history.
    pub fn new(checkpoint: impl Into<String>) -> Result<Self> {
        let config = Self {
            checkpoint: checkpoint.into(),
            live_window_tokens: DEFAULT_LIVE_WINDOW_TOKENS,
            trace_history: TaggingTraceHistory::default(),
        };
        config.validate()?;
        Ok(config)
    }

    #[must_use]
    pub fn with_live_window_tokens(mut self, tokens: u32) -> Self {
        self.live_window_tokens = tokens;
        self
    }

    #[must_use]
    pub fn with_trace_history(mut self, history: TaggingTraceHistory) -> Self {
        self.trace_history = history;
        self
    }

    /// Refuses a checkpoint that is not 16 lowercase hex digits, a live
    /// window past the runtime's input window, and a trace history past its
    /// bounds or with no age.
    pub fn validate(&self) -> Result<()> {
        let invalid = |reason: &str| Err(Error::InvalidConfig(reason.to_owned()));
        if !is_checkpoint(&self.checkpoint) {
            return invalid("tagging checkpoint must be 16 lowercase hex digits");
        }
        if self.live_window_tokens > MAX_LIVE_WINDOW_TOKENS {
            return invalid("tagging live window must be at most 2048 tokens");
        }
        if self.trace_history.per_turn > MAX_TRACES_PER_TURN {
            return invalid("tagging trace history keeps at most 1024 traces per turn");
        }
        if self.trace_history.max_age_secs == 0 {
            return invalid("tagging trace history max age must be greater than zero");
        }
        Ok(())
    }
}

pub(super) fn is_checkpoint(value: &str) -> bool {
    value.len() == CHECKPOINT_HEX_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// What one marker names: a turn owed one pass by one tagger checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MarkerPayload {
    pub(super) turn: EntityId,
    pub(super) checkpoint: String,
}

impl MarkerPayload {
    fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvariantViolation("tagging marker payload encoding"))
    }

    /// `None` for a payload this build cannot read; its marker is failed, not
    /// retried, because no pass can ever read it.
    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        rmp_serde::from_slice::<Self>(bytes)
            .ok()
            .filter(|payload| is_checkpoint(&payload.checkpoint))
    }
}

pub(super) fn dedupe_key(turn: &EntityId, checkpoint: &str) -> String {
    format!("{}@{checkpoint}", turn.to_hex())
}

/// The marker id is the owner-retained prefix, the low seven bytes of the
/// store-clock second it was committed at, then a digest of what it names: a
/// new marker's digest names its turn and checkpoint, a retry's names the try
/// it retries, so a long retry history takes none of the ids a new marker of
/// the turn needs. Committing either draws nothing from the vault's id
/// source, so a write allocates the same entity ids with or without a tagger;
/// the readiness index still drains markers in commit order across seconds;
/// and every marker sits in the ledger's owner-retained range, which no scan
/// of another job kind reads.
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
        if vault
            .store
            .attempt_records
            .get(wtxn, id.as_bytes())?
            .is_none()
        {
            return Ok(id);
        }
    }
    Err(Error::IndexOverflow("tagging marker generations"))
}

/// Commits a marker for `turn` under `checkpoint` in the caller's write
/// transaction, stamped at `recorded_at`. A live marker for the same pair
/// absorbs the call.
pub(super) fn enqueue_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    turn: EntityId,
    checkpoint: &str,
    recorded_at: u64,
) -> Result<EnqueueOutcome> {
    let queue = AttemptQueue::from_store(&vault.store);
    let key = dedupe_key(&turn, checkpoint);
    // A live marker absorbs the call before any id is drawn for it.
    if let Some(live) = queue.pending_dedupe_in_txn(wtxn, TAGGING_MARKER_KIND, &key)? {
        return Ok(EnqueueOutcome::Existing(live));
    }
    let id = free_id(vault, wtxn, MAX_MARKER_GENERATIONS, |generation| {
        derived_id(
            MARKER_ID_DOMAIN,
            &[turn.as_bytes(), checkpoint.as_bytes()],
            recorded_at,
            generation,
        )
    })?;
    let payload = MarkerPayload {
        turn,
        checkpoint: checkpoint.to_owned(),
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
pub(super) fn retry_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: RetryAttempt,
) -> Result<()> {
    let source = input.id;
    let id = free_id(vault, wtxn, MAX_RETRY_GENERATIONS, |generation| {
        derived_id(RETRY_ID_DOMAIN, &[source.as_bytes()], input.now, generation)
    })?;
    AttemptQueue::from_store(&vault.store).retry_with_id_in_txn(wtxn, input, id)?;
    Ok(())
}

/// The turn doors' half of the outbox rule (a base witness, an off-record
/// promotion): an armed vault owes the turn a tag pass, committed with the
/// turn or not at all.
pub(crate) fn mark_turn_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    turn: EntityId,
) -> Result<()> {
    let Some(tagging) = vault.config.tagging.as_ref() else {
        return Ok(());
    };
    // Stamped from the store clock without persisting its floor, at every
    // door: the marker writes only the job tables, and the turn's own write
    // keeps its clock policy whether the vault is armed or not.
    let recorded_at = crate::ports::job_recorded_at_in_txn(&vault.store, wtxn)?;
    enqueue_marker_in_txn(vault, wtxn, turn, &tagging.checkpoint, recorded_at).map(|_| ())
}

/// The type of an entity whose document text a turn's tag pass reads, on an
/// armed vault: a MESSAGE or a TURN. `None` for any other entity, and on a
/// vault with no tagger, so a document write there compares no text.
/// Entity documents exist only on a sync build.
#[cfg(feature = "sync")]
pub(crate) fn text_entity_type_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<u8>> {
    if vault.config.tagging.is_none() {
        return Ok(None);
    }
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

/// The indexer's half: a publication that moved the indexed frontier of a
/// TURN, or of a MESSAGE inside one, marks that turn again in the same
/// transaction. Both publishers call it: an entity revision published at
/// idle, and an entity document whose text a write changed.
pub(crate) fn mark_on_publication_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    entity_type: u8,
) -> Result<()> {
    if vault.config.tagging.is_none() {
        return Ok(());
    }
    match entity_type {
        ENTITY_TYPE_TURN => mark_turn_in_txn(vault, wtxn, *entity),
        ENTITY_TYPE_MESSAGE => {
            let turns = vault.filtered_edge_peers(
                wtxn,
                EdgeDirection::Out,
                entity,
                EdgeKind::PartOf,
                Some(ENTITY_TYPE_TURN),
                "tagging frontier turns",
            )?;
            for turn in turns {
                mark_turn_in_txn(vault, wtxn, turn)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
