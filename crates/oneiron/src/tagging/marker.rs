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

/// Arms the tagging marker on a vault ([`crate::VaultConfig::tagging`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggingMarkerConfig {
    /// The active tagger's checkpoint identity: the first 16 lowercase hex
    /// digits of the SHA-256 of its weights. Half of every marker's dedupe
    /// key, so a new checkpoint owes every turn a new pass.
    pub checkpoint: String,
}

impl TaggingMarkerConfig {
    /// A validated marker configuration.
    pub fn new(checkpoint: impl Into<String>) -> Result<Self> {
        let config = Self {
            checkpoint: checkpoint.into(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Refuses a checkpoint that is not 16 lowercase hex digits.
    pub fn validate(&self) -> Result<()> {
        if is_checkpoint(&self.checkpoint) {
            Ok(())
        } else {
            Err(Error::InvalidConfig(
                "tagging checkpoint must be 16 lowercase hex digits".to_owned(),
            ))
        }
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

/// The marker id is the store-clock second it was committed at, then a digest
/// of what it names. Committing one, or a retry of one, draws nothing from the
/// vault's id source, so a write allocates the same entity ids with or without
/// a tagger, and the readiness index still drains markers in commit order
/// across seconds.
fn derived_id(
    turn: &EntityId,
    checkpoint: &str,
    recorded_at: u64,
    generation: u32,
) -> Result<AttemptId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MARKER_ID_DOMAIN);
    hasher.update(turn.as_bytes());
    hasher.update(checkpoint.as_bytes());
    hasher.update(&generation.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&recorded_at.to_be_bytes());
    bytes[8..].copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    AttemptId::from_bytes(&bytes)
}

fn free_marker_id(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    turn: &EntityId,
    checkpoint: &str,
    recorded_at: u64,
) -> Result<AttemptId> {
    for generation in 0..MAX_MARKER_GENERATIONS {
        let id = derived_id(turn, checkpoint, recorded_at, generation)?;
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
    let id = free_marker_id(vault, wtxn, &turn, checkpoint, recorded_at)?;
    let payload = MarkerPayload {
        turn,
        checkpoint: checkpoint.to_owned(),
    };
    AttemptQueue::from_store(&vault.store).enqueue_with_id_in_txn(
        wtxn,
        id,
        EnqueueAttempt {
            kind: TAGGING_MARKER_KIND.to_owned(),
            payload: payload.encode()?,
            dedupe_key: Some(dedupe_key(&turn, checkpoint)),
            run_id: None,
            now: recorded_at,
        },
    )
}

/// Retries a leased marker in the caller's write transaction, under a
/// successor id derived as a new marker's is, stamped at `input.now`.
pub(super) fn retry_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    payload: &MarkerPayload,
    input: RetryAttempt,
) -> Result<()> {
    let id = free_marker_id(vault, wtxn, &payload.turn, &payload.checkpoint, input.now)?;
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
