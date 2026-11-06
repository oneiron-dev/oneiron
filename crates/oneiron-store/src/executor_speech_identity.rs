//! The deterministic ids of a durable executor run's speech turn and
//! compaction session, and the domain-tagged derivation they share. The code
//! run layer (`code_run`) derives its conversation, turn and message ids with
//! it; the store's compaction packet source finds a run's session and turn.
use sha2::{Digest, Sha256};

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

const EXECUTOR_SPEECH_TURN_DOMAIN: &[u8] = b"oneiron:executor-speech-turn:v1";

/// Domain tag for a run's compaction session.
const EXECUTOR_COMPACTION_SESSION_DOMAIN: &[u8] = b"oneiron:executor-compaction-session:v1";

/// Derives one deterministic entity id from a domain tag and length-prefixed
/// material, re-salting past a reserved sentinel rather than truncating into
/// one.
pub fn derived_executor_id(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
    for salt in 0..=u8::MAX {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update([salt]);
        for part in parts {
            let len = u64::try_from(part.len())
                .map_err(|_| Error::ArithmeticOverflow("executor speech id material"))?;
            hasher.update(len.to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "executor speech id derivation failed",
    ))
}

/// The turn one run's speech appends to.
///
/// ONE turn per run, not one per utterance: a TURN is the maximal consecutive
/// run of ONE speaker, and every bubble a run emits is the same Companion. The
/// bubbles' own `order` values carry the interleaving.
pub fn executor_speech_turn_id(run_ref: &str, run_id: Option<EntityId>) -> Result<EntityId> {
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_TURN_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes()],
        ),
        None => derived_executor_id(EXECUTOR_SPEECH_TURN_DOMAIN, &[run_ref.as_bytes()]),
    }
}

/// The compaction session of one durable run (agent-runtime-v1 §d7).
///
/// A run's REPL window is its own session: one log, one epoch lineage, its
/// steps as the turns. The ref is derived, never minted, so a resumed run
/// (same run ref, same credential scope) re-enters its lineage and no other
/// run can address it.
pub fn executor_compaction_session_id(run_ref: &str, run_id: EntityId) -> Result<EntityId> {
    derived_executor_id(
        EXECUTOR_COMPACTION_SESSION_DOMAIN,
        &[run_ref.as_bytes(), run_id.as_bytes()],
    )
}

/// The speech TURN of a canonical durable run, whether or not it spoke yet.
pub fn executor_speech_turn_id_for_run(run_ref: &str, run_id: EntityId) -> Result<EntityId> {
    executor_speech_turn_id(run_ref, Some(run_id))
}
