//! The deterministic ids of a durable executor run's speech turn and
//! compaction session, and the domain-tagged derivation they share. The code
//! run layer (`code_run`) derives its conversation, turn and message ids with
//! it; the store's compaction packet source finds a run's session and turn.
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::{
    EXECUTOR_COMPACTION_SESSION, EXECUTOR_SPEECH_TURN,
};

/// Derives one deterministic entity id from a registered domain and its
/// parts by the one derived-id rule, [`EntityId::derive`] (FIX 9711): a
/// result in the reserved range is refused, never re-salted.
pub fn derived_executor_id(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
    EntityId::derive(domain, parts)
}

/// The turn one run's speech appends to.
///
/// ONE turn per run, not one per utterance: a TURN is the maximal consecutive
/// run of ONE speaker, and every bubble a run emits is the same Companion. The
/// bubbles' own `order` values carry the interleaving.
pub fn executor_speech_turn_id(run_ref: &str, run_id: Option<EntityId>) -> Result<EntityId> {
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_TURN,
            &[run_ref.as_bytes(), run_id.as_bytes()],
        ),
        None => derived_executor_id(EXECUTOR_SPEECH_TURN, &[run_ref.as_bytes()]),
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
        EXECUTOR_COMPACTION_SESSION,
        &[run_ref.as_bytes(), run_id.as_bytes()],
    )
}

/// The speech TURN of a canonical durable run, whether or not it spoke yet.
pub fn executor_speech_turn_id_for_run(run_ref: &str, run_id: EntityId) -> Result<EntityId> {
    executor_speech_turn_id(run_ref, Some(run_id))
}
