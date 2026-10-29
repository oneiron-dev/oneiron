//! The rows a Dreamer attempt's inputs were read from, as its own readers
//! report them on its read set (FIX 7019, 7073). Capture only (FIX 7021): a
//! storage error recording them never ends the work, and the attempt's set
//! then reads as unknown.
use crate::Vault;
use crate::attempt_queue::{AttemptId, ReadSetProducer};
use crate::entity_id::EntityId;

/// Declares the producers `attempt` waits on, before any of them reads.
pub(crate) fn declare_attempt_reads(
    vault: &Vault,
    attempt: AttemptId,
    producers: &[ReadSetProducer],
) {
    if let Err(error) = vault.declare_attempt_read_producers(attempt, producers) {
        tracing::warn!(
            attempt = ?attempt,
            kind = ?error.kind(),
            "a Dreamer attempt could not declare its read set; its receipt keeps it unknown"
        );
    }
}

/// Records `rows` as `producer`'s report on `attempt`: the rows it read,
/// `None` when they are not known complete.
pub(crate) fn record_attempt_reads(
    vault: &Vault,
    attempt: AttemptId,
    producer: ReadSetProducer,
    rows: Option<Vec<EntityId>>,
) {
    if let Err(error) = vault.record_attempt_sources(attempt, producer, rows) {
        tracing::warn!(
            attempt = ?attempt,
            producer = producer.as_str(),
            kind = ?error.kind(),
            "a Dreamer attempt could not record its read set; its receipt keeps it unknown"
        );
        let _ = vault.record_attempt_sources(attempt, producer, None);
    }
}
