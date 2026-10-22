//! A chat reply's typed assertions (OF-063, FIX 3416, Engine ruling (a)):
//! the records the reply cited or created, gathered host-side while it runs.
//!
//! Only trusted host code adds to a reply's collector: a typed tool citation
//! the host served for this reply, and a record a write made for it once
//! that write committed, never one requested, queued or refused. Nothing
//! here reads the model's text, a provider's list, the rows the request was
//! assembled from or a read set. The producer stamps the reply's terminal
//! with what was gathered, replacing whatever the terminal carried, and the
//! ledger plane hands that to the MESSAGE's finalize, which judges each id
//! under the agent's own read and keeps the set it admits. A reply that ran
//! no tool and committed no creation asserts nothing. Continue and Retry
//! each start a collector of their own.

use std::sync::{Arc, Mutex};

use oneiron::lens::RecordRef;
use oneiron::llm::{ReplyAssertionRecord, ReplyAssertions};
use oneiron::memory::WitnessAssertions;
use oneiron::{EntityId, LlmStreamEvent};

/// The records one reply gathers. Clones share them.
#[derive(Clone, Default)]
pub(crate) struct ReplyAssertionCollector(Arc<Mutex<ReplyAssertions>>);

impl ReplyAssertionCollector {
    /// Notes a record a typed tool citation named for this reply.
    #[expect(
        dead_code,
        reason = "a chat reply runs no tool yet; its first typed tool citation notes here"
    )]
    pub(crate) fn cited(&self, entity_type: u8, id: EntityId) {
        if let Ok(mut gathered) = self.0.lock() {
            gathered.cite(ReplyAssertionRecord { entity_type, id });
        }
    }

    /// Notes a record a write made for this reply. Called only once that
    /// write committed.
    #[expect(
        dead_code,
        reason = "a chat reply commits no creation yet; its first creation receipt notes here"
    )]
    pub(crate) fn created(&self, entity_type: u8, id: EntityId) {
        if let Ok(mut gathered) = self.0.lock() {
            gathered.create(ReplyAssertionRecord { entity_type, id });
        }
    }

    /// `event`, a terminal carrying this reply's gathered records and no
    /// other: whatever records it came with are dropped. Any other event
    /// passes as it came.
    pub(super) fn stamp(&self, event: LlmStreamEvent) -> LlmStreamEvent {
        match event {
            LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
                ..
            } => LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
                reply_assertions: self.gathered(),
            },
            event => event,
        }
    }

    fn gathered(&self) -> ReplyAssertions {
        match self.0.lock() {
            Ok(gathered) => gathered.clone(),
            // A collector a panic poisoned names nothing: no record is
            // invented.
            Err(_) => ReplyAssertions::default(),
        }
    }
}

/// A terminal's records as the witness's typed assertions: each named by its
/// entity type and id, labelled with its kind alone. The id is what the
/// finalize admits; the label is display only.
pub(super) fn witness_assertions(carrier: &ReplyAssertions) -> WitnessAssertions {
    WitnessAssertions {
        cited: record_refs(&carrier.cited),
        created: record_refs(&carrier.created),
    }
}

fn record_refs(records: &[ReplyAssertionRecord]) -> Vec<RecordRef> {
    records
        .iter()
        .map(|record| RecordRef::from_id(record.entity_type, &record.id, None))
        .collect()
}
