//! FIX 6934: the rows an attempt's inputs were read from, recorded by the
//! host code that read them while the attempt runs and frozen onto its
//! terminal pack receipt. Capture only: nothing here admits, bounds or
//! refuses work.
//!
//! FIX 7073: the set is complete only when every producer the attempt's owner
//! declared reported at least once, none reported an unknown set and no
//! undeclared one reported; otherwise it reads as unknown.

use std::collections::BTreeSet;

use super::{AttemptId, AttemptQueue, AttemptRecord, decode_record};
use crate::Vault;
use crate::attempt_queue::source_rows::union_source_rows;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::attempt_sources::AttemptSources;

pub use crate::store::attempt_read_producer::ReadSetProducer;
pub use crate::store::attempt_record::AttemptReadSet;

impl AttemptReadSet {
    /// Nothing declared or read yet: a known, empty set.
    fn new() -> Self {
        Self {
            rows: Some(Vec::new()),
            native: BTreeSet::new(),
            expected: BTreeSet::new(),
            reported: BTreeSet::new(),
        }
    }
}

impl AttemptRecord {
    /// The complete set of rows this attempt's producers recorded its inputs
    /// read from. `None`, unknown, unless its owner declared producers and
    /// every one reported (FIX 7073); `None` too once any reported an unknown
    /// set or an undeclared one reported. A native component cannot be
    /// represented by this entity-only projection and also returns `None`.
    #[must_use]
    pub(crate) fn source_rows(&self) -> Option<&[EntityId]> {
        let set = self.read_set.as_ref()?;
        if set.expected.is_empty() || !set.expected.is_subset(&set.reported) {
            return None;
        }
        if !set.native.is_empty() {
            return None;
        }
        set.rows.as_deref()
    }

    /// The same completeness rule, retaining native family witnesses.
    pub(crate) fn sources(&self) -> Option<AttemptSources> {
        let set = self.read_set.as_ref()?;
        if set.expected.is_empty() || !set.expected.is_subset(&set.reported) {
            return None;
        }
        Some(AttemptSources {
            entities: set.rows.clone()?,
            native: set.native.clone(),
        })
    }
}

impl AttemptQueue<'_> {
    /// Widens the producers live attempt `id` expects to report, in the
    /// caller's transaction; a second declaration unions with the first.
    fn declare_attempt_read_producers_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        producers: &[ReadSetProducer],
    ) -> Result<bool> {
        self.change_read_set_in_txn(txn, id, |set| {
            for producer in producers {
                set.expected.insert(producer.as_str().to_owned());
            }
        })
    }

    /// Unions `rows` into the read set of live attempt `id` as `producer`'s
    /// report, in the caller's transaction. A second report unions with the
    /// first; an unknown set keeps the whole set unknown, and so does a
    /// report from a producer the owner never declared, which means the
    /// declaration missed a reader.
    fn record_attempt_sources_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        producer: ReadSetProducer,
        sources: Option<AttemptSources>,
    ) -> Result<bool> {
        self.change_read_set_in_txn(txn, id, |set| {
            let declared = set.expected.contains(producer.as_str());
            let sources = sources.filter(|_| declared);
            let rows = sources.map(|sources| {
                set.native.extend(sources.native);
                sources.entities
            });
            set.rows = union_source_rows([set.rows.take(), rows]);
            set.reported.insert(producer.as_str().to_owned());
        })
    }

    /// Applies `change` to live attempt `id`'s read set and writes it back.
    /// `false` when no live attempt is `id`: a closed attempt's receipt is
    /// already minted, so nothing is recorded.
    fn change_read_set_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        change: impl FnOnce(&mut AttemptReadSet),
    ) -> Result<bool> {
        let Some(raw_record) = self.store.attempt_records.get(txn, id.as_bytes())? else {
            return Ok(false);
        };
        let mut record = decode_record(&raw_record, id)?;
        if !record.state.is_pending() {
            return Ok(false);
        }
        change(record.read_set.get_or_insert_with(AttemptReadSet::new));
        let encoded = self.encode_in_txn(txn, &mut record)?;
        self.store
            .attempt_records
            .put(txn, record.id.as_bytes(), &encoded)?;
        Ok(true)
    }
}

impl Vault {
    /// Declares the producers expected to report attempt `attempt`'s read
    /// set (FIX 7073). The attempt's owner calls it while the attempt is
    /// pending, before any declared producer's inputs are consumed; a second
    /// declaration widens the first. Until every declared producer reported,
    /// the set reads as unknown. `false` when no live attempt is `attempt`,
    /// and nothing is declared.
    pub fn declare_attempt_read_producers(
        &self,
        attempt: AttemptId,
        producers: &[ReadSetProducer],
    ) -> Result<bool> {
        self.with_write_txn_grouped(|txn| {
            AttemptQueue::new(self).declare_attempt_read_producers_in_txn(txn, attempt, producers)
        })
    }

    /// [`Self::declare_attempt_read_producers`] inside a writer's `txn`, best
    /// effort (FIX 7119): it writes in a savepoint of `txn`, as FIX 6667's
    /// step masking does, so the carrying write is never failed or rolled
    /// back by the declaration. An error aborts only the savepoint. A failed
    /// declare stays safe: a producer that reports without a declaration
    /// marks the set unknown, as an empty declaration does. It logs one WARN
    /// and returns `false`; `false` too when no live attempt is `attempt`.
    pub fn declare_attempt_read_producers_best_effort_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        producers: &[ReadSetProducer],
    ) -> bool {
        match self.declare_attempt_read_producers_in_savepoint(txn, attempt, producers) {
            Ok(declared) => declared,
            Err(error) => {
                tracing::warn!(
                    attempt = ?attempt,
                    kind = ?error.kind(),
                    %error,
                    "an attempt's read producers could not be declared; the set stays unknown"
                );
                false
            }
        }
    }

    /// One declare in a savepoint of `txn` that commits only when it lands.
    fn declare_attempt_read_producers_in_savepoint(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        producers: &[ReadSetProducer],
    ) -> Result<bool> {
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let declared = AttemptQueue::new(self).declare_attempt_read_producers_in_txn(
            &mut savepoint,
            attempt,
            producers,
        )?;
        savepoint.commit()?;
        Ok(declared)
    }

    /// Records the rows `producer` read attempt `attempt`'s inputs from
    /// (FIX 6934): the ids of the rows it actually read, never ids a caller
    /// named. Pass `None` when the set read is not known complete; it keeps
    /// the attempt's whole set unknown, as a report from a producer the
    /// owner never declared does (FIX 7073). `false` when no live attempt is
    /// `attempt`, and nothing is recorded.
    pub fn record_attempt_sources(
        &self,
        attempt: AttemptId,
        producer: ReadSetProducer,
        rows: Option<Vec<EntityId>>,
    ) -> Result<bool> {
        self.record_attempt_read_sources(attempt, producer, rows.map(AttemptSources::entities))
    }

    /// Records a complete typed report from the original producer. `None`
    /// poisons completeness exactly as the entity-only entrypoint does.
    pub fn record_attempt_read_sources(
        &self,
        attempt: AttemptId,
        producer: ReadSetProducer,
        sources: Option<AttemptSources>,
    ) -> Result<bool> {
        self.with_write_txn_grouped(|txn| {
            AttemptQueue::new(self).record_attempt_sources_in_txn(txn, attempt, producer, sources)
        })
    }

    /// [`Self::record_attempt_sources`] inside a writer's `txn`, best effort
    /// (FIX 7073): it writes in a savepoint of `txn`, as FIX 6667's step
    /// masking does, so the carrying write is never failed or rolled back by
    /// the capture. An error aborts only the savepoint. A second savepoint
    /// then reports `None` for `producer`, so an earlier report of its
    /// cannot read as complete (FIX 7021); if that fails too, `producer`'s
    /// report stays missing or unknown, and the set unknown either way. It
    /// logs one WARN and returns `false`; `false` too when no live attempt
    /// is `attempt`.
    pub fn record_attempt_sources_best_effort_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        producer: ReadSetProducer,
        rows: Option<Vec<EntityId>>,
    ) -> bool {
        self.record_attempt_read_sources_best_effort_in_txn(
            txn,
            attempt,
            producer,
            rows.map(AttemptSources::entities),
        )
    }

    /// The typed report through the same best-effort savepoint and unknown fallback.
    pub fn record_attempt_read_sources_best_effort_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        producer: ReadSetProducer,
        sources: Option<AttemptSources>,
    ) -> bool {
        match self.record_attempt_sources_in_savepoint(txn, attempt, producer, sources) {
            Ok(recorded) => recorded,
            Err(error) => {
                let marked_unknown = self
                    .record_attempt_sources_in_savepoint(txn, attempt, producer, None)
                    .is_ok();
                tracing::warn!(
                    attempt = ?attempt,
                    producer = producer.as_str(),
                    kind = ?error.kind(),
                    %error,
                    marked_unknown,
                    "an attempt's read set could not be recorded; its receipt keeps it unknown"
                );
                false
            }
        }
    }

    /// One record in a savepoint of `txn` that commits only when it lands.
    fn record_attempt_sources_in_savepoint(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        producer: ReadSetProducer,
        sources: Option<AttemptSources>,
    ) -> Result<bool> {
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let recorded = AttemptQueue::new(self).record_attempt_sources_in_txn(
            &mut savepoint,
            attempt,
            producer,
            sources,
        )?;
        savepoint.commit()?;
        Ok(recorded)
    }
}
