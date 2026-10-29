//! FIX 6934: the rows an attempt's inputs were read from, recorded by the
//! host code that read them while the attempt runs and frozen onto its
//! terminal pack receipt. Capture only: nothing here admits, bounds or
//! refuses work.
//!
//! FIX 7073: the set is complete only when every producer the attempt's owner
//! declared reported at least once, none reported an unknown set and no
//! undeclared one reported; otherwise it reads as unknown.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{AttemptId, AttemptQueue, AttemptRecord, decode_record};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill_optimize::union_source_rows;

/// One host producer that reads some of an attempt's inputs and reports
/// their rows (FIX 7073), kept on the record as its key. Each producer is
/// one constant here, so no two share a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadSetProducer(&'static str);

impl ReadSetProducer {
    /// The Coach's training-offer draft: its brief, the offer skill's body
    /// and the pilots its draft grounds on.
    pub const COACH_OFFER_DRAFT: Self = Self("coach.offer_draft");

    /// The skill pack load door: the SKILL whose instructions loaded and the
    /// replicated carrier its package was recovered from (FIX 7017).
    pub const SKILL_PACK: Self = Self("skill.pack_load");

    /// The actor claim load door: each actor CLAIM a run loaded (FIX 7017).
    pub const ACTOR_CLAIM: Self = Self("actor.claim_load");

    /// A resident run's tool answers: the rows each verb answer listed as
    /// served (FIX 7017).
    pub const TOOL_ANSWERS: Self = Self("resident.tool_answers");

    /// A Dreamer weave recipe's evidence: the one row its draft reads
    /// (FIX 7019).
    pub const DREAMER_RECIPE_EVIDENCE: Self = Self("dreamer.recipe_evidence");

    /// A Dreamer weave lens render's period: the rows its stored report's
    /// items were read from (FIX 7019).
    pub const DREAMER_WEAVE_REPORT: Self = Self("dreamer.weave_report");

    /// A Dreamer consolidation branch's extraction: each slice's TURNs,
    /// conversations, projected MESSAGEs and the listed rows its page
    /// shows (FIX 7019).
    pub const DREAMER_EXTRACTION: Self = Self("dreamer.extraction");

    /// The Coach's eval-authoring pass: the inventory it read and the
    /// authoring skill's body (FIX 7019).
    pub const COACH_EVAL_AUTHORING: Self = Self("coach.eval_authoring");

    /// The key the record keeps.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// What an attempt's producers recorded of the rows its inputs were read
/// from. `rows` is the union of their reports, sorted and deduplicated;
/// `Some([])` when they read no vault row; `None`, unknown, once any
/// producer reported an unknown set or a producer reported undeclared.
/// `expected` holds the producers the owner declared, `reported` the ones
/// that reported (FIX 7073). An attempt no producer declared or recorded
/// keeps no read set at all, which its receipt keeps as unknown too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptReadSet {
    pub rows: Option<Vec<EntityId>>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub expected: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub reported: BTreeSet<String>,
}

impl AttemptReadSet {
    /// Nothing declared or read yet: a known, empty set.
    fn new() -> Self {
        Self {
            rows: Some(Vec::new()),
            expected: BTreeSet::new(),
            reported: BTreeSet::new(),
        }
    }
}

impl AttemptRecord {
    /// The complete set of rows this attempt's producers recorded its inputs
    /// read from. `None`, unknown, unless its owner declared producers and
    /// every one reported (FIX 7073); `None` too once any reported an unknown
    /// set or an undeclared one reported.
    #[must_use]
    pub(crate) fn source_rows(&self) -> Option<&[EntityId]> {
        let set = self.read_set.as_ref()?;
        if set.expected.is_empty() || !set.expected.is_subset(&set.reported) {
            return None;
        }
        set.rows.as_deref()
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
        rows: Option<Vec<EntityId>>,
    ) -> Result<bool> {
        self.change_read_set_in_txn(txn, id, |set| {
            let declared = set.expected.contains(producer.as_str());
            set.rows = union_source_rows([set.rows.take(), rows.filter(|_| declared)]);
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
        self.with_write_txn_grouped(|txn| {
            AttemptQueue::new(self).record_attempt_sources_in_txn(txn, attempt, producer, rows)
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
        match self.record_attempt_sources_in_savepoint(txn, attempt, producer, rows) {
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
        rows: Option<Vec<EntityId>>,
    ) -> Result<bool> {
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let recorded = AttemptQueue::new(self).record_attempt_sources_in_txn(
            &mut savepoint,
            attempt,
            producer,
            rows,
        )?;
        savepoint.commit()?;
        Ok(recorded)
    }
}
