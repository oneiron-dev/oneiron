//! A bound session's replay append, on the run's one route, in one routed
//! transaction: the record compared against the generation its writer
//! expects, put, its heal tally when the turn healed, and the rows that
//! commit with it. On a stretch on record the record lands in base, so the
//! same writer runs the full replay fence first (FIX 9180, FIX 11392): a
//! copy read before an erase writes back its erased form, exactly as on the
//! owned path. An overlay row stays the room's own.

use std::borrow::Cow;

use super::super::records::{
    MODEL_HEAL_COUNTS, REPLAY_RECORDS, next_additive_heal_count, replay_generation_matches,
};
use super::super::response_erase::fence_replay_in_txn;
use super::*;
use crate::side_table::RoutedDbs;

impl SessionBinding<'_> {
    /// Compares and puts `record` along the route, with the heal tally of
    /// `healed_model` and the rows `also` writes, in one transaction; on
    /// base the record runs the full replay fence in that writer before its
    /// put (FIX 11392), exactly as the owned path does.
    ///
    /// # Errors
    ///
    /// The route's and the compare's refusals, and storage errors.
    pub(in crate::code_run::storage) fn put_replay_routed(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
        also: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>) -> Result<()>,
    ) -> Result<()> {
        if self.route.target() == RouteTarget::Base {
            return self
                .session
                .routed_side_txn(&self.route, |txn, read, write| {
                    let current = REPLAY_RECORDS.get(&read, &*txn, &record.run_id)?;
                    replay_generation_matches(current.as_ref(), expected)?;
                    let RoutedDbs::Base(vault) = write else {
                        return Err(crate::Error::InvariantViolation(
                            "a base route wrote outside base",
                        ));
                    };
                    let record = fence_replay_in_txn(vault, txn, Cow::Borrowed(record))?;
                    REPLAY_RECORDS.put(vault, txn, &record.run_id, &record)?;
                    if let Some(model) = healed_model {
                        let key = model.as_str().to_owned();
                        let base = MODEL_HEAL_COUNTS.get(&vault.store, txn, &key)?;
                        let (next, _) = next_additive_heal_count(base, None, RouteTarget::Base)?;
                        MODEL_HEAL_COUNTS.put(&vault.store, txn, &key, &next)?;
                    }
                    also(txn, write)
                });
        }
        match healed_model {
            Some(model) => self
                .session
                .side_table_compare_and_put_with_counter_routed_and(
                    &self.route,
                    &REPLAY_RECORDS,
                    &record.run_id,
                    record,
                    |current| replay_generation_matches(current, expected),
                    &MODEL_HEAL_COUNTS,
                    &model.as_str().to_owned(),
                    next_additive_heal_count,
                    also,
                )
                .map(drop),
            None => self
                .session
                .routed_side_txn(&self.route, |txn, read, write| {
                    let current = REPLAY_RECORDS.get(&read, &*txn, &record.run_id)?;
                    replay_generation_matches(current.as_ref(), expected)?;
                    REPLAY_RECORDS.put(&write, txn, &record.run_id, record)?;
                    also(txn, write)
                }),
        }
    }
}
