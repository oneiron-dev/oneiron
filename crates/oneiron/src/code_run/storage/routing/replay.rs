//! A bound session's replay append, on the run's one route, in one routed
//! transaction: the record compared against the generation its writer
//! expects, put, its heal tally when the turn healed, and the rows that
//! commit with it. On a stretch on record the record lands in base, so the
//! same writer runs the full replay fence first (FIX 9180, FIX 11392): a
//! copy read before an erase writes back its erased form, exactly as on the
//! owned path. An overlay row stays the room's own: it takes the fold-answer
//! fence through the room's composed view before its put (FIX 18924), on
//! the owned put as on the append.

use std::borrow::Cow;

use super::super::records::{
    MODEL_HEAL_COUNTS, REPLAY_RECORDS, next_additive_heal_count, replay_generation_matches,
};
use super::super::response_erase::fence_replay_in_txn;
use super::super::response_owners::stamp_response_owner_in_txn;
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
                    put_base_replay_in_txn(txn, read, write, record, expected, healed_model)?;
                    also(txn, write)
                });
        }
        // A fold answer whose words a withdrawal took keeps none in the
        // room's row either (FIX 18924).
        let fenced = self.composed_fold_answers(Cow::Borrowed(record))?;
        let record: &CodeRunReplayRecord = &fenced;
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

    /// [`Self::put_replay_record_if_generation_with_heal`] with no heal, as
    /// `actor`'s run `run`. On an on-record stretch the record lands in base,
    /// so the same transaction fences it and stamps its owner there, as the
    /// vault's put does (FIX 5718, 7429): an erase of `actor` finds the run
    /// by its owner row, and a write after that erase stays erased. An
    /// overlay row stamps its owner in the overlay, in the same writer, so
    /// the room's waits know whose run it is (FIX 6586). It also takes the
    /// fold-answer fence through the room's composed view before its put
    /// (FIX 18924): a withdrawn fold's answer never lands in the room's row.
    pub(in crate::code_run::storage) fn put_owned_replay_record_if_generation(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        run: EntityId,
        actor: EntityId,
    ) -> Result<CodeRunReplayGeneration> {
        use crate::side_table::RoutedDbs;
        REPLAY_RECORDS.encode_value(record)?;
        let next_generation = record.generation()?;
        let fenced = match self.route.target() {
            RouteTarget::Base => Cow::Borrowed(record),
            RouteTarget::Overlay | RouteTarget::Discard => {
                self.composed_fold_answers(Cow::Borrowed(record))?
            }
        };
        let overlay_record: &CodeRunReplayRecord = &fenced;
        self.answered(|| {
            self.session
                .routed_side_txn(&self.route, |wtxn, read, write| {
                    let current = REPLAY_RECORDS.get(&read, wtxn, &record.run_id)?;
                    replay_generation_matches(current.as_ref(), expected)?;
                    match write {
                        RoutedDbs::Base(vault) => {
                            stamp_response_owner_in_txn(vault, wtxn, record.run_id, run, actor)?;
                            let record = fence_replay_in_txn(vault, wtxn, Cow::Borrowed(record))?;
                            REPLAY_RECORDS.put(vault, wtxn, &record.run_id, &record)
                        }
                        RoutedDbs::Session(_) => {
                            stamp_response_owner_in_txn(&write, wtxn, record.run_id, run, actor)?;
                            REPLAY_RECORDS.put(&write, wtxn, &record.run_id, overlay_record)
                        }
                    }
                })
        })?;
        Ok(next_generation)
    }

    /// Appends a resumed record to base and retires the full keys that its
    /// writer changed from the sealed room, only after the base commit.
    pub(in crate::code_run::storage) fn put_base_replay_routed_retiring(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        also: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<Vec<Vec<u8>>>,
    ) -> Result<()> {
        self.session
            .routed_reader_txn(&self.route, |txn, read, write| {
                put_base_replay_in_txn(txn, read, write, record, expected, None)?;
                let mut keys = also(txn, read, write)?;
                keys.push(REPLAY_RECORDS.key_bytes(&record.run_id));
                Ok(((), keys))
            })
    }
}

fn put_base_replay_in_txn(
    txn: &mut heed::RwTxn<'_>,
    read: RoutedDbs<'_>,
    write: RoutedDbs<'_>,
    record: &CodeRunReplayRecord,
    expected: Option<CodeRunReplayGeneration>,
    healed_model: Option<&ModelId>,
) -> Result<()> {
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
    Ok(())
}
