//! A bound session's replay append, on the run's one route, in one routed
//! transaction: the record compared against the generation its writer
//! expects, put, its heal tally when the turn healed, and the rows that
//! commit with it. On a stretch on record the record lands in base, so the
//! same writer runs the full replay fence first (FIX 9180, FIX 11392): a
//! copy read before an erase writes back its erased form, exactly as on the
//! owned path. An overlay row stays the room's own: it takes the fold-answer
//! fence through the room's composed view before its put (FIX 18924), on
//! the owned put as on the append, and lands erased in that writer when the
//! actor of its run is gone in the vault (FIX 7366).

use std::borrow::Cow;

use super::super::overlay_erase::fence_overlay_replay_in_txn;
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
        self.put_replay_routed_prepared(record, expected, healed_model, |_, _, _| Ok(()), also)
    }

    /// [`Self::put_replay_routed`] with `prepare`'s rows written in the same
    /// writer after the generation check. It is given the composed view and
    /// the route's write. On base it runs before the replay fence, as the
    /// owned path's prepared seam does (FIX 6592): a body published there is
    /// one the fence releases in that writer. An overlay row takes no replay
    /// fence, only the room's gone-actor one (FIX 7366), so with a heal tally
    /// `prepare` runs after the record's put.
    ///
    /// # Errors
    ///
    /// The route's and the compare's refusals, `prepare`'s and `also`'s,
    /// and storage errors.
    pub(in crate::code_run::storage) fn put_replay_routed_prepared(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
        prepare: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<()>,
        also: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>) -> Result<()>,
    ) -> Result<()> {
        if self.route.target() == RouteTarget::Base {
            return self
                .session
                .routed_side_txn(&self.route, |txn, read, write| {
                    put_base_replay_in_txn(
                        txn,
                        read,
                        write,
                        record,
                        expected,
                        healed_model,
                        prepare,
                    )?;
                    also(txn, write)
                });
        }
        // A fold answer whose words a withdrawal took keeps none in the
        // room's row either (FIX 18924).
        let fenced = self.composed_fold_answers(Cow::Borrowed(record))?;
        let record: &CodeRunReplayRecord = &fenced;
        // An overlay record of a run whose actor is gone lands erased, in
        // the same writer (FIX 7366).
        let run_id = record.run_id;
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
                    |txn, write| {
                        // The helper put `record`; its erased form, when it
                        // is one, replaces it in the same segment.
                        let fenced =
                            fence_overlay_replay_in_txn(&write, txn, Cow::Borrowed(record), None)?;
                        if let Cow::Owned(erased) = fenced {
                            REPLAY_RECORDS.put(&write, txn, &run_id, &erased)?;
                        }
                        prepare(txn, write, write)?;
                        also(txn, write)
                    },
                )
                .map(drop),
            None => self
                .session
                .routed_side_txn(&self.route, |txn, read, write| {
                    let current = REPLAY_RECORDS.get(&read, &*txn, &record.run_id)?;
                    replay_generation_matches(current.as_ref(), expected)?;
                    prepare(txn, read, write)?;
                    let record =
                        fence_overlay_replay_in_txn(&write, txn, Cow::Borrowed(record), None)?;
                    REPLAY_RECORDS.put(&write, txn, &run_id, &record)?;
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
    /// (FIX 18924): a withdrawn fold's answer never lands in the room's row;
    /// and it lands erased when `actor` is gone in the vault (FIX 7366).
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
                            let record = fence_overlay_replay_in_txn(
                                &write,
                                wtxn,
                                Cow::Borrowed(overlay_record),
                                Some((run, actor)),
                            )?;
                            REPLAY_RECORDS.put(&write, wtxn, &record.run_id, &record)
                        }
                    }
                })
        })?;
        Ok(next_generation)
    }

    /// Appends a resumed record to base and retires the full keys that its
    /// writer changed from the sealed room, only after the base commit.
    /// `prepare`'s rows are written in that writer before the replay fence,
    /// as [`Self::put_replay_routed_prepared`] writes them on base (FIX 6592).
    pub(in crate::code_run::storage) fn put_base_replay_routed_retiring(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        prepare: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<()>,
        also: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<Vec<Vec<u8>>>,
    ) -> Result<()> {
        self.session
            .routed_reader_txn(&self.route, |txn, read, write| {
                put_base_replay_in_txn(txn, read, write, record, expected, None, prepare)?;
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
    prepare: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<()>,
) -> Result<()> {
    let current = REPLAY_RECORDS.get(&read, &*txn, &record.run_id)?;
    replay_generation_matches(current.as_ref(), expected)?;
    let RoutedDbs::Base(vault) = write else {
        return Err(crate::Error::InvariantViolation(
            "a base route wrote outside base",
        ));
    };
    prepare(txn, read, write)?;
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
