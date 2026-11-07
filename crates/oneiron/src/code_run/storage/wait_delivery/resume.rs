//! The commit of a run resumed from a wait's reply: its replay record, the
//! seen-change cursor an ask's Changed status raises, and the consumption of
//! a bound code consent wait's settlement, in one writer.

use super::super::records::REPLAY_RECORDS;
use super::super::replay_bodies::response_erased_error;
use super::super::wait_holders::{holder_erased_in_txn, holder_erased_routed};
use super::erased_read::delivery_in_txn;
use super::{WaitKey, canonical_store, raise_observed_change_in, retire_wait_in_txn};
use crate::Result;
use crate::code_run::ExecutorStorage;

impl ExecutorStorage<'_> {
    /// Commits the replay record of a run resumed from `key`'s reply, the
    /// result of its parked step `step_seq` at `resumed_path`. When that
    /// reply is an ask's Changed status, the run's seen-change cursor rises
    /// in the same transaction, so a failed append acknowledges nothing. A
    /// bound code consent wait's settlement is consumed in it (DOOR-079 1b):
    /// its reply must be delivered and verify, or the record does not
    /// commit. A canonical wait's rows retire in that same writer, after
    /// consumption and the observed-change cursor; a room retires them after
    /// the commit. Retirement consumes nothing and deletes no consumption.
    /// Once an erase of the run's actor took its replies, nothing commits
    /// and nothing is consumed: a typed unavailable (FIX 5718). A room's
    /// record commits as any other append does, along its route, and the
    /// same check runs in that writer (FIX 6586).
    pub(crate) fn put_code_run_wait_resume_record(
        &self,
        record: &crate::code_run::CodeRunReplayRecord,
        expected: Option<crate::code_run::CodeRunReplayGeneration>,
        key: &WaitKey,
        step_seq: u64,
        resumed_path: &str,
    ) -> Result<crate::code_run::CodeRunReplayGeneration> {
        match self {
            Self::Canonical(vault) => vault.put_code_run_replay_record_if_generation_with_heal_and(
                record,
                expected,
                None,
                |txn| {
                    if holder_erased_in_txn(vault, txn, key)? {
                        return Err(response_erased_error("a resumed wait's reply"));
                    }
                    let delivery = delivery_in_txn(&vault.store, txn, &key.row())?;
                    if delivery.as_ref().is_some_and(|delivery| delivery.erased) {
                        return Err(response_erased_error("a resumed wait's reply"));
                    }
                    let resume = crate::code_run::CodeConsentResume {
                        record,
                        key: *key,
                        step_seq,
                        resumed_path,
                    };
                    let delivered = delivery.as_ref().map(|delivery| delivery.reply.as_str());
                    if crate::code_run::consume_code_consent_wait_in_txn(
                        vault, txn, &resume, delivered,
                    )? {
                        return retire_wait_in_txn(vault, txn, key);
                    }
                    let Some(delivery) = delivery else {
                        return retire_wait_in_txn(vault, txn, key);
                    };
                    if let Ok(crate::task_verb::TaskAskStatus::Changed { generation, .. }) =
                        serde_json::from_str::<crate::task_verb::TaskAskStatus>(&delivery.reply)
                    {
                        raise_observed_change_in(vault, txn, key.run, key.wait_id, generation)?;
                    }
                    retire_wait_in_txn(vault, txn, key)
                },
            ),
            Self::Session(binding) => {
                REPLAY_RECORDS.encode_value(record)?;
                let next_generation = record.generation()?;
                binding.answered(|| {
                    binding.put_replay_routed(record, expected, None, |txn, write| {
                        // The run's own rows ride its route, so `write`
                        // reads them on either route.
                        if holder_erased_routed(canonical_store(&write), &write, txn, key)? {
                            return Err(response_erased_error("a resumed wait's reply"));
                        }
                        let delivery = delivery_in_txn(&write, txn, &key.row())?;
                        if delivery.is_some_and(|delivery| delivery.erased) {
                            return Err(response_erased_error("a resumed wait's reply"));
                        }
                        Ok(())
                    })
                })?;
                Ok(next_generation)
            }
        }
    }
}
