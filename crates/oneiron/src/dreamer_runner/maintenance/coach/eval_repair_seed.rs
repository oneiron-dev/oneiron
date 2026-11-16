//! The Coach's repair-seed measuring job (census L1-20 PR D): one per seed
//! key, queued when the seed turns `Pending` and run by the host.

use rmpv::Value;

use super::{COACH_EVAL_REPAIR_SEED_FACET, COACH_HOST_QUEUE_KIND, invalid};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::{Result, Vault};

/// The job input's one key: the seed's key, as hex.
const INPUT_KEY: &str = "seed";

/// Queues the host's job for the repair seed `key`, under the caller's
/// writer. Its dedupe key keeps one job per key.
pub(crate) fn enqueue_coach_eval_repair_seed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    now: u64,
) -> Result<()> {
    let hex = oneiron_hex::encode(key);
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HOST_QUEUE_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_EVAL_REPAIR_SEED_FACET.into(),
            input: Value::Map(vec![(Value::from(INPUT_KEY), Value::from(hex.as_str()))]),
            parent_attempt: None,
        },
        Some(format!("{COACH_EVAL_REPAIR_SEED_FACET}:{hex}")),
        None,
        now,
    )?;
    Ok(())
}

impl Vault {
    /// The repair seed a leased `coach.eval_repair_seed` attempt runs, read
    /// by the host before it releases the seed.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, or a payload that
    /// names no seed.
    pub fn coach_eval_repair_seed_target(
        &self,
        attempt: &DreamerAdmittedAttempt,
    ) -> Result<[u8; 32]> {
        self.require_coach_attempt(attempt, COACH_EVAL_REPAIR_SEED_FACET)?;
        match &attempt.status.payload.input {
            Value::Map(fields) if fields.len() == 1 && fields[0].0.as_str() == Some(INPUT_KEY) => {
                let hex = fields[0].1.as_str().ok_or_else(invalid)?;
                oneiron_hex::decode(hex).ok_or_else(invalid)
            }
            _ => Err(invalid()),
        }
    }
}
