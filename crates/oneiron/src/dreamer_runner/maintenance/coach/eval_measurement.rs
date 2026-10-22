//! The Coach's eval measurement job (FIX 574, OF-578): one per request
//! digest, queued when the measurement is asked for and run by the host.

use rmpv::Value;

use super::{COACH_EVAL_MEASUREMENT_FACET, COACH_HOST_QUEUE_KIND, invalid};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::{Result, Vault};

/// The job input's one key: the measurement's request digest, as hex.
const INPUT_KEY: &str = "measurement";

/// Queues the host's job for the measurement `digest`, under the caller's
/// writer. Its dedupe key keeps one job per digest.
pub(crate) fn enqueue_coach_eval_measurement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
    now: u64,
) -> Result<()> {
    let hex = blake3::Hash::from(*digest).to_hex();
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HOST_QUEUE_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_EVAL_MEASUREMENT_FACET.into(),
            input: Value::Map(vec![(Value::from(INPUT_KEY), Value::from(hex.as_str()))]),
            parent_attempt: None,
        },
        Some(format!("{COACH_EVAL_MEASUREMENT_FACET}:{hex}")),
        None,
        now,
    )?;
    Ok(())
}

impl Vault {
    /// The measurement a leased `coach.eval_measurement` attempt runs, read
    /// by the host before it claims the measurement.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, or a payload that
    /// names no measurement.
    pub fn coach_eval_measurement_target(
        &self,
        attempt: &DreamerAdmittedAttempt,
    ) -> Result<[u8; 32]> {
        self.require_coach_attempt(attempt, COACH_EVAL_MEASUREMENT_FACET)?;
        match &attempt.status.payload.input {
            Value::Map(fields) if fields.len() == 1 && fields[0].0.as_str() == Some(INPUT_KEY) => {
                let hex = fields[0].1.as_str().ok_or_else(invalid)?;
                Ok(*blake3::Hash::from_hex(hex)
                    .map_err(|_| invalid())?
                    .as_bytes())
            }
            _ => Err(invalid()),
        }
    }
}
