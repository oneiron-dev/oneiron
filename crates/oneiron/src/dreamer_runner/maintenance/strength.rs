//! Nightly strength maintenance rides the existing wake recipe/run-tree lane.
use super::super::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::attempt_queue::AttemptId;
use crate::{Result, Vault};
use rmpv::Value;

pub const CONSOLIDATION_STRENGTH_FACET: &str = "dreamer.consolidation_strength";

impl DreamerRunnerStore<'_> {
    pub(crate) fn enqueue_consolidation_strength_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent: AttemptId,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        self.enqueue_kind_in_txn(
            txn,
            super::MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: CONSOLIDATION_STRENGTH_FACET.into(),
                input: Value::Nil,
                parent_attempt: Some(parent),
            },
            Some(format!(
                "{CONSOLIDATION_STRENGTH_FACET}:{}",
                crate::entity_id::bytes_to_hex_lower(parent.as_bytes()),
            )),
            run_id,
            now,
        )?;
        Ok(())
    }
}

pub(super) fn run(vault: &Vault, attempt: &DreamerAdmittedAttempt, now_ms: u64) -> Result<()> {
    crate::dreamer_consolidation::strength::archive_quiet_claims(
        vault,
        attempt.status.attempt.id,
        now_ms,
    )?;
    Ok(())
}
