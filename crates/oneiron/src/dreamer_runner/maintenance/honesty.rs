//! The Coach's audit-draw recipe on the shared, gated maintenance lane.
//! It only draws durable check requests; the host runs deep checks under its
//! existing model, Grant and budget doors, then admits their findings.

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::{Result, Vault};
use rmpv::Value;

pub const HONESTY_AUDIT_FACET: &str = "coach.honesty_audits";

impl DreamerRunnerStore<'_> {
    pub(crate) fn enqueue_honesty_audits_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.enqueue_kind_in_txn(
            txn,
            super::MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: HONESTY_AUDIT_FACET.into(),
                input: Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{HONESTY_AUDIT_FACET}:{}",
                    blake3::hash(key.as_bytes()).to_hex()
                )
            }),
            run_id,
            now,
        )
    }
}

pub(super) fn run(vault: &Vault, now: u64) -> Result<u64> {
    vault.with_write_txn_grouped(|txn| crate::self_heal::audit::draw_audits_in_txn(vault, txn, now))
}
