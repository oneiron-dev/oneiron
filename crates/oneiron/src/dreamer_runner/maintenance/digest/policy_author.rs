//! Proposed shared digest rhythm from the existing owner's Weave verdict.

use super::{ProactivityPolicyRequest, load_cadence, load_presentation};
use crate::dreamer_runner::maintenance::MAINTENANCE_QUEUE_KIND;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::{Result, Vault};

pub(in crate::dreamer_runner::maintenance) const PROACTIVITY_POLICY_FACET: &str =
    "dreamer.digest.policy";

impl DreamerRunnerStore<'_> {
    pub(in crate::dreamer_runner::maintenance) fn enqueue_proactivity_policy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<crate::attempt_queue::AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        self.enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: PROACTIVITY_POLICY_FACET.into(),
                input: rmpv::Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{PROACTIVITY_POLICY_FACET}:{}",
                    blake3::hash(key.as_bytes()).to_hex()
                )
            }),
            run_id,
            now,
        )?;
        Ok(())
    }
}

pub(in crate::dreamer_runner::maintenance) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<()> {
    let drafted = {
        let txn = vault.store.env.read_txn()?;
        // This is the existing filing door's subject, not another person's
        // engagement or an aggregate of the vault's owners.
        let owner = crate::vault::embedded_owner_actor_id()?;
        let Some((period_secs, evidence)) =
            vault.dreamer_proactivity_cadence_step_in_txn(&txn, owner, now)?
        else {
            return Ok(());
        };
        let mut cadence = load_cadence(vault, &txn)?;
        if cadence.period_secs == period_secs || evidence.is_empty() {
            return Ok(());
        }
        cadence.period_secs = period_secs;
        let request = ProactivityPolicyRequest {
            cadence,
            presentation: load_presentation(vault, &txn)?,
        };
        (request, evidence)
    };
    vault.file_dreamer_proactivity_policy(
        attempt.status.attempt.id,
        &drafted.0,
        &drafted.1,
        now,
    )?;
    Ok(())
}
