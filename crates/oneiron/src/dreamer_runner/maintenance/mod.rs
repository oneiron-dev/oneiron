//! Scheduled curator and harness-evaluation facets on one gated Dreamer authority.
mod curator;
mod evaluation;
mod proposals;
pub mod representation;
#[cfg(test)]
mod tests;
use super::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::side_table::{LegacyJson, SideTable};
use crate::{Error, Result, Vault};
pub use curator::{CuratorRubric, CuratorTrigger};
pub use evaluation::{DreamerTuningConfig, HarnessEvaluation, RetuneThresholds};
use rmpv::Value;
pub const MAINTENANCE_QUEUE_KIND: &str = "dreamer.maintenance";
pub const CURATOR_FACET: &str = "dreamer.curator";
pub const HARNESS_FACET: &str = "dreamer.harness_maintenance";
fn invalid() -> Error {
    Error::InvalidConfig("invalid Dreamer maintenance row".into())
}
impl DreamerRunnerStore<'_> {
    pub(super) fn enqueue_maintenance(
        &self,
        facet: &str,
        input: Value,
        dedupe: String,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.vault.with_write_txn(|txn| {
            self.enqueue_kind_in_txn(
                txn,
                MAINTENANCE_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: facet.into(),
                    input,
                    parent_attempt: None,
                },
                Some(dedupe),
                None,
                now,
            )
        })
    }
    pub fn admit_next_maintenance(
        &self,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerAdmissionOutcome> {
        self.admit_next_kind(MAINTENANCE_QUEUE_KIND, input)
    }
}
pub(crate) fn execute(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
) -> Result<DreamerAttemptExecution> {
    let facet = attempt.status.payload.attempt_type.as_str();
    match facet {
        CURATOR_FACET => {
            curator::run(ctx.vault, attempt, ctx.now_ms / 1000)?;
        }
        HARNESS_FACET => {
            evaluation::run(ctx.vault, attempt, ctx.now_ms / 1000)?;
        }
        representation::REPRESENTATION_FACET => {
            representation::run(ctx.vault, attempt, ctx.now_ms / 1000)?;
        }
        _ => return Err(invalid()),
    }
    Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
}
fn load_row<T: serde::Serialize + serde::de::DeserializeOwned>(
    vault: &Vault,
    table: SideTable<(), T, LegacyJson>,
    defaults: &str,
) -> Result<T> {
    let txn = vault.store.env.read_txn()?;
    match table.get(&vault.store, &txn, &())? {
        Some(row) => Ok(row),
        None => serde_json::from_str(defaults).map_err(|_| invalid()),
    }
}

pub mod digest;

fn validate_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &crate::consent::AuthenticatedOwner,
) -> Result<()> {
    let refused = || {
        Error::Gate(crate::error::GateError::ConsentOwnerNotAuthenticated(
            "maintenance requires a live owner in this vault",
        ))
    };
    let actor = owner.actor();
    if !matches!(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, &actor)?,
        crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            ..
        }
    ) || vault.entity_lifecycle_state_in_txn(txn, &actor)?
        != crate::identity_topology::EntityLifecycleState::Active
    {
        return Err(refused());
    }
    Ok(())
}
