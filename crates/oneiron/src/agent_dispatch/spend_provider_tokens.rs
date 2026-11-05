//! Last recorded provider-token snapshots on each native guard generation.
//! These are observations, not a money ledger or proof of whole-scope coverage.

use serde::{Deserialize, Serialize};

use super::{AgentDispatcher, SpendScopeId};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::run_admission::{RunEvent, RunReceipt};
use crate::llm::{ObservedInferenceSlot, ProviderTokenMeasurement, ProviderTokenSnapshot};
use crate::side_table::{self, Named, SideTable};
use crate::{AttemptId, EntityId, Result};

const OBSERVATION: SideTable<String, ProviderTokenCapture, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_SPEND_PROVIDER_OBSERVATION);

/// One guard capture and the native permit receipts recorded beside it.
/// The permits present do not enumerate every source on this spend scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderTokenCapture {
    pub snapshot: ProviderTokenSnapshot,
    pub leases: Vec<ProviderLeaseTokenObservation>,
    pub run_observations: Vec<ProviderRunTokenObservation>,
}

/// Entry and model-future return observed on one actual scoped run instance.
/// A returned model future does not seal the RunAdmission against later use,
/// close the guard or scope, or certify complete physical-request reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRunTokenObservation {
    pub instance: EntityId,
    /// The executed caller's identity, supplied by its native lease.
    pub owner_attempt: Option<AttemptId>,
    pub entry_recorded: bool,
    pub model_future_returned: bool,
}

/// Content-free observations of one actual native permit. The instance and
/// lease together identify it, even when another run reuses the lease string.
/// The optional owner names only this permit's executed caller, not the
/// scope's aggregate observations or every request it may have made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderLeaseTokenObservation {
    pub instance: EntityId,
    pub owner_attempt: Option<AttemptId>,
    pub lease: String,
    /// Whether its Admitted receipt was recorded here, not a full inventory.
    pub admitted_receipt: bool,
    /// Whether its Dispatched receipt was recorded here. That receipt is
    /// emitted at the native call's end, not at its first physical send.
    pub dispatched_receipt: bool,
    /// Only the actual Dispatched receipt supplies this answer status.
    /// A missing receipt stays unknown, even if a settlement was recorded.
    pub answered: Option<bool>,
    /// The native permit ended. This does not close its run or spend scope,
    /// or certify that every physical request reported its final token use.
    pub settlement: Option<ProviderLeaseTokenSettlement>,
}

/// Actual fields from one native Settled receipt, independent of its charges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderLeaseTokenSettlement {
    pub dispatched: bool,
    /// The answer's explicit provider measurement, not normalized usage.
    pub answer: Option<ProviderTokenMeasurement>,
    /// One entry per native inference receipt, retaining multiplicity and
    /// missing components. These can be partial, and are never summed here.
    /// An empty list is not a measured zero or proof that no request ran.
    pub reports: Vec<ProviderTokenMeasurement>,
    /// The same native capture's publisher slots, including slots that recorded
    /// nothing. Slot identity is local to this instance and lease. These are
    /// separate from merged reports and do not certify complete coverage.
    pub observed_slots: Vec<ObservedInferenceSlot>,
}

impl ProviderLeaseTokenObservation {
    /// Selects only actual native permit receipts and typed token reports.
    /// No prompt, credential, price or normalized token count is copied.
    #[must_use]
    pub fn from_receipt(receipt: &RunReceipt, owner_attempt: Option<AttemptId>) -> Option<Self> {
        let mut observation = Self {
            instance: receipt.instance,
            owner_attempt,
            lease: String::new(),
            admitted_receipt: false,
            dispatched_receipt: false,
            answered: None,
            settlement: None,
        };
        match &receipt.event {
            RunEvent::Admitted(facts) => {
                observation.lease.clone_from(&facts.lease);
                observation.admitted_receipt = true;
            }
            RunEvent::Dispatched {
                lease, answered, ..
            } => {
                observation.lease.clone_from(lease);
                observation.dispatched_receipt = true;
                observation.answered = Some(*answered);
            }
            RunEvent::Settled {
                lease,
                dispatched,
                usage,
                inference_calls,
                observed_slots,
                ..
            } => {
                observation.lease.clone_from(lease);
                observation.settlement = Some(ProviderLeaseTokenSettlement {
                    dispatched: *dispatched,
                    answer: usage
                        .as_ref()
                        .and_then(|usage| usage.provider_token_measurement),
                    reports: inference_calls
                        .iter()
                        .map(|report| ProviderTokenMeasurement {
                            input: report.logical_prompt_tokens,
                            output: report.output_tokens,
                        })
                        .collect(),
                    observed_slots: observed_slots.clone(),
                });
            }
            _ => return None,
        }
        Some(observation)
    }
}

impl AgentDispatcher<'_> {
    /// Records one actual guard capture without changing any charge or scope
    /// state. A late writer cannot replace a newer capture of that generation.
    /// A missing row is unknown; these rows do not enumerate every source.
    pub fn record_provider_token_snapshot(
        &self,
        scope: &SpendScopeId,
        snapshot: &ProviderTokenSnapshot,
    ) -> Result<()> {
        self.record_provider_token_capture(scope, snapshot, None, None)
    }

    /// Keeps one native permit observation beside its actual scoped guard.
    /// Receipt merging is independent of capture order: an older capture can
    /// still carry a different permit, or the end of one already admitted.
    pub fn record_provider_lease_tokens(
        &self,
        scope: &SpendScopeId,
        snapshot: &ProviderTokenSnapshot,
        lease: &ProviderLeaseTokenObservation,
    ) -> Result<()> {
        self.record_provider_token_capture(scope, snapshot, Some(lease), None)
    }

    /// Records only the source stages the native scoped model path observed.
    /// A return without an entry can be retained after a failed entry write;
    /// neither stage is proof of complete source coverage or scope closure.
    pub fn record_provider_run_tokens(
        &self,
        scope: &SpendScopeId,
        snapshot: &ProviderTokenSnapshot,
        run: &ProviderRunTokenObservation,
    ) -> Result<()> {
        self.record_provider_token_capture(scope, snapshot, None, Some(run))
    }

    fn record_provider_token_capture(
        &self,
        scope: &SpendScopeId,
        snapshot: &ProviderTokenSnapshot,
        lease: Option<&ProviderLeaseTokenObservation>,
        run: Option<&ProviderRunTokenObservation>,
    ) -> Result<()> {
        let key = snapshot_key(scope, &snapshot.generation);
        let mut txn = self.vault.store.env.write_txn()?;
        let previous = OBSERVATION.get(&self.vault.store, &txn, &key)?;
        if lease.is_none()
            && run.is_none()
            && previous
                .as_ref()
                .is_some_and(|capture| capture.snapshot.observation_id >= snapshot.observation_id)
        {
            return Ok(());
        }
        let mut capture = previous.unwrap_or_else(|| ProviderTokenCapture {
            snapshot: snapshot.clone(),
            leases: Vec::new(),
            run_observations: Vec::new(),
        });
        if capture.snapshot.observation_id < snapshot.observation_id {
            capture.snapshot.clone_from(snapshot);
        }
        if let Some(lease) = lease {
            if let Some(previous) = capture.leases.iter_mut().find(|previous| {
                previous.instance == lease.instance && previous.lease == lease.lease
            }) {
                if previous.owner_attempt.is_none() {
                    previous.owner_attempt = lease.owner_attempt;
                }
                previous.admitted_receipt |= lease.admitted_receipt;
                previous.dispatched_receipt |= lease.dispatched_receipt;
                if previous.answered.is_none() {
                    previous.answered = lease.answered;
                }
                if previous.settlement.is_none() {
                    previous.settlement.clone_from(&lease.settlement);
                }
            } else {
                capture.leases.push(lease.clone());
            }
        }
        if let Some(run) = run {
            if let Some(previous) = capture
                .run_observations
                .iter_mut()
                .find(|previous| previous.instance == run.instance)
            {
                if previous.owner_attempt.is_none() {
                    previous.owner_attempt = run.owner_attempt;
                }
                previous.entry_recorded |= run.entry_recorded;
                previous.model_future_returned |= run.model_future_returned;
            } else {
                capture.run_observations.push(run.clone());
            }
        }
        OBSERVATION.put(&self.vault.store, &mut txn, &key, &capture)?;
        txn.commit()?;
        Ok(())
    }

    /// Present historical captures in the caller's snapshot. Even when every
    /// returned component is known, unrecorded generations remain uncovered.
    pub(crate) fn provider_token_snapshots_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<Vec<ProviderTokenCapture>> {
        let prefix = scope_prefix(scope);
        Ok(OBSERVATION
            .scan_from(&self.vault.store, txn, prefix.as_bytes())?
            .into_iter()
            .map(|(_, capture)| capture)
            .collect())
    }
}

fn scope_prefix(scope: &SpendScopeId) -> String {
    format!("{}:{}\0", scope.as_str().len(), scope.as_str())
}

fn snapshot_key(scope: &SpendScopeId, generation: &[u8; 16]) -> String {
    let mut key = scope_prefix(scope);
    key.push_str(&bytes_to_hex_lower(generation));
    key
}
