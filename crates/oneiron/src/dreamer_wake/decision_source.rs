//! Original caller provenance for a native decision read, never an execution grant.

use super::WakePassDeadline;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::AdmittedCallId;
use oneiron_model::llm::{BudgetAccountingSnapshot, BudgetGuard, BudgetLease};
use std::sync::{Arc, OnceLock, Weak};

/// The original admitted line of a scoped caller. Merely carrying this value
/// allocates nothing; the native read draws its own invocation after admission.
#[derive(Clone, Copy)]
pub struct DecisionCallSource<'a> {
    deadline: &'a WakePassDeadline,
    attempt_id: AttemptId,
    boot: [u8; 16],
}

impl<'a> DecisionCallSource<'a> {
    pub(crate) fn new(
        vault: &Vault,
        deadline: &'a WakePassDeadline,
        attempt_id: AttemptId,
    ) -> Self {
        Self {
            deadline,
            attempt_id,
            boot: vault.active_wakes.boot(),
        }
    }

    pub(crate) fn admitted(
        &self,
        guard: &BudgetGuard,
        lease: &BudgetLease,
    ) -> crate::Result<Option<DecisionCallAdmission>> {
        Ok(self
            .deadline
            .admitted_call_id(self.attempt_id)?
            .map(|origin| {
                if let Some(line) = self.deadline.original_budget_line() {
                    line.retain_native_lease(origin, lease);
                }
                DecisionCallAdmission {
                    origin,
                    guard: guard.clone(),
                    lease: lease.clone(),
                    boot: self.boot,
                    line: self
                        .deadline
                        .admitted_budget_line(self.attempt_id)
                        .map(str::to_owned),
                    reserved_units: guard.reserved_for(lease),
                    admitted_at: crate::unix_seconds_now(),
                    meter_vault: Arc::default(),
                }
            }))
    }
}

/// One native admission's original coordinate and the actual issuing guard and
/// lease. A snapshot is GROSS meter data, not a NET invoice or a paid receipt.
#[derive(Clone)]
pub struct DecisionCallAdmission {
    pub(crate) origin: AdmittedCallId,
    pub(crate) guard: BudgetGuard,
    pub(crate) lease: BudgetLease,
    boot: [u8; 16],
    line: Option<String>,
    reserved_units: Option<u64>,
    admitted_at: u64,
    meter_vault: Arc<OnceLock<Weak<Vault>>>,
}

/// One actual native completion request. List position is request order on this
/// read, not a corrective financial ordinal or proof that bytes reached a model.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionCompletionObservation {
    /// The finalized native JSON input body, not compressed wire bytes or proof of send.
    pub input_body_hash: [u8; 32],
    pub requested_prompts: usize,
    /// None when the request returned no parsed native response.
    pub response: Option<DecisionCompletionResponse>,
}

/// Parsed response counters before status, batch or label validation. These are
/// source data only; missing counts and malformed shapes are never zero invoices.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionCompletionResponse {
    pub status: u16,
    /// None for a non-object/non-array body; an empty array stays explicitly empty.
    pub answers: Option<Vec<DecisionAnswerQuantity>>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionAnswerQuantity {
    pub index: Option<u64>,
    pub tokens_evaluated: Option<u64>,
    pub tokens_predicted: Option<u64>,
}

/// A native producer whose original admission was retained before its read.
/// Recording its response quantity never pays or authorizes the call.
pub struct DecisionCallInvoice<'a> {
    vault: &'a Vault,
    origin: AdmittedCallId,
}

impl DecisionCompletionObservation {
    /// Complete native input/output totals under the House forward-pass policy.
    /// Cache, timing and inference-receipt details are not reconstructed.
    pub(crate) fn terminal_usage(completions: &[Self]) -> Option<oneiron_model::llm::LlmUsage> {
        completed_units(completions)?;
        let mut usage = oneiron_model::llm::LlmUsage::zero();
        for completion in completions {
            for answer in completion.response.as_ref()?.answers.as_ref()? {
                usage.input.total = usage.input.total.checked_add(answer.tokens_evaluated?)?;
                usage.output.total = usage
                    .output
                    .total
                    .checked_add(answer.tokens_predicted?.max(1))?;
            }
        }
        Some(usage)
    }
}

impl DecisionCallInvoice<'_> {
    /// Retains observed response counters separately from the immutable invoice,
    /// including unknown responses after a known prefix. This never pays a call.
    pub fn record_completions(
        &self,
        completions: &[DecisionCompletionObservation],
    ) -> crate::Result<()> {
        if completions.is_empty() {
            return Ok(());
        }
        self.vault.with_write_txn_grouped(|wtxn| {
            crate::dreamer_runner::record_native_house_completions_in_txn(
                self.vault,
                wtxn,
                self.origin,
                completions,
            )
        })
    }

    /// A failed logical read can still have complete native response counts.
    /// Unknown or unresolved requests retain source data but never freeze a prefix
    /// as the terminal invoice. The ordinary read error remains the caller's result.
    pub fn record_failed_completions(
        &self,
        completions: &[DecisionCompletionObservation],
    ) -> crate::Result<()> {
        let Some(units) = completed_units(completions) else {
            return Ok(());
        };
        self.vault.with_write_txn_grouped(|wtxn| {
            crate::dreamer_runner::record_native_house_completions_in_txn(
                self.vault,
                wtxn,
                self.origin,
                completions,
            )?;
            crate::dreamer_runner::invoice_native_call_in_txn(self.vault, wtxn, self.origin, units)
        })
    }

    /// Records the native terminal quantity, not a quote or a GROSS meter delta.
    pub fn record_usage(&self, usage: &oneiron_model::llm::LlmUsage) -> crate::Result<()> {
        let units = usage
            .input
            .total
            .checked_add(usage.output.total)
            .ok_or(crate::Error::ArithmeticOverflow("native decision usage"))?;
        self.vault.with_write_txn_grouped(|wtxn| {
            crate::dreamer_runner::invoice_native_call_in_txn(self.vault, wtxn, self.origin, units)
        })
    }
}

/// Every response must name exactly its request's native prompt population.
/// These indices identify returned prompts, never financial corrective ordinals.
fn completed_units(completions: &[DecisionCompletionObservation]) -> Option<u64> {
    if completions.is_empty() {
        return None;
    }
    let mut units = 0_u64;
    for completion in completions {
        let response = completion.response.as_ref()?;
        if !(200..=299).contains(&response.status) {
            return None;
        }
        let answers = response.answers.as_ref()?;
        if completion.requested_prompts == 0 || answers.len() != completion.requested_prompts {
            return None;
        }
        let mut indices = std::collections::BTreeSet::new();
        for answer in answers {
            let index = usize::try_from(answer.index?).ok()?;
            if index >= completion.requested_prompts || !indices.insert(index) {
                return None;
            }
            units = units.checked_add(answer.tokens_evaluated?)?;
            // Match the existing native forward-pass accounting, not a raw zero rewrite.
            units = units.checked_add(answer.tokens_predicted?.max(1))?;
        }
    }
    Some(units)
}

impl DecisionCallAdmission {
    /// Retains the actual native input plan on this admission before bytes leave.
    /// The returned producer can record usage only in this original vault boot.
    /// Failure is evidence loss; callers keep the ordinary read and settlement.
    pub fn retain_native_input<'a>(
        &self,
        vault: &'a Arc<Vault>,
        input_hash: [u8; 32],
    ) -> crate::Result<DecisionCallInvoice<'a>> {
        let invalid = || crate::Error::InvalidConfig("native decision admission differs".into());
        if vault.active_wakes.boot() != self.boot {
            return Err(invalid());
        }
        let admitted = crate::dreamer_wake::owed::WakeOwedCall {
            origin: self.origin,
            boot: self.boot,
            line: self.line.clone().ok_or_else(invalid)?,
            lease: self.lease.id().to_owned(),
            reserved_units: self.reserved_units.ok_or_else(invalid)?,
            at: self.admitted_at,
        };
        let snapshot = self.accounting_snapshot();
        vault.with_write_txn_grouped(|wtxn| {
            crate::dreamer_runner::retain_native_call_in_txn(
                vault,
                wtxn,
                input_hash,
                &admitted,
                snapshot.guard_id,
            )
        })?;
        let _ = self.meter_vault.set(Arc::downgrade(vault));
        Ok(DecisionCallInvoice {
            vault,
            origin: self.origin,
        })
    }

    /// Reads only this original admission's retained, fully observed House invoice.
    /// Unknown response quantities stay absent; this neither settles nor pays a call.
    pub fn terminal_usage(&self) -> crate::Result<Option<oneiron_model::llm::LlmUsage>> {
        let Some(vault) = self.meter_vault.get().and_then(Weak::upgrade) else {
            return Ok(None);
        };
        if vault.active_wakes.boot() != self.boot {
            return Ok(None);
        }
        let Some(line) = self.line.as_deref() else {
            return Ok(None);
        };
        crate::dreamer_runner::DreamerRunnerStore::new(&vault).native_house_terminal_usage(
            self.origin,
            self.boot,
            line,
            self.lease.id(),
        )
    }

    /// The original settlement calls this before forwarding its unchanged receipt.
    pub(crate) fn record_native_meter(&self) {
        if std::thread::panicking() {
            return;
        }
        let Some(vault) = self.meter_vault.get().and_then(Weak::upgrade) else {
            return;
        };
        if vault.active_wakes.boot() != self.boot {
            return;
        }
        let snapshot = self.accounting_snapshot();
        let Some(range) = snapshot.meter_ranges[0] else {
            return;
        };
        if let Err(error) = vault.with_write_txn_grouped(|wtxn| {
            crate::dreamer_runner::record_native_call_meter_in_txn(
                &vault,
                wtxn,
                self.origin,
                self.lease.id(),
                snapshot.guard_id,
                range,
            )
        }) {
            tracing::warn!(kind = ?error.kind(), %error, "native decision meter was not retained");
        }
    }

    /// Samples this exact lease through its issuing guard, including unknown
    /// and unstarted states. Its public lease id is never used to reconstruct it.
    #[must_use]
    pub fn accounting_snapshot(&self) -> BudgetAccountingSnapshot {
        self.guard.accounting_snapshot(&[&self.lease])
    }
}

impl std::fmt::Debug for DecisionCallAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionCallAdmission")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl PartialEq for DecisionCallAdmission {
    fn eq(&self, other: &Self) -> bool {
        self.origin == other.origin && self.lease == other.lease
    }
}

impl Eq for DecisionCallAdmission {}
