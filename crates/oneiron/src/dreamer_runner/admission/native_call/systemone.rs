//! The native System One response's single aggregate measurement, not per-answer shares.

use super::{
    AdmittedCallId, CALLS, DreamerRunnerStore, Result, invalid_dreamer_runner,
    invoice_native_call_in_txn,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SystemOneTerminalUsage {
    input_tokens: u64,
    output_tokens: u64,
}

impl SystemOneTerminalUsage {
    pub(super) fn terminal_usage(&self) -> oneiron_model::llm::LlmUsage {
        let mut usage = oneiron_model::llm::LlmUsage::zero();
        usage.input.total = self.input_tokens;
        usage.output.total = self.output_tokens;
        usage.raw_provider = serde_json::json!({
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        });
        usage
    }
}

impl DreamerRunnerStore<'_> {
    /// Source counters and the original invoice commit together. This does not
    /// settle the call or identify any logical answer's share of the measurement.
    pub(crate) fn record_native_systemone_usage_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        origin: AdmittedCallId,
        usage: &oneiron_model::llm::LlmUsage,
    ) -> Result<()> {
        let units = usage
            .input
            .total
            .checked_add(usage.output.total)
            .ok_or(crate::Error::ArithmeticOverflow("native System One usage"))?;
        let observed = SystemOneTerminalUsage {
            input_tokens: usage.input.total,
            output_tokens: usage.output.total,
        };
        let Some(mut row) = CALLS.get(&self.vault.store, &*wtxn, &origin)? else {
            return Err(invalid_dreamer_runner(
                "native call has no original admission",
            ));
        };
        match &row.systemone_usage {
            None => {
                row.systemone_usage = Some(observed);
                CALLS.put(&self.vault.store, wtxn, &origin, &row)?;
            }
            Some(original) if original == &observed => {}
            _ => {
                return Err(invalid_dreamer_runner(
                    "native System One observations differ",
                ));
            }
        }
        invoice_native_call_in_txn(self.vault, wtxn, origin, units)
    }
}
