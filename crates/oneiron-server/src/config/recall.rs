//! The `[recall]` section: how recall behaves at this server. Today it holds
//! call mode's deadline (retrieval hub #call-mode), handed to the engine as the
//! vault's `call_mode_deadline`. It also holds whether this server captures
//! retrieval-run telemetry (`retrieval_telemetry_capture`, off by default), handed
//! to the engine as the vault's setting of the same name (FIX 21998).

use serde::Deserialize;

/// Resolved recall settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallConfig {
    /// How long a call-mode recall may take before it answers with the best
    /// results ready, in milliseconds. Defaults to the engine's
    /// `DEFAULT_CALL_MODE_DEADLINE`, the ARCH-0042 #call-mode-budget bar.
    pub call_deadline_ms: u64,
    /// Whether recalls on this server record retrieval-run telemetry, so a
    /// recall that asks `telemetry: { capture_trace: true }` gets a
    /// `retrieval_run_id` back. Off by default: the trace/export lane is a
    /// measurement lane, never an always-on hot path (ARCH-0004 RET-TRACE-1).
    /// Handed to the engine as `VaultConfig::retrieval_telemetry_capture`.
    pub retrieval_telemetry_capture: bool,
}

impl Default for RecallConfig {
    fn default() -> Self {
        let default = oneiron::memory::DEFAULT_CALL_MODE_DEADLINE.as_millis();
        Self {
            call_deadline_ms: u64::try_from(default).unwrap_or(u64::MAX),
            retrieval_telemetry_capture: false,
        }
    }
}

impl RecallConfig {
    pub(super) fn apply_override(&mut self, over: RecallConfigOverride) {
        if let Some(value) = over.call_deadline_ms {
            self.call_deadline_ms = value;
        }
        if let Some(value) = over.retrieval_telemetry_capture {
            self.retrieval_telemetry_capture = value;
        }
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        oneiron::memory::caps::check_deadline_ms(Some(self.call_deadline_ms)).map_err(|_| {
            anyhow::anyhow!(
                "recall.call_deadline_ms must be between 1 and {}",
                oneiron::memory::caps::MAX_RECALL_DEADLINE_MS
            )
        })
    }
}

/// One layer's `[recall]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct RecallConfigOverride {
    pub(super) call_deadline_ms: Option<u64>,
    pub(super) retrieval_telemetry_capture: Option<bool>,
}

pub(super) fn lookup_recall_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<RecallConfigOverride>> {
    let call_deadline_ms = lookup("ONEIRON_RECALL_CALL_DEADLINE_MS")
        .map(|value| {
            value.parse().map_err(|_| {
                anyhow::anyhow!(
                    "ONEIRON_RECALL_CALL_DEADLINE_MS must be whole milliseconds, not {value:?}"
                )
            })
        })
        .transpose()?;
    let retrieval_telemetry_capture =
        super::lookup::lookup_bool(lookup, "ONEIRON_RECALL_RETRIEVAL_TELEMETRY_CAPTURE")?;
    if call_deadline_ms.is_none() && retrieval_telemetry_capture.is_none() {
        return Ok(None);
    }
    Ok(Some(RecallConfigOverride {
        call_deadline_ms,
        retrieval_telemetry_capture,
    }))
}
