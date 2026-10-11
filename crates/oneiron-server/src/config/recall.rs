//! The `[recall]` section: how recall behaves at this server. Today it holds
//! call mode's deadline (retrieval hub #call-mode), handed to the engine as the
//! vault's `call_mode_deadline`.

use serde::Deserialize;

/// Resolved recall settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallConfig {
    /// How long a call-mode recall may take before it answers with the best
    /// results ready, in milliseconds. Defaults to the engine's
    /// `DEFAULT_CALL_MODE_DEADLINE`, the ARCH-0042 #call-mode-budget bar.
    pub call_deadline_ms: u64,
}

impl Default for RecallConfig {
    fn default() -> Self {
        let default = oneiron::memory::DEFAULT_CALL_MODE_DEADLINE.as_millis();
        Self {
            call_deadline_ms: u64::try_from(default).unwrap_or(u64::MAX),
        }
    }
}

impl RecallConfig {
    pub(super) fn apply_override(&mut self, over: RecallConfigOverride) {
        if let Some(value) = over.call_deadline_ms {
            self.call_deadline_ms = value;
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
    Ok(
        call_deadline_ms.map(|call_deadline_ms| RecallConfigOverride {
            call_deadline_ms: Some(call_deadline_ms),
        }),
    )
}
