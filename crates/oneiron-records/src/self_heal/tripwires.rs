//! Moved from `crates/oneiron/src/self_heal/tripwires.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::self_heal::tripwires::policy::TripwireBound;
pub use crate::self_heal::tripwires::policy::TripwireBoundOrigin;
pub use crate::self_heal::tripwires::policy::TripwirePolicyReceipt;
pub use crate::self_heal::tripwires::policy::TripwirePolicySource;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

pub fn default_retrieval_regressions() -> u64 {
    32
}

/// One fixed-window bound resolved from the vault's POLICY_MANIFEST rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TripwireBounds {
    pub window_secs: u64,
    pub consent_depth: u64,
    pub actor_writes: u64,
    /// Degraded retrieval runs inside one window that read as a regression
    /// (the ARCH-0037 kill-criterion shape, ARCH-0066 §4).
    #[serde(default = "default_retrieval_regressions")]
    pub retrieval_regressions: u64,
}

impl Default for TripwireBounds {
    fn default() -> Self {
        Self {
            window_secs: 600,
            consent_depth: 1_000,
            actor_writes: 100,
            retrieval_regressions: default_retrieval_regressions(),
        }
    }
}

impl TripwireBounds {
    pub fn decode(value: &Value) -> Option<Self> {
        let entries = value.as_map()?;
        if !(3..=4).contains(&entries.len()) {
            return None;
        }
        let field = |name| {
            let matches: Vec<_> = entries
                .iter()
                .filter(|(key, _)| key.as_str() == Some(name))
                .collect();
            if matches.len() != 1 {
                return None;
            }
            matches[0].1.as_u64()
        };
        let bounds = Self {
            window_secs: field("window_secs")?,
            consent_depth: field("consent_depth")?,
            actor_writes: field("actor_writes")?,
            retrieval_regressions: match entries.len() {
                4 => field("retrieval_regressions")?,
                _ => default_retrieval_regressions(),
            },
        };
        bounds.valid().then_some(bounds)
    }

    /// A positive window and positive thresholds. A large threshold is the
    /// owner's to set; `Vault::tripwire_bounds` asks past
    /// `limits.tripwire_threshold`.
    pub fn valid(self) -> bool {
        self.window_secs > 0
            && self.consent_depth > 0
            && self.actor_writes > 0
            && self.retrieval_regressions > 0
    }
}
pub mod policy;
