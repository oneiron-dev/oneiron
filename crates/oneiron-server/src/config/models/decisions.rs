//! `[models.decisions]`: the host's own typed questions and the System One
//! seat on its decision ladder.
//!
//! The ladder is built once at serve start from what `[models]` already
//! binds: the rule table first, the house model's decision read
//! (`[models.decision_read]`) on the escalation rung, and the vault owner's
//! ask queue last. These rows add the System One seat and word the host's
//! own questions; a question with no wording is not asked, and its hook stays
//! unbound. No question text lives in the server.
use std::time::Duration;

use serde::Deserialize;

/// A seat pick's anytime budget when the file names none.
const DEFAULT_SEAT_BUDGET_MS: u64 = 2_000;

/// `[models.decisions]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionsFile {
    /// The write gate's auto check: allow or hold.
    auto_check: Option<String>,
    seat: Option<SeatPickFile>,
    system_one: Option<SystemOneFile>,
}

/// `[models.decisions.seat]`: the code-mode seat pick.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeatPickFile {
    /// The model-description facet a run's candidates are described under.
    facet: String,
    /// Which candidate the seat pins.
    model: String,
    /// Which of the chosen model's efforts it runs at.
    effort: String,
    budget_ms: Option<u64>,
}

/// `[models.decisions.system_one]`: the remote System One seat.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemOneFile {
    /// Ends `/v1/systemone`; HTTPS, or HTTP on loopback.
    endpoint: String,
    /// The environment variable holding the seat's bearer token.
    key_env: String,
    model: String,
    version: String,
    /// Owner opt-in for unit state to leave a non-hosted vault.
    remote_opt_in: Option<bool>,
    budget_units: Option<u64>,
}

/// The resolved section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecisionsSettings {
    /// The auto check's wording; `None` leaves the checker unbound.
    pub auto_check: Option<String>,
    pub seat: Option<SeatPickSettings>,
    pub system_one: Option<SystemOneSettings>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatPickSettings {
    pub facet: String,
    pub model_wording: String,
    pub effort_wording: String,
    pub budget: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemOneSettings {
    pub endpoint: String,
    pub key_env: String,
    pub model: String,
    pub version: String,
    pub remote_opt_in: bool,
    /// The seat's own meter; the raw routes' units when unset.
    pub budget_units: Option<u64>,
}

impl DecisionsFile {
    pub(super) fn resolve(self) -> anyhow::Result<DecisionsSettings> {
        let filled = |field: &str, value: String| {
            if value.trim().is_empty() {
                anyhow::bail!("models.decisions.{field} must not be blank");
            }
            Ok(value)
        };
        let auto_check = self
            .auto_check
            .map(|wording| filled("auto_check", wording))
            .transpose()?;
        let seat = self
            .seat
            .map(|seat| -> anyhow::Result<_> {
                Ok(SeatPickSettings {
                    facet: filled("seat.facet", seat.facet)?,
                    model_wording: filled("seat.model", seat.model)?,
                    effort_wording: filled("seat.effort", seat.effort)?,
                    budget: Duration::from_millis(
                        match seat.budget_ms.unwrap_or(DEFAULT_SEAT_BUDGET_MS) {
                            0 => anyhow::bail!("models.decisions.seat.budget_ms must be above 0"),
                            ms => ms,
                        },
                    ),
                })
            })
            .transpose()?;
        let system_one = self
            .system_one
            .map(|seat| -> anyhow::Result<_> {
                if seat.budget_units == Some(0) {
                    anyhow::bail!("models budget units must be greater than zero");
                }
                Ok(SystemOneSettings {
                    endpoint: filled("system_one.endpoint", seat.endpoint)?,
                    key_env: filled("system_one.key_env", seat.key_env)?,
                    model: filled("system_one.model", seat.model)?,
                    version: filled("system_one.version", seat.version)?,
                    remote_opt_in: seat.remote_opt_in.unwrap_or(false),
                    budget_units: seat.budget_units,
                })
            })
            .transpose()?;
        Ok(DecisionsSettings {
            auto_check,
            seat,
            system_one,
        })
    }
}
