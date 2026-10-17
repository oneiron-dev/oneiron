//! `[models.planner]`: the seats a leased agent's planned spawns choose
//! among (OF-541, OF-389).
//!
//! A seat joins a model the host serves to the AGENT_DEF that runs on it.
//! The planner picks the shape (model, pattern, width) and the spawn runs the
//! seat's definition. With no seats the host lends no planner: an agent's
//! planned spawn and its leader calls answer `planner_unbound`.
use std::collections::BTreeSet;

use serde::Deserialize;

/// How many shapes the leader's advice returns when the call names no count.
const DEFAULT_TOP_SHAPES: usize = 3;

/// `[models.planner]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlannerFile {
    #[serde(default)]
    seats: Vec<PlannerSeatFile>,
    top: Option<usize>,
}

/// One `[[models.planner.seats]]` row.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannerSeatFile {
    /// The engine model ID the seat runs, `provider/model@revision`.
    model: String,
    /// The AGENT_DEF that runs on it: its hex ID, or a seeded definition's
    /// logical ID such as `sys.team_lead`.
    agent: String,
}

/// The resolved `[models.planner]` section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlannerSettings {
    pub seats: Vec<PlannerSeatSetting>,
    /// How many shapes the leader's advice returns by default.
    pub top: usize,
}

/// One seat: the model and the AGENT_DEF reference, resolved against the
/// vault when a run binds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerSeatSetting {
    pub model: oneiron::ModelId,
    pub agent: String,
}

impl PlannerFile {
    pub(super) fn resolve(self) -> anyhow::Result<PlannerSettings> {
        let mut models = BTreeSet::new();
        let mut seats = Vec::with_capacity(self.seats.len());
        for seat in self.seats {
            let model = oneiron::ModelId::new(seat.model.trim()).map_err(|error| {
                anyhow::anyhow!("models.planner.seats.model {:?}: {error}", seat.model)
            })?;
            if !models.insert(model.clone()) {
                anyhow::bail!("models.planner.seats names one seat per model ({model})");
            }
            let agent = seat.agent.trim();
            if agent.is_empty() {
                anyhow::bail!("models.planner.seats.agent must not be blank");
            }
            seats.push(PlannerSeatSetting {
                model,
                agent: agent.to_owned(),
            });
        }
        let top = match self.top.unwrap_or(DEFAULT_TOP_SHAPES) {
            0 => anyhow::bail!("models.planner.top must be above 0"),
            top => top,
        };
        Ok(PlannerSettings { seats, top })
    }
}
