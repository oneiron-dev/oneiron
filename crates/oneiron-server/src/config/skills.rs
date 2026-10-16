//! The `[skills]` section: how the skill-edit gate's live slice is funded at
//! this server. Today it holds the pull budget of one live goal-axis
//! measurement (OF-495), which the Coach and the owner's measure route read.

use serde::Deserialize;

/// The least budget a live slice can compare two arms on.
const MIN_LIVE_PULLS: u32 = 2;

/// Resolved skill settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SkillsConfig {
    /// Live pulls per online goal axis, across both arms, that one
    /// measurement of a skill edit takes. Unset: the Coach takes no live
    /// slice, and the owner's measure must name its own budget.
    pub live_pulls_per_axis: Option<u32>,
}

impl SkillsConfig {
    pub(super) fn apply_override(&mut self, over: SkillsConfigOverride) {
        if let Some(value) = over.live_pulls_per_axis {
            self.live_pulls_per_axis = Some(value);
        }
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        if self
            .live_pulls_per_axis
            .is_some_and(|pulls| pulls < MIN_LIVE_PULLS)
        {
            anyhow::bail!("skills.live_pulls_per_axis must be at least {MIN_LIVE_PULLS}");
        }
        Ok(())
    }
}

/// One layer's `[skills]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct SkillsConfigOverride {
    pub(super) live_pulls_per_axis: Option<u32>,
}

pub(super) fn lookup_skills_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<SkillsConfigOverride>> {
    let live_pulls_per_axis = lookup("ONEIRON_SKILLS_LIVE_PULLS_PER_AXIS")
        .map(|value| {
            value.parse().map_err(|_| {
                anyhow::anyhow!(
                    "ONEIRON_SKILLS_LIVE_PULLS_PER_AXIS must be a whole count, not {value:?}"
                )
            })
        })
        .transpose()?;
    Ok(
        live_pulls_per_axis.map(|live_pulls_per_axis| SkillsConfigOverride {
            live_pulls_per_axis: Some(live_pulls_per_axis),
        }),
    )
}
