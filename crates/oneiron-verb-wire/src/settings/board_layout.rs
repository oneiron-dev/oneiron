//! Moved from `crates/oneiron/src/settings/board_layout.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::context_board::layout::BoardLayout;
use crate::context_board::layout::BoardLayoutError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The owner's board cap and layout layers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardLayoutSettings {
    /// The board cap in tokens. Absent, each harness's default applies. A
    /// caller may still ask for less, never silently more (ARCH-0067 §3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_tok: Option<u64>,
    /// The layout an agent's board renders under until the agent lays out
    /// its own.
    #[serde(default)]
    pub default_layout: BoardLayout,
    /// Sections whose layout the owner sets for every agent: each one wins
    /// over the agent's own layout of that section.
    #[serde(default)]
    pub override_layout: BoardLayout,
    /// Sections whose layout the owner sets for one agent alone, by agent
    /// id in ascending order: each wins over the agent's own layout and over
    /// `override_layout` for that agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_override_layouts: Vec<AgentBoardLayoutOverride>,
}

/// The most agents the owner may override one by one.
pub const BOARD_LAYOUT_AGENT_OVERRIDES_MAX: usize = 256;

/// The owner's override of one agent's board layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentBoardLayoutOverride {
    /// The agent whose board this override lays out.
    pub agent: EntityId,
    /// The sections the owner sets for this agent.
    pub layout: BoardLayout,
}

impl BoardLayoutSettings {
    /// Checks every layer as any layout is checked, and the per-agent list:
    /// at most [`BOARD_LAYOUT_AGENT_OVERRIDES_MAX`] agents, each once, in
    /// ascending order, none empty.
    pub fn validate(&self) -> std::result::Result<(), Error> {
        let layout = |error: BoardLayoutError| Error::InvalidConfig(error.to_string());
        self.default_layout.validate().map_err(layout)?;
        self.override_layout.validate().map_err(layout)?;
        if self.agent_override_layouts.len() > BOARD_LAYOUT_AGENT_OVERRIDES_MAX {
            return Err(Error::InvalidConfig(format!(
                "board layout overrides name {} agents; at most {BOARD_LAYOUT_AGENT_OVERRIDES_MAX}",
                self.agent_override_layouts.len()
            )));
        }
        for pair in self.agent_override_layouts.windows(2) {
            if pair[0].agent >= pair[1].agent {
                return Err(Error::InvalidConfig(
                    "board layout overrides must name each agent once, in ascending order".into(),
                ));
            }
        }
        for agent in &self.agent_override_layouts {
            if agent.layout.sections.is_empty() {
                return Err(Error::InvalidConfig(format!(
                    "board layout override of agent {} sets no section",
                    agent.agent.to_hex()
                )));
            }
            agent.layout.validate().map_err(layout)?;
            // With the override for every agent under it, the agent's
            // override must still be a layout: its shares within the cap.
            self.override_for(agent.agent).validate().map_err(layout)?;
        }
        Ok(())
    }

    /// The owner's override for `actor`'s board: the override for every
    /// agent, with this agent's own override sections laid over it.
    #[must_use]
    pub fn override_for(&self, actor: EntityId) -> BoardLayout {
        let mut layout = self.override_layout.clone();
        if let Some(agent) = self
            .agent_override_layouts
            .iter()
            .find(|agent| agent.agent == actor)
        {
            for (key, section) in &agent.layout.sections {
                layout.sections.insert(key.clone(), section.clone());
            }
        }
        layout
    }

    /// The settings with `actor`'s own override set to `layout`, or cleared
    /// when `layout` is `None` or sets no section; the list stays in
    /// ascending agent order.
    fn with_agent_override(mut self, actor: EntityId, layout: Option<BoardLayout>) -> Self {
        self.agent_override_layouts
            .retain(|agent| agent.agent != actor);
        if let Some(layout) = layout.filter(|layout| !layout.sections.is_empty()) {
            let at = self
                .agent_override_layouts
                .partition_point(|agent| agent.agent < actor);
            self.agent_override_layouts.insert(
                at,
                AgentBoardLayoutOverride {
                    agent: actor,
                    layout,
                },
            );
        }
        self
    }

    /// The cap a harness renders under: the owner's cap, else `harness_tok`.
    #[must_use]
    pub fn cap_or(&self, harness_tok: usize) -> usize {
        self.cap_tok.map_or(harness_tok, |cap| {
            usize::try_from(cap).unwrap_or(usize::MAX)
        })
    }

    /// `actor`'s own layout `own` with the owner's override for it
    /// ([`Self::override_for`]) laid over it. When the override's shares and
    /// the agent's remaining shares together pass the cap, the agent's
    /// shares give way and the override's stay.
    #[must_use]
    pub fn effective(&self, actor: EntityId, own: &BoardLayout) -> BoardLayout {
        let owner = self.override_for(actor);
        if owner.sections.is_empty() {
            return own.clone();
        }
        let mut layout = own.clone();
        for (key, section) in &owner.sections {
            layout.sections.insert(key.clone(), section.clone());
        }
        if layout.validate().is_err() {
            for (key, section) in &mut layout.sections {
                if !owner.sections.contains_key(key) {
                    section.share_pct = None;
                }
            }
        }
        layout
    }
}
