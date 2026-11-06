//! The owner's board layout settings (BOARD-LAYOUT = A, owner 2026-11-03
//! 20:25: "better to just set the cap and let the agent manage"). The owner
//! sets the board cap; an agent lays out its own board inside it. Two more
//! owner layers are optional: a default layout, which an agent's board
//! renders under until the agent lays out its own, and an override, whose
//! sections win over any agent's own layout of those sections. The owner may
//! also override one agent's layout alone ("you can configure the defaults
//! or change it too"); that agent's override sections win over both.
//!
//! Absent, every layer reads empty: the harness default cap applies and the
//! agents' own layouts render as they are. Every change records the owner's
//! act with the settings it replaces, as the other owner policy settings do.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::context_board::{BoardLayout, BoardLayoutError};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// The owner's board layout settings. Absent reads empty.
const BOARD_LAYOUT_SETTINGS: SideTable<(), BoardLayoutSettings, Named> =
    SideTable::new(&side_table::BOARD_LAYOUT_SETTINGS);

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

/// An actor's erase removes the owner's override of that agent's board
/// layout alone (FIX 3520); the other layers stay. A restore or a replayed
/// erase runs it again and finds nothing to remove.
pub(crate) fn erase_board_layout_agent_override_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let Some(mut settings) = BOARD_LAYOUT_SETTINGS.get(&vault.store, &*txn, &())? else {
        return Ok(());
    };
    let before = settings.agent_override_layouts.len();
    settings
        .agent_override_layouts
        .retain(|agent| agent.agent != *actor);
    if settings.agent_override_layouts.len() != before {
        BOARD_LAYOUT_SETTINGS.put(&vault.store, txn, &(), &settings)?;
    }
    Ok(())
}

/// The owner's board layout settings in `txn`, absent read empty.
pub(crate) fn board_layout_settings_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BoardLayoutSettings> {
    Ok(BOARD_LAYOUT_SETTINGS
        .get(&vault.store, txn, &())?
        .unwrap_or_default())
}

impl Vault {
    /// The owner's board cap and layout layers, absent read empty.
    pub fn board_layout_settings(&self) -> Result<BoardLayoutSettings> {
        let rtxn = self.store.env.read_txn()?;
        board_layout_settings_in_txn(self, &rtxn)
    }

    /// The owner sets the board cap, the default layout, the override, one
    /// agent's override, or any of them; `None` leaves one as it is, and
    /// `Some(None)` clears the cap. `agent_override` names the agent and its
    /// layout; a `None` or empty layout clears that agent's override, and a
    /// layout set must name an entity the vault holds. The Owner is
    /// revalidated in the writer, and the settings are
    /// written only when they change. A change records the owner's act with
    /// the settings it replaces when `surface` names where the owner said
    /// so, in the same commit. Answers the settings as they now read.
    pub fn set_board_layout_settings(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<crate::authority::ActSurface>,
        cap_tok: Option<Option<u64>>,
        default_layout: Option<BoardLayout>,
        override_layout: Option<BoardLayout>,
        agent_override: Option<(EntityId, Option<BoardLayout>)>,
    ) -> Result<BoardLayoutSettings> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let prior = board_layout_settings_in_txn(self, txn)?;
            let mut settings = prior.clone();
            if let Some(cap) = cap_tok {
                settings.cap_tok = cap;
            }
            if let Some(layout) = default_layout {
                settings.default_layout = layout;
            }
            if let Some(layout) = override_layout {
                settings.override_layout = layout;
            }
            if let Some((agent, layout)) = agent_override {
                // An empty layout clears, as `None` does; a layout set names
                // an agent the vault holds: its AGENT_DEF or its PERSON.
                let layout = layout.filter(|layout| !layout.sections.is_empty());
                if layout.is_some() {
                    let kind = self
                        .entity_header_in_txn(&*txn, &agent)?
                        .map(|header| header.entity_type);
                    if !matches!(
                        kind,
                        Some(
                            crate::registry::ENTITY_TYPE_AGENT_DEF
                                | crate::registry::ENTITY_TYPE_PERSON
                        )
                    ) {
                        return Err(Error::InvalidConfig(format!(
                            "board layout override names {}, which is no agent the vault holds",
                            agent.to_hex()
                        )));
                    }
                }
                settings = settings.with_agent_override(agent, layout);
            }
            settings.validate()?;
            if settings != prior {
                BOARD_LAYOUT_SETTINGS.put(&self.store, txn, &(), &settings)?;
                let signed = crate::policy_setting_doors::record_policy_setting_act_in_txn(
                    self,
                    txn,
                    crate::policy_setting_doors::PolicySetting::BoardLayout,
                    actor,
                    surface,
                    &prior,
                    &settings,
                )?;
                // The signed record goes last, best effort (FIX 4624).
                if let Some(act) = signed {
                    self.record_policy_setting_op_in_txn(txn, act);
                }
            }
            Ok(settings)
        })
    }
}
