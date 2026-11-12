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

#[doc(hidden)]
pub use oneiron_verb_wire::settings::board_layout::{
    AgentBoardLayoutOverride, BOARD_LAYOUT_AGENT_OVERRIDES_MAX, BoardLayoutSettings,
};

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
