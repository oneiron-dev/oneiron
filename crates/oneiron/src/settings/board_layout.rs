//! The owner's board layout settings (BOARD-LAYOUT = A, owner 2026-11-03
//! 20:25: "better to just set the cap and let the agent manage"). The owner
//! sets the board cap; an agent lays out its own board inside it. Two more
//! owner layers are optional: a default layout, which an agent's board
//! renders under until the agent lays out its own, and an override, whose
//! sections win over any agent's own layout of those sections.
//!
//! Absent, every layer reads empty: the harness default cap applies and the
//! agents' own layouts render as they are. Every change records the owner's
//! act with the settings it replaces, as the other owner policy settings do.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::context_board::{BoardLayout, BoardLayoutError};
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
}

impl BoardLayoutSettings {
    /// Checks both layers as any layout is checked.
    pub fn validate(&self) -> std::result::Result<(), BoardLayoutError> {
        self.default_layout.validate()?;
        self.override_layout.validate()
    }

    /// The cap a harness renders under: the owner's cap, else `harness_tok`.
    #[must_use]
    pub fn cap_or(&self, harness_tok: usize) -> usize {
        self.cap_tok.map_or(harness_tok, |cap| {
            usize::try_from(cap).unwrap_or(usize::MAX)
        })
    }

    /// `own` with the override's sections laid over it. When the override's
    /// shares and the agent's remaining shares together pass the cap, the
    /// agent's shares give way and the override's stay.
    #[must_use]
    pub fn effective(&self, own: &BoardLayout) -> BoardLayout {
        if self.override_layout.sections.is_empty() {
            return own.clone();
        }
        let mut layout = own.clone();
        for (key, section) in &self.override_layout.sections {
            layout.sections.insert(key.clone(), section.clone());
        }
        if layout.validate().is_err() {
            for (key, section) in &mut layout.sections {
                if !self.override_layout.sections.contains_key(key) {
                    section.share_pct = None;
                }
            }
        }
        layout
    }
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

    /// The owner sets the board cap, the default layout, the override, or
    /// any of them; `None` leaves one as it is, and `Some(None)` clears the
    /// cap. The Owner is revalidated in the writer, and the settings are
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
            settings
                .validate()
                .map_err(|error| Error::InvalidConfig(error.to_string()))?;
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
