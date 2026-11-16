//! The Setting vocabulary below the engine (DESIGN 15-setting-primitive section 1.2): a Setting
//! is a stored choice, for one key at one scope, that someone with the power set and that stays
//! in force until it is changed or cleared.
//!
//! This crate holds what a value type and a pure reader need, and nothing that names the engine:
//! - [`SettingValue`], the contract every stored value type meets (serde, JSON Schema, one
//!   `check` that normalises and validates);
//! - [`ScopeKind`] and [`SettingScope`], where a row applies, and the read's scope chain;
//! - [`SettingMode`], [`Restore`], [`SettingSync`], [`ReadBy`] and [`Setter`];
//! - [`RowKey`], the stored key bytes `name 0x00 item 0x00 mode scope`;
//! - [`decide`], the pure order in which a read takes its value from the rows it found:
//!   the narrowest owner pin, else the narrowest value row (the item's own row first), a
//!   holder's row held inside the owner's, or inside the catalogue default where the owner set
//!   none, on a key that names a tighter direction, else the catalogue default. A row that does
//!   not decode never reads as the default.
//!
//! The catalogue row (`SettingSpec`), the tables and the doors are the engine's: they name its
//! act classes and its grants.

mod decide;
mod key;
mod scope;
mod value;

pub use self::decide::{Decided, FoundFit, FoundRow, decide};
pub use self::key::{RowKey, check_item, check_name};
pub use self::scope::{ScopeKind, SettingScope};
pub use self::value::{EncodedValue, SettingValue, higher_is_tighter, lower_is_tighter};

use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// Whether a row is a value or the owner's pin. A pin fixes the value in force until the owner
/// changes it: no holder's row moves it. For a key the engine learns, the value row is its seed.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SettingMode {
    Value,
    Pin,
}

impl SettingMode {
    /// The byte a stored key carries for this mode.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Value => 0,
            Self::Pin => 1,
        }
    }

    /// The mode a stored key's byte names.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Value),
            1 => Some(Self::Pin),
            _ => None,
        }
    }
}

/// What a restore does to a key's rows (ARCH-0038). `refuse` is not offered: a row that needs it
/// is authority, not a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Restore {
    /// The live vault's choice stands; a restore never resets it. The default.
    Live,
    /// The choice is part of what records mean and travels with them.
    Content,
}

/// Where a key's value holds. Recorded only: no value leaves its install yet (design stage 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettingSync {
    /// The owner's choice holds on every machine of the vault. The default.
    Vault,
    /// A choice about this machine.
    Install,
}

/// Who may read a key's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReadBy {
    /// The owner, a holder of the key's `engine.controls` class, an agent whose Grant lists the
    /// key's read line (`settings.get:<key>`), and a subject for its own rows. The default.
    Holders,
    /// Any reader of the vault.
    Members,
    /// The holders, and any live Steward grant that reaches the whole vault and names an
    /// `engine.controls` class: the read of the learning dials and the snapshot bounds, which
    /// changes nothing (S66F-READ = C).
    Dials,
}

/// In which capacity a change was made: the change row's `as`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "as", rename_all = "snake_case")]
pub enum Setter {
    /// The owner, by a proof that revalidated in the write.
    Owner,
    /// A live holder of the key's class, through this grant.
    Holder { grant: EntityId },
    /// An agent through its live owner Grant that lists the key's own line
    /// (`settings.set:<key>`, DESIGN 1.2 step 3), as a holder: its value stays inside the
    /// owner's row, or the catalogue default where the owner set none; a widening asks the user
    /// (AUTH-1 = A). It never pins.
    KeyGrant { grant: EntityId },
    /// The agent or person the row's scope names, on its own row.
    Subject,
    /// An actor whose request the holders approved, through this check-in.
    Approved { check_in: EntityId },
    /// The engine itself, on a path of its own: it applies the owner's answer to this ask, or,
    /// with no ask, makes its own path's change (the change's reason names the path).
    Engine { ask: Option<EntityId> },
}

/// The value in force for one key, and the row that decided it.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved<T> {
    pub value: T,
    pub source: SettingSource,
    /// The deciding row's revision; 0 when no row decided.
    pub revision: u64,
}

/// The cell a learned key's fit is learned in (ARCH-0003 `#learning-settings`): the project its
/// runs ran under, else the vault; the project's goal, for a fit learned on that goal; the task
/// type's node, for a fit learned at one type rather than the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FitCell {
    pub project: Option<EntityId>,
    pub goal: Option<EntityId>,
    pub task_type: Option<String>,
}

/// Which row decided a read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "from", content = "scope", rename_all = "snake_case")]
pub enum SettingSource {
    /// The owner's pin at this scope.
    Pin(SettingScope),
    /// The value row at this scope.
    Row(SettingScope),
    /// A learned key's fit, learned in this cell.
    Fit(FitCell),
    /// No row: the catalogue default.
    Default,
    /// The deciding row at this scope does not decode: the key's strictest value, never the
    /// default (DEC-0005, four substrate rules, rule 4).
    Unreadable(SettingScope),
}

#[cfg(test)]
mod tests {
    use super::{EntityId, Setter};

    #[test]
    fn every_setter_round_trips_as_a_stored_row_writes_it() {
        let id = EntityId::from_bytes_unchecked([7; 16]);
        for setter in [
            Setter::Owner,
            Setter::Holder { grant: id },
            Setter::KeyGrant { grant: id },
            Setter::Subject,
            Setter::Approved { check_in: id },
            Setter::Engine { ask: Some(id) },
            Setter::Engine { ask: None },
        ] {
            let row = rmp_serde::to_vec_named(&setter).expect("a setter encodes");
            assert_eq!(
                rmp_serde::from_slice::<Setter>(&row).expect("a setter decodes"),
                setter
            );
        }
    }
}
