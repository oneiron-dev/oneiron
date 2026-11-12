//! The owner's bounds on primitive A's snapshot handles (slice 6.4b; lead 19:4x
//! S64-2-SETTINGS): one row holds all six, and an absent row reads as the
//! defaults below. The cap at a credential's own expiry is not a setting: it
//! is a security property, fixed in `crate::snapshot_read`.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// The owner's snapshot bounds. Key: ().
const SETTINGS: SideTable<(), SnapshotReadSettings, Named> =
    SideTable::new(&side_table::SNAPSHOT_READ_SETTINGS);

/// The name an engine-control receipt gives this row (untangle 6.6f): the
/// row's stored name, as every knob has.
pub const SNAPSHOT_READ_BOUNDS_KNOB: &str = "SNAPSHOT_READ_SETTINGS";

/// The bounds every snapshot handle is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotReadSettings {
    /// Handles one actor may hold open at once.
    pub open_per_actor: u32,
    /// A handle's lifetime when its opener names none, in seconds.
    pub default_lifetime_secs: u64,
    /// The longest lifetime an opener may ask for, in seconds.
    pub max_lifetime_secs: u64,
    /// The most rows one page serves.
    pub page_rows: u32,
    /// The most bytes of rows one page serves.
    pub page_bytes: u64,
    /// The most rows one handle serves over all its pages.
    pub handle_rows: u64,
}

impl SnapshotReadSettings {
    /// The defaults (lead 19:4x): 8 open per actor, 10 min by default and
    /// 60 min at most, 200 rows and 4 MiB per page, 20,000 rows per handle.
    pub const DEFAULT: Self = Self {
        open_per_actor: 8,
        default_lifetime_secs: 600,
        max_lifetime_secs: 3_600,
        page_rows: 200,
        page_bytes: 4 * 1024 * 1024,
        handle_rows: 20_000,
    };

    /// Refuses a zero bound, and a default lifetime above the most lifetime.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming the bound.
    pub fn validate(&self) -> Result<()> {
        let zero = [
            ("open_per_actor", u64::from(self.open_per_actor)),
            ("default_lifetime_secs", self.default_lifetime_secs),
            ("max_lifetime_secs", self.max_lifetime_secs),
            ("page_rows", u64::from(self.page_rows)),
            ("page_bytes", self.page_bytes),
            ("handle_rows", self.handle_rows),
        ]
        .into_iter()
        .find(|(_, bound)| *bound == 0);
        if let Some((name, _)) = zero {
            return Err(Error::InvalidConfig(format!(
                "the snapshot bound {name} must be above zero"
            )));
        }
        if self.default_lifetime_secs > self.max_lifetime_secs {
            return Err(Error::InvalidConfig(
                "the default snapshot lifetime must not exceed the most lifetime".to_owned(),
            ));
        }
        Ok(())
    }

    /// The first bound of `self` that is above the same bound of `held`.
    fn first_bound_above(&self, held: &Self) -> Option<&'static str> {
        [
            (
                "open_per_actor",
                u64::from(self.open_per_actor),
                u64::from(held.open_per_actor),
            ),
            (
                "default_lifetime_secs",
                self.default_lifetime_secs,
                held.default_lifetime_secs,
            ),
            (
                "max_lifetime_secs",
                self.max_lifetime_secs,
                held.max_lifetime_secs,
            ),
            (
                "page_rows",
                u64::from(self.page_rows),
                u64::from(held.page_rows),
            ),
            ("page_bytes", self.page_bytes, held.page_bytes),
            ("handle_rows", self.handle_rows, held.handle_rows),
        ]
        .into_iter()
        .find(|(_, bound, in_force)| bound > in_force)
        .map(|(name, _, _)| name)
    }
}

impl Default for SnapshotReadSettings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Vault {
    /// The snapshot bounds in force: the owner's row, or the defaults while
    /// he set none.
    ///
    /// # Errors
    ///
    /// Storage errors, and a stored row that does not decode.
    pub fn snapshot_read_settings(&self) -> Result<SnapshotReadSettings> {
        let txn = self.store.env.read_txn()?;
        Ok(SETTINGS.get(&self.store, &txn, &())?.unwrap_or_default())
    }

    /// [`Self::snapshot_read_settings`] under the owner's proof.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, and storage errors.
    pub fn snapshot_read_settings_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<SnapshotReadSettings> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        Ok(SETTINGS.get(&self.store, &txn, &())?.unwrap_or_default())
    }

    /// Replaces the bounds under the owner's proof. The returned bounds are
    /// the ones this transaction stored; the next page reads them.
    ///
    /// # Errors
    ///
    /// Bounds that fail [`SnapshotReadSettings::validate`], a proof that no
    /// longer holds, and storage errors.
    pub fn replace_snapshot_read_settings_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        settings: SnapshotReadSettings,
    ) -> Result<SnapshotReadSettings> {
        settings.validate()?;
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        SETTINGS.put(&self.store, &mut txn, &(), &settings)?;
        txn.commit()?;
        Ok(settings)
    }

    /// The owner, by its proof, or a holder of `engine.controls.work_budget`
    /// lowers the snapshot bounds (untangle 6.6f; Engine 9 Nov 19:48,
    /// SNAPSHOT-SETTINGS-IN-6.6, in the shape of S66B-BUDGETS B1 = A; its
    /// verb is `vault.settings.snapshot_read.lower`). The row in force is the
    /// owner's cap: each new bound must be at or below its value in force,
    /// so this door never raises one. Raising a bound stays the owner's act,
    /// at `vault.settings.snapshot_read.replace`. The cap at a credential's
    /// own expiry is not a bound of this row and does not move.
    ///
    /// The next page of any handle is held to the new page and handle
    /// bounds. A handle that is already open keeps the lifetime it was
    /// opened with, and stays open when fewer may now be open at once.
    /// Returns the receipt.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for bounds that fail
    /// [`SnapshotReadSettings::validate`]; when `actor` is neither the
    /// owner, by a proof that still holds, nor a live holder of
    /// `engine.controls.work_budget`; and for a bound above its value in
    /// force. Store failures.
    pub fn lower_snapshot_read_bounds_by(
        &self,
        actor: crate::federation::EngineControlActor<'_>,
        bounds: SnapshotReadSettings,
    ) -> Result<crate::entity_id::EntityId> {
        bounds.validate()?;
        self.apply_engine_control(
            actor,
            crate::federation::EngineControlClass::WorkBudget,
            SNAPSHOT_READ_BOUNDS_KNOB,
            &crate::federation::rendered_change(&bounds)?,
            |txn| {
                let held = SETTINGS.get(&self.store, &*txn, &())?.unwrap_or_default();
                if let Some(name) = bounds.first_bound_above(&held) {
                    return Err(Error::InvalidConfig(format!(
                        "this door only lowers the snapshot bounds, and {name} is above its value in force; raising one is the owner's act at vault.settings.snapshot_read.replace"
                    )));
                }
                SETTINGS.put(&self.store, txn, &(), &bounds)
            },
        )
    }

    /// [`Self::lower_snapshot_read_bounds_by`] for a holder of
    /// `engine.controls.work_budget` (untangle 6.6f).
    ///
    /// # Errors
    ///
    /// As [`Self::lower_snapshot_read_bounds_by`].
    pub fn lower_snapshot_read_bounds_as_holder(
        &self,
        holder: crate::entity_id::EntityId,
        bounds: SnapshotReadSettings,
    ) -> Result<crate::entity_id::EntityId> {
        self.lower_snapshot_read_bounds_by(
            crate::federation::EngineControlActor::Holder(holder),
            bounds,
        )
    }
}
