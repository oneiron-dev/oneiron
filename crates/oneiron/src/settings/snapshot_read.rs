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

#[doc(hidden)]
pub use oneiron_verb_wire::settings::snapshot_read::SnapshotReadSettings;

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
