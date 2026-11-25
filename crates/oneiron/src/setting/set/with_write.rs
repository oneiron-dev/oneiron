//! [`Vault::set_setting_with`]: one change of a setting and a door's own writes, committed
//! together in one write.

use super::{SetSetting, SetSettingOutcome, SettingCaller, judged_change, owner_change_signs};
use super::{run_after_commit, spec_named};
use crate::Vault;
use crate::authority::OwnerProofGround;
use crate::error::Error;
use crate::store::Callback;
use crate::world_keys::owner_presence_reasons;

impl Vault {
    /// [`Self::set_setting`] with `also` run in the same write after the change, for a door
    /// whose own writes commit with the change or not at all (door 12: the issuer's clear of a
    /// machine's drain with the owner's `machines.drain.cleared_at`). `between` runs after the
    /// ask and before the turn and write. The owner's presence is asked before the write opens,
    /// so `also` reads again, inside the write, what the ask may have outlived. `also` sees the
    /// change's outcome (a `Pending` change opened its check-in in this write); an `Err` from
    /// it leaves the change out too. `also` runs inside the vault's one writer with the key's
    /// write turn held, so it must not open a write, take a write turn or ask the owner's
    /// presence.
    ///
    /// # Errors
    ///
    /// As [`Self::set_setting`]; `also`'s error.
    pub(crate) fn set_setting_with<T, E: From<Error>>(
        &self,
        caller: SettingCaller<'_>,
        request: SetSetting,
        between: impl FnOnce(),
        also: impl FnOnce(&mut heed::RwTxn<'_>, &SetSettingOutcome) -> Result<T, E>,
    ) -> Result<(SetSettingOutcome, T), E> {
        // The owner's change is checked and judged on a read first. The read drops before
        // the ask, and the ask is before the turn, so the door holds nothing while it blocks.
        let ground = match caller {
            SettingCaller::Owner(owner) if owner_change_signs(&request) => {
                let importance = judged_change::owner_change_importance(self, owner, &request)?;
                let witness =
                    self.owner_presence(importance, owner_presence_reasons::SETTING_CHANGE)?;
                Some(OwnerProofGround::witnessed(&witness))
            }
            _ => None,
        };
        between();
        // Taken before the write opens, never inside it: a holder of the turn may be waiting on
        // the writer. An unknown key takes none; the write refuses it.
        let turn = match spec_named(&request.key)
            .ok()
            .and_then(|spec| spec.write_turn)
        {
            Some(turn) => Some((turn.take)(self)?),
            None => None,
        };
        let outcome = self.write_txn_door_after_commit(
            Callback::Audited,
            |txn| {
                let outcome = self.set_setting_in_txn(txn, ground.as_ref(), caller, &request)?;
                let also = also(txn, &outcome)?;
                Ok((outcome, also))
            },
            |(outcome, also)| {
                run_after_commit(self, &[(&request, &outcome)]);
                Ok((outcome, also))
            },
        );
        // The projection pass this write's commit ran left the rows of keys with this turn for
        // later: it runs now that the turn is released.
        drop(turn);
        crate::setting::project::project_deferred_settings(self);
        outcome
    }
}
