//! The one-tap undo of an agent's tighten (FIX 4480): the tapping holder's
//! own act (`by: Owner`), bound to the change's receipt. It restores the
//! receipt's `previous` settings on the revision right after the change, so
//! a world whose settings moved since is a conflict, never a silent
//! overwrite. One holder's tap restores them even under "widen needs every
//! owner": it returns to settings the holders already settled (CALLS "FIX
//! 4480 undo of an agent tighten").

use crate::authority::{
    ActSurface, EffectiveModelOrder, EffectiveRead, EffectiveWorldPrivacy, ModelOrder,
    ReadLocation, WorldEditAuthor, WorldPrivacy,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

use super::super::world_privacy_switch::WorldPrivacyReceipt;
use super::record::parse_revision;
use super::{key_owner_in_txn, revalidate_holder_in_txn};

/// The receipt was no agent's change: a holder's own one has no one-tap undo.
const NOT_AN_AGENT_CHANGE: &str =
    "only an agent's change has a one-tap undo; choose the settings instead";
/// The settings before the change were in conflict, which one settings edit
/// cannot state.
const PREVIOUS_CONFLICTED: &str =
    "the earlier settings were in conflict; choose the settings instead";

/// `previous` as one edit states it, or the typed refusal for a conflicted
/// state no single edit expresses.
fn restorable(previous: &EffectiveWorldPrivacy) -> Result<WorldPrivacy> {
    let read = match &previous.read {
        EffectiveRead::Everywhere => ReadLocation::Everywhere,
        EffectiveRead::MyMachines => ReadLocation::MyMachines,
        EffectiveRead::OneMachine(machine) => ReadLocation::OneMachine(*machine),
        EffectiveRead::Conflicted { .. } => {
            return Err(Error::InvalidConfig(PREVIOUS_CONFLICTED.to_owned()));
        }
    };
    let models = match &previous.models {
        EffectiveModelOrder::Inherit => ModelOrder::Inherit,
        EffectiveModelOrder::Ordered(routes) => ModelOrder::Ordered(routes.clone()),
        EffectiveModelOrder::Conflicted => {
            return Err(Error::InvalidConfig(PREVIOUS_CONFLICTED.to_owned()));
        }
    };
    Ok(WorldPrivacy {
        read,
        sealed: previous.sealed,
        models,
    })
}

impl Vault {
    /// Undoes the agent's change `receipt_id` names, as the holder `owner`'s
    /// own act from `surface` (audit only): the world's settings return to
    /// the receipt's `previous`, on the revision right after that change.
    ///
    /// # Errors
    /// [`Error::EntityNotFound`] for no such receipt;
    /// [`Error::InvalidConfig`] for a holder's own change, or a conflicted
    /// earlier state; [`Error::ConcurrentWrite`] when the world's settings
    /// moved since the change; as [`Self::set_world_privacy_as`] otherwise.
    pub fn undo_world_privacy_change(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        receipt_id: &str,
    ) -> Result<WorldPrivacyReceipt> {
        self.with_world_settings_writer(|txn, secret| {
            let receipt = self
                .world_privacy_receipt_in_txn(txn, receipt_id)?
                .ok_or(Error::EntityNotFound)?;
            if receipt.agent.is_none() {
                return Err(Error::InvalidConfig(NOT_AN_AGENT_CHANGE.to_owned()));
            }
            let world = EntityId::from_hex(&receipt.world)
                .map_err(|_| Error::CorruptedIndex("world privacy receipt world"))?;
            let actor = revalidate_holder_in_txn(self, txn, owner, world)?;
            let settings = restorable(&receipt.previous)?;
            let seen = parse_revision(&receipt.revision_after)
                .ok_or(Error::CorruptedIndex("world privacy receipt revision"))?;
            let author = WorldEditAuthor::holder(actor, surface);
            let undone =
                self.write_world_privacy_in_txn(txn, author, world, settings, Some(seen), None)?;
            let key_owner = key_owner_in_txn(self, txn, actor)?;
            self.finish_world_key_work_in_txn(txn, key_owner, undone, secret)
        })
    }
}
