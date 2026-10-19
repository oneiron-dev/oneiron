//! The owner's import check for a travelling AgentPack (FIX 5493, owner
//! ruling 1-EXPORT = B plus an import check): "We allow you to import
//! stuff, but we mark that: 'Please double-check'". The agent and its
//! knowledge land in the local world its scope binds to; when that world's
//! CURRENT setting does not cover this install's own machine, a notice names
//! it and says why before it lands, and the import still lands (CALLS `FIX
//! 5493 import scope`, `FIX 5493 import timing`). A pack carries no source
//! world ids or settings, so the sender's settings are never judged here,
//! and the notice says so.
//!
//! [`Vault::preview_pack_import`] says it before the owner's put, staging and
//! writing nothing; every install (the owner's put, a hub install or sync, a
//! placement of a world-held pack) keeps the same notices on its
//! [`PackInstallReceipt`](super::PackInstallReceipt). Neither ever refuses,
//! holds or asks again for a world the check names.

use serde::{Deserialize, Serialize};

use super::PackSource;
use super::agent_admission::TravelAgent;
use crate::Vault;
use crate::authority::Destination;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::share_travel::WorldRecipientNotice;
use crate::skill_hub::HubFile;

/// What installing a pack folder would land, as the owner previews it before
/// `vault.packs.put` (FIX 5493). Nothing is staged or written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackImportPreview {
    /// The pack's name, as its manifest gives it.
    pub pack_name: String,
    /// Whether the folder carries a travelling agent.
    pub agent: bool,
    /// The name of the local world the agent and its knowledge would land
    /// in; absent for a base or all scope, while its scope names no single
    /// local world, or for a world whose body names none a read may show.
    /// A preview names no row by id, so every release off this device
    /// passes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_name: Option<String>,
    /// Whether the install would wait for the owner to pick its world.
    pub needs_world: bool,
    /// Each world whose current setting does not cover this machine: a
    /// "please double-check", never a refusal.
    pub notices: Vec<WorldRecipientNotice>,
}

impl Vault {
    /// The owner's preview of a pack folder before he installs it (FIX
    /// 5493): the world its travelling agent would land in, picked by him
    /// (`world`) or bound by its scope's name, and a notice for that world
    /// when its current setting does not cover this install. Parses the
    /// folder as the put does and reads one snapshot; stages and writes
    /// nothing.
    ///
    /// # Errors
    ///
    /// A folder the put would refuse as malformed, a picked world that is
    /// not a live local world, an owner proof that no longer holds, or
    /// storage errors.
    pub fn preview_pack_import(
        &self,
        owner: &AuthenticatedOwner,
        files: Vec<HubFile>,
        world: Option<EntityId>,
    ) -> Result<PackImportPreview> {
        let tree = PackSource::from_tree(files)?;
        let source = &tree.source;
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        if let Some(world) = world
            && !self.is_local_world_in_txn(&txn, world)?
        {
            return Err(super::invalid("the picked world is not a live local world"));
        }
        let travel = self.travel_agent_in_txn(&txn, source, world)?;
        let notices = import_notices_in_txn(self, &txn, travel.as_ref())?;
        let world_name = match travel.as_ref().and_then(TravelAgent::world) {
            Some(world) => crate::share_travel::world_label_in_txn(self, &txn, &world)?,
            None => None,
        };
        Ok(PackImportPreview {
            pack_name: source.manifest.name.clone(),
            agent: travel.is_some(),
            world_name,
            needs_world: travel.as_ref().is_some_and(TravelAgent::needs_world),
            notices,
        })
    }
}

/// The notices an import of `travel` carries, judged in `txn`: its bound
/// local world's current recipient choice for this install's machine (a
/// destination nobody proved while this install has no machine id). None
/// for a pack with no travelling agent, a base or all scope, or a world it
/// does not bind yet.
pub(super) fn import_notices_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    travel: Option<&TravelAgent>,
) -> Result<Vec<WorldRecipientNotice>> {
    let Some(world) = travel.and_then(TravelAgent::world) else {
        return Ok(Vec::new());
    };
    let machine = match crate::identity::read_machine_id_in_txn(vault, txn)? {
        Some(machine) => Destination::Machine(machine),
        None => Destination::Unknown,
    };
    let Some(hold) = crate::settings::machine_recipient_hold_in(vault, txn, world, machine)? else {
        return Ok(Vec::new());
    };
    let name = crate::share_travel::world_label_in_txn(vault, txn, &world)?;
    Ok(vec![WorldRecipientNotice::import(world, name, hold)])
}

/// [`import_notices_in_txn`] for an install's receipt: a check that cannot
/// be read names nothing and never stops the install.
pub(super) fn import_notices_kept_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    travel: Option<&TravelAgent>,
) -> Vec<WorldRecipientNotice> {
    import_notices_in_txn(vault, txn, travel).unwrap_or_else(|error| {
        tracing::warn!(%error, "pack install kept no import notice: the check did not read");
        Vec::new()
    })
}
