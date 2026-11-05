use serde::{Deserialize, Serialize};

use crate::authority::{ActSurface, ModelOrder, ReadLocation, SealedCopies, WorldPrivacy};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::derived_domains;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_WORLD;
use crate::{EntityId, TimeRange, Vault};

pub const CLIPBOARD_WORLD_NAME: &str = "Clipboard";
const CLIPBOARD_ROLE: &str = "clipboard";
const WORLD_ID_COUNTER_BOUND: u64 = 64;

/// The engine-owned Clipboard role in one vault's namespace. It grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardWorld {
    pub world: EntityId,
}

#[derive(Serialize, Deserialize)]
struct WorldBody {
    name: String,
    system_role: String,
}

/// The same role id in each isolated vault. Foreign imports still acquire the
/// source-vault-bound foreign world id; a display name never selects this role.
pub fn clipboard_world_id() -> Result<EntityId> {
    for counter in 0..WORLD_ID_COUNTER_BOUND {
        let id = EntityId::derive(derived_domains::CLIPBOARD_WORLD, &[&counter.to_le_bytes()])?;
        if id != crate::claim::base_world_id() && !crate::entity_id::is_foreign_world_id_range(id) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "no local Clipboard world id within the counter bound",
    ))
}

impl Vault {
    /// The Clipboard role's stored WORLD, if it has been opened. This locator
    /// is not a read grant and does not return clipboard text.
    pub fn clipboard_world(&self) -> Result<Option<ClipboardWorld>> {
        let txn = self.store.env.read_txn()?;
        let world = clipboard_world_id()?;
        Ok(self
            .clipboard_world_exists_in_txn(&txn, world)?
            .then_some(ClipboardWorld { world }))
    }

    /// Opens the dedicated world under the actual owner's proof. Its first
    /// privacy act makes plaintext readable on the owner's machines only and
    /// allows sealed copies on those machines and the cloud, before any text
    /// door writes a clip. Existing owner settings are never reset on reopen.
    ///
    /// Native holder/profile/key-work failures retain their existing types;
    /// this door does not manufacture a profile or fall back to Everywhere.
    pub fn open_clipboard_world(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
    ) -> Result<ClipboardWorld> {
        let world = clipboard_world_id()?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            match self.get_entity_type_in_txn(txn, &world)? {
                Some(ENTITY_TYPE_WORLD) => {
                    self.clipboard_world_exists_in_txn(txn, world)?;
                }
                Some(_) => return Err(Error::InvalidClaimBody("Clipboard role id is not a WORLD")),
                None => {
                    let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                    let body = rmp_serde::to_vec_named(&WorldBody {
                        name: CLIPBOARD_WORLD_NAME.to_owned(),
                        system_role: CLIPBOARD_ROLE.to_owned(),
                    })
                    .map_err(|_| Error::InvariantViolation("Clipboard world encoding failed"))?;
                    self.batch_in()
                        .put(
                            &world,
                            ENTITY_TYPE_WORLD,
                            TimeRange { start: at, end: at },
                            at,
                            &body,
                        )
                        .apply(txn)?;
                }
            }
            Ok(())
        })?;
        let revision = self.world_privacy_revision(world)?;
        if revision.0 == [0; 32] {
            match self.set_world_privacy_as(
                owner,
                surface,
                world,
                WorldPrivacy {
                    read: ReadLocation::MyMachines,
                    sealed: SealedCopies::CloudAndMyMachines,
                    models: ModelOrder::Inherit,
                },
                Some(revision),
            ) {
                Ok(_) => {}
                Err(error @ Error::ConcurrentWrite(_)) => {
                    // Another opener or an owner choice installed the settings.
                    // Preserve that nonzero revision, never retry our defaults over it.
                    if self.world_privacy_revision(world)?.0 == [0; 32] {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(ClipboardWorld { world })
    }

    pub(super) fn clipboard_world_exists_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        world: EntityId,
    ) -> Result<bool> {
        let Some(row) = self.store.port_entity_record(txn, &world)? else {
            return Ok(false);
        };
        if row.entity_type != ENTITY_TYPE_WORLD {
            return Err(Error::InvalidClaimBody("Clipboard role id is not a WORLD"));
        }
        let body: WorldBody = rmp_serde::from_slice(&row.body)
            .map_err(|_| Error::InvalidClaimBody("Clipboard WORLD has no role marker"))?;
        if body.system_role != CLIPBOARD_ROLE {
            return Err(Error::InvalidClaimBody(
                "Clipboard role id belongs to another WORLD",
            ));
        }
        Ok(true)
    }
}
