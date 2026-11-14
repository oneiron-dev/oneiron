//! The custody revokes this install still owes the owner's other machines
//! (CALLS CUSTODY_REVOKE_PENDING_CARRY): one value-free row per custody
//! record. Custody's revoke carry (`secret_custody::control`) writes and
//! settles them; an erase of the owner drops his. A revoke may be a
//! person's own act instead (Engine RULING L6-03-WRITER-CARRY): the person
//! who wrote a found key and ruled it no secret; an erase of that person
//! drops theirs the same way.

use oneiron_authority::authority::{ActBy, ActSurface, CustodyRevokeScreen};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::vault::Vault;

/// Each revoke this install still owes the owner's other machines, by
/// custody record id.
pub(crate) const PENDING: SideTable<EntityId, PendingRevoke, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_PENDING_REVOKE);

/// One revoke this install has not carried yet. It holds no value and no
/// proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingRevoke {
    /// The PERSON the revoke is by: the vault owner, or with `by_person`
    /// the person who wrote the key.
    pub(crate) owner: EntityId,
    /// Where it was decided: audit only.
    pub(crate) surface: ActSurface,
    /// The second the revoke was made at: its transition's.
    pub(crate) at: u64,
    /// The generation it revoked.
    pub(crate) generation: u32,
    /// Whether the revoke is `owner`'s own act as the person who wrote the
    /// key and ruled it no secret ([`ActBy::Person`]), not a vault owner's.
    /// A row written before this field reads as the owner's.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) by_person: bool,
    /// The found-key ruling's value-free screen the revoke carries
    /// (L6-03-RULED-SCREEN-LOCAL); a row written before this field reads as
    /// carrying none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) screen: Option<CustodyRevokeScreen>,
}

impl PendingRevoke {
    /// Who the carried act names as deciding.
    pub(crate) const fn by(&self) -> ActBy {
        if self.by_person {
            ActBy::Person
        } else {
            ActBy::Owner
        }
    }
}

/// Erasing `actor` (FIX 3520): a revoke still owed for them, the owner's or
/// their own as a writer, is dropped, so no act is carried in their name.
/// One-way, in the erase's own transaction.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_pending_revoke_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (id, pending) in PENDING.scan(&vault.store, wtxn)? {
        if pending.owner == *actor {
            PENDING.delete(&vault.store, wtxn, &id)?;
        }
    }
    Ok(())
}
