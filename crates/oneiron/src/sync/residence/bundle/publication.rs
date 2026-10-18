//! The home's admission of the install the owner asked to publish the vault's
//! sealed bundle here (WILL L04 row 03), in any role: the publisher turn, a
//! stage and a commit admit the executor of any counted bundle publication
//! request that names this home and has no result yet; a list and a get admit
//! it for the one request the call names. Erase's pad rewrite admits no
//! publication, and nothing else is relaxed. The home opens nothing: each
//! reader checks the request in the bundle's signed provenance
//! (`world_keys::bundle`'s publication).

use super::denied;
use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, OwnerWorkBody};
use crate::entity_id::EntityId;
use crate::error::Result;

/// Which bundle publication may admit a peer the owner's machine rule does
/// not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Asked {
    /// None: erase's pad rewrite, and a list or a get that names no request.
    No,
    /// Any request naming the peer and this home: the turn, a stage, a
    /// commit.
    Any,
    /// The one request a list or a get names.
    Named(AuthorityEntryHash),
}

impl Asked {
    /// What a list or a get naming `request`, or none, admits.
    pub(crate) fn named(request: Option<AuthorityEntryHash>) -> Self {
        request.map_or(Self::No, Self::Named)
    }
}

/// Whether `machine` is the executor of a counted bundle publication request
/// to `home`, this install, that has no result yet and that `asked` admits.
pub(crate) fn asked_of(
    fold: &AuthorityFold,
    home: Option<EntityId>,
    machine: EntityId,
    asked: Asked,
) -> bool {
    let Some(home) = home else {
        return false;
    };
    fold.pending_owner_work_for(machine).any(|(hash, request)| {
        matches!(request.work, OwnerWorkBody::PublishBundle { home: to } if to == home)
            && match asked {
                Asked::No => false,
                Asked::Any => true,
                Asked::Named(named) => hash == named,
            }
    })
}

/// `machine`, proved under `key`, when its proof stands here on that key and
/// the owner asked it to publish here as `asked` admits ([`asked_of`]);
/// refused otherwise.
pub(super) fn asked_publisher(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    machine: EntityId,
    key: [u8; 32],
    asked: Asked,
) -> Result<EntityId> {
    let home = crate::identity::read_machine_id_in_txn(vault, txn)?;
    if fold.machine_proof_key(machine) == Some(key) && asked_of(fold, home, machine, asked) {
        Ok(machine)
    } else {
        Err(denied())
    }
}
