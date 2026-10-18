//! Who a typed-body fork names, and the erase that forgets it (FIX 3520).
//! The office rows over these bodies name their actors the same way.

use super::{FORK_DOCS, FORKS, TypedForkState};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;
use serde::{Deserialize, Serialize};

/// Who a body row names (a fork's opener or settler, an office export's
/// actor, an office proposal's opener or answerer): an actor, or no one once
/// that actor was erased (FIX 3520). It reads and writes as the actor's hex
/// id, or as [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyActor {
    Actor(EntityId),
    Erased,
}

impl BodyActor {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// The actor, while it is not erased.
    #[must_use]
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// The actor's hex id, or [`ERASED_CALL_IDENTITY`].
    #[must_use]
    pub fn to_hex(self) -> String {
        match self {
            Self::Actor(id) => id.to_hex(),
            Self::Erased => ERASED_CALL_IDENTITY.to_owned(),
        }
    }

    /// Makes this no one when it is `actor`; whether it was.
    pub(crate) fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

impl Serialize for BodyActor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BodyActor {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

impl TypedForkState {
    /// Makes the one who settled the fork no one when it is `actor`; whether
    /// it was.
    fn forget(&mut self, actor: EntityId) -> bool {
        match self {
            Self::Open => false,
            Self::Merged { by, .. } | Self::Discarded { by, .. } => by.forget(actor),
        }
    }
}

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the body rows.
pub(crate) fn names_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// Erasing `actor` from the body forks (FIX 3520): an open fork it opened is
/// work a merge could still land, so it goes with its snapshot; a merged or
/// discarded fork keeps its row and names no one. An office fork's own
/// records go in the office scrubs. One-way, in the erase's own transaction.
/// An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a fork row that cannot be read.
pub(crate) fn erase_fork_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut forks = Vec::new();
    for (key, mut fork) in FORKS.scan(&vault.store, wtxn)? {
        let opened = fork.opener.forget(*actor);
        let settled = fork.state.forget(*actor);
        if opened || settled {
            forks.push((key, fork, opened));
        }
    }
    for (key, fork, opened) in forks {
        if opened && fork.state == TypedForkState::Open {
            FORKS.delete(&vault.store, wtxn, &key)?;
            FORK_DOCS.delete(&vault.store, wtxn, &key)?;
        } else {
            FORKS.put(&vault.store, wtxn, &key, &fork)?;
        }
    }
    Ok(())
}
