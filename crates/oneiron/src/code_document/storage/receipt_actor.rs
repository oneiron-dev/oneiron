//! Whose operation a code-document receipt records, and the erase that
//! forgets it (FIX 3520). An operation's Loro stamp names no actor, so the
//! erase rewrites the receipts alone: every operation, frontier, hash and
//! sequence stays, and blame, ops and range changes read it as no one's.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{CODE_DOCUMENT_HEAD, CODE_DOCUMENT_INGRESS};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;

/// Who made one operation: its actor, or no one once that actor was erased
/// (FIX 3520). It reads and writes as the actor's hex id, or as
/// [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReceiptActor {
    Actor(EntityId),
    Erased,
}

impl ReceiptActor {
    /// The actor, while it is not erased.
    pub(super) const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// Makes this no one when it is `actor`; whether it was.
    fn forget(&mut self, actor: EntityId) -> bool {
        let named = *self == Self::Actor(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

impl Serialize for ReceiptActor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Actor(id) => serializer.serialize_str(&id.to_hex()),
            Self::Erased => serializer.serialize_str(ERASED_CALL_IDENTITY),
        }
    }
}

impl<'de> Deserialize<'de> for ReceiptActor {
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

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the receipts.
fn names_no_actor(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
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

/// Erasing `actor` from the ingress receipts (FIX 3520): each operation it
/// made keeps its receipt, edit, frontiers and sequence and names no one, and
/// a replay of that ingress identity refuses. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a receipt row that cannot be read.
pub(crate) fn erase_ingress_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut named = Vec::new();
    for row in CODE_DOCUMENT_INGRESS.iter_from(&vault.store, wtxn, &[])? {
        let (operation, mut receipt) = row?;
        if receipt.actor.forget(*actor) {
            named.push((operation, receipt));
        }
    }
    for (operation, receipt) in named {
        CODE_DOCUMENT_INGRESS.put(&vault.store, wtxn, &operation, &receipt)?;
    }
    Ok(())
}

/// Erasing `actor` from the document heads (FIX 3520): a head keeps its
/// snapshot and its whole receipt history, and each operation the actor made
/// names no one there. One-way, in the erase's own transaction. An id whose
/// entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a head row that cannot be read.
pub(crate) fn erase_head_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut named = Vec::new();
    for row in CODE_DOCUMENT_HEAD.iter_from(&vault.store, wtxn, &[])? {
        let (document, mut head) = row?;
        let mut forgot = false;
        for receipt in &mut head.receipts {
            forgot |= receipt.actor.forget(*actor);
        }
        if forgot {
            named.push((document, head));
        }
    }
    for (document, head) in named {
        CODE_DOCUMENT_HEAD.put(&vault.store, wtxn, &document, &head)?;
    }
    Ok(())
}
