//! Who an answer names, and the erase that forgets it (FIX 3520): an ask's
//! answerer, and the owner whose reason on that answer wrote a rule row.

use super::asks::ASKS;
use super::rules::RULES;
use crate::{EntityId, Result, Vault};

/// The actor an answer names (an ask's answerer, a rule row's writer), or no
/// one once that actor was erased (FIX 3520). It reads and writes as the
/// actor's hex id, or as [`crate::receipt::ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerActor {
    Actor(EntityId),
    Erased,
}

impl AnswerActor {
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

    /// Makes this no one when it is `actor`; whether it was.
    fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the decision rows.
fn names_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
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

/// Erasing `actor` from the asks (FIX 3520): each answer it gave keeps its
/// value, time, role, kind, reason and rule, and names no one. The ask stays
/// answered, since clearing the answer would reopen it. A use of the answer
/// still to run takes a live answerer: the e-sign hold refuses an erased
/// one. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing.
///
/// # Errors
///
/// Storage errors, or an ask row that cannot be read.
pub(crate) fn erase_ask_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut asks = Vec::new();
    for (seq, mut ask) in ASKS.scan(&vault.store, wtxn)? {
        if ask
            .answer
            .as_mut()
            .is_some_and(|answer| answer.by.forget(*actor))
        {
            asks.push((seq, ask));
        }
    }
    for (seq, ask) in asks {
        ASKS.put(&vault.store, wtxn, &seq, &ask)?;
    }
    Ok(())
}

/// Erasing `actor` from the rule rows (FIX 3520): every revision it wrote
/// keeps its question, evidence, answer, reason and times, and names no one.
/// A standing row still answers its question, as a row is advice and never a
/// grant; the owner's revoke still stops it. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a rule row that cannot be read.
pub(crate) fn erase_rule_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut rows = Vec::new();
    for (key, mut row) in RULES.scan(&vault.store, wtxn)? {
        if row.by.forget(*actor) {
            rows.push((key, row));
        }
    }
    for (key, row) in rows {
        RULES.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}
