//! The local publisher's complete stored source and exact native extension.

use loro::ID;

use super::super::{EntityDoc, storage};
use super::codec::{LocalSkillStateFact, SkillStateFact};
use super::inspect::{NativeMapInventory, NativeMapWrite, inspect};
use crate::batch::NativeSkillFinalInput;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// Closed source of an in-process local publication. Its constructor reads the
/// real old head and complete document in the applying writer. The stored
/// source invariant must cover every ingress before native doors are enabled;
/// this is not a constructor for caller-supplied rows or decoded snapshots.
pub(super) struct LocalSkillStateSource {
    entity: EntityId,
    head: Vec<u8>,
    frontier: Vec<u8>,
    birth_at: u64,
    inventory: NativeMapInventory,
}

/// The exact native extension of that source, not recipient standing. No
/// decoder, signature checker or raw document constructor can produce it.
pub(super) struct LocalSkillStateAdmission {
    source: LocalSkillStateSource,
    inventory: NativeMapInventory,
}

fn invalid() -> Error {
    Error::CorruptedIndex("native SKILL state local publication source")
}

impl LocalSkillStateSource {
    pub(super) fn capture_in_txn(
        input: &NativeSkillFinalInput<'_>,
        txn: &heed::RoTxn<'_>,
    ) -> Result<(Self, storage::Head, EntityDoc)> {
        input.recheck_in_txn(txn)?;
        let store = &input.vault().store;
        let entity = input.entity();
        let head_bytes = storage::record_head_bytes(store, txn, &entity)?.ok_or_else(invalid)?;
        let head = storage::head(store, txn, &entity)?;
        let document = storage::load(store, txn, &head)?;
        let inventory = inspect(&document)?;
        validate_birth(&inventory, entity, document.birth().at)?;
        let source = Self {
            entity,
            head: head_bytes,
            frontier: document.frontier(),
            birth_at: document.birth().at,
            inventory,
        };
        Ok((source, head, document))
    }

    /// The selected value of this actual source, never a floor/history fallback.
    /// Raw history has already been captured in the same closed source owner.
    pub(super) fn previous(&self) -> Option<&SkillStateFact> {
        self.inventory.current.as_ref()
    }

    pub(super) fn admit_local(
        self,
        document: &EntityDoc,
        next: &LocalSkillStateFact,
    ) -> Result<LocalSkillStateAdmission> {
        let head: storage::Head = storage::decode(&self.head)?;
        let document_id = EntityId::from_hex(&head.document)?;
        if document.birth().entity != self.entity.to_hex()
            || document.birth().at != self.birth_at
            || !next.extends_source(self.entity, document_id, self.birth_at, &self.frontier)
        {
            return Err(invalid());
        }
        let inventory = inspect(document)?;
        validate_birth(&inventory, self.entity, self.birth_at)?;
        if inventory.floor != self.inventory.floor
            || inventory.current.as_ref() != Some(next.fact())
        {
            return Err(invalid());
        }
        // Every inherited write, including deletes and hidden inserts, keeps
        // its real Loro identity and dependencies. Equal bytes at a new id
        // do not acquire permission from a retained fact.
        let mut added: Option<ID> = None;
        for mutation in &inventory.mutations {
            if self.inventory.mutations.contains(mutation) {
                continue;
            }
            match &mutation.write {
                NativeMapWrite::Insert(fact) if fact == next.fact() && added.is_none() => {
                    added = Some(mutation.id);
                }
                _ => return Err(invalid()),
            }
        }
        if added.is_none()
            || self
                .inventory
                .mutations
                .iter()
                .any(|old| !inventory.mutations.contains(old))
        {
            return Err(invalid());
        }
        Ok(LocalSkillStateAdmission {
            source: self,
            inventory,
        })
    }
}

impl LocalSkillStateAdmission {
    /// Recheck the real old source before a persistence continuation consumes
    /// this owner. A head or native-history replacement cannot reuse it.
    pub(super) fn recheck_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        let source = &self.source;
        if storage::record_head_bytes(&vault.store, txn, &source.entity)?.as_deref()
            != Some(source.head.as_slice())
        {
            return Err(invalid());
        }
        let head = storage::head(&vault.store, txn, &source.entity)?;
        let document = storage::load(&vault.store, txn, &head)?;
        if document.frontier() != source.frontier || inspect(&document)? != source.inventory {
            return Err(invalid());
        }
        Ok(())
    }

    /// Uses come from the same complete admitted inventory, not a second
    /// history export or a lookup that reconstructs an erased writer.
    pub(super) fn writer_tokens(&self) -> Result<std::collections::BTreeSet<EntityId>> {
        self.inventory.writer_tokens()
    }
}

fn validate_birth(inventory: &NativeMapInventory, entity: EntityId, birth_at: u64) -> Result<()> {
    let check = |fact: &SkillStateFact| {
        if fact.target_birth_is(entity, birth_at) {
            Ok(())
        } else {
            Err(invalid())
        }
    };
    if let Some(current) = &inventory.current {
        check(current)?;
    }
    if let Some(floor) = &inventory.floor
        && let Some(fact) = &floor.fact
    {
        check(fact)?;
    }
    for mutation in &inventory.mutations {
        if let NativeMapWrite::Insert(fact) = &mutation.write {
            check(fact)?;
        }
    }
    Ok(())
}
