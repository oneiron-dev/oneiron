//! Existing batch admission, carried to actual communication head writes.

use super::super::actor_content::ContentWriteSet;
use super::reference_read::{self, GatedClaim};
use crate::claim::ScopedRead;
use crate::comm::ProjectedHeadAdmission;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::{Vault, WriteActor};
use std::collections::BTreeSet;

enum Bound<'a, 'read> {
    Actor(&'a WriteActor),
    Reader(&'a ScopedRead<'read>),
}

pub(super) struct CommHeadWrites<'a, 'read> {
    bound: Bound<'a, 'read>,
    effects: Option<ContentWriteSet>,
    heads: BTreeSet<EntityId>,
}

impl<'a, 'read> CommHeadWrites<'a, 'read> {
    pub(super) fn actor(actor: &'a WriteActor) -> Self {
        Self {
            bound: Bound::Actor(actor),
            effects: None,
            heads: BTreeSet::new(),
        }
    }

    pub(super) fn reader(reader: &'a ScopedRead<'read>) -> Self {
        Self {
            bound: Bound::Reader(reader),
            effects: None,
            heads: BTreeSet::new(),
        }
    }

    pub(super) fn gated_claims(
        self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<GatedClaim>> {
        reference_read::projected_head_claims(vault, txn, &self.heads)
    }
}

impl ProjectedHeadAdmission for CommHeadWrites<'_, '_> {
    fn before(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        ids: &[EntityId],
        local_puts: &[EntityId],
    ) -> Result<()> {
        match self.bound {
            Bound::Actor(actor) => {
                self.effects = ContentWriteSet::before_heads(vault, txn, actor, ids, local_puts)?;
            }
            Bound::Reader(reader) => {
                if !reference_read::head_targets_admitted(vault, reader, txn, ids.iter().copied())?
                {
                    return Err(Error::EntityNotFound);
                }
            }
        }
        Ok(())
    }

    fn after(&mut self, vault: &Vault, txn: &mut heed::RwTxn<'_>, _ids: &[EntityId]) -> Result<()> {
        if let Bound::Actor(actor) = self.bound {
            if let Some(effects) = self.effects.take() {
                effects.after(vault, txn, actor)?;
            }
        }
        Ok(())
    }

    fn projected(&mut self, ids: &[EntityId]) {
        self.heads.extend(ids.iter().copied());
    }
}
