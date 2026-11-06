//! The self-model a resident's compaction home wears (FIX 4570).
//!
//! One explicit binding per actor names the SUMMARY its home wears as its
//! self-model, by ref only: no words are copied, no persona is kept per
//! model, and nothing infers a latest summary. The owner sets it, or the
//! actor through its own door; either first proves, through the actor's own
//! scoped SUMMARY read, that the SUMMARY is a standing, current `self_model`
//! SUMMARY the actor owns. Every home load proves it again the same way at
//! the caller's place, and names the part absent when it no longer holds,
//! with why. With no binding the part stays absent as
//! `no_self_model_binding`. An actor's erase drops its binding.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::scope_summary::SelfModelRead;
use crate::side_table::{self, Named, SideTable};
use crate::store::ManifestDbs;
use crate::vault::RevisionRef;
use serde::{Deserialize, Serialize};

/// Each actor's bound self-model SUMMARY. Key: id16(actor).
const SELF_MODEL_BINDING: SideTable<EntityId, SelfModelBinding, Named> =
    SideTable::new(&side_table::ACTOR_SELF_MODEL_SUMMARY);

/// One actor's binding: the SUMMARY its home wears as its self-model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SelfModelBinding {
    summary: EntityId,
}

/// The SUMMARY `actor`'s binding names, as `dbs` reads it in `txn`.
pub(crate) fn bound_self_model_in(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Option<EntityId>> {
    Ok(SELF_MODEL_BINDING
        .get(dbs, txn, actor)?
        .map(|binding| binding.summary))
}

/// Drops `actor`'s binding with the actor: its side-row actor scrub.
pub(crate) fn erase_self_model_binding_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    SELF_MODEL_BINDING.delete(vault, txn, actor)?;
    Ok(())
}

/// Binds `actor` to `summary`, or clears its binding with `None`. A
/// binding that no longer names the SUMMARY it named withdraws, in the same
/// write, every self-written summary of `actor` that wore the old one
/// (FIX 4817): their home pin no longer stands.
fn put_binding_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    summary: Option<EntityId>,
) -> Result<()> {
    let previous = bound_self_model_in(&vault.store, txn, &actor)?;
    match summary {
        Some(summary) => {
            SELF_MODEL_BINDING.put(vault, txn, &actor, &SelfModelBinding { summary })?;
        }
        None => {
            SELF_MODEL_BINDING.delete(vault, txn, &actor)?;
        }
    }
    match previous {
        Some(old) if Some(old) != summary => {
            let custody = crate::secret_custody::CustodyWrite::of(vault);
            crate::ports::withdraw_changed_home_dependents_in_txn(&custody, txn, &old)
        }
        _ => Ok(()),
    }
}

/// The self-model part of a home: the bound SUMMARY with its words and the
/// revision they were read at, or why it is absent.
pub(super) enum SelfModelPart {
    Worn {
        summary: EntityId,
        revision: Option<RevisionRef>,
        text: String,
    },
    Absent(&'static str),
}

/// Reads `agent`'s bound self-model through `memory`, the agent's own read
/// at its caller's place. A binding that cannot be read is `unreadable`.
pub(super) fn read_self_model_part(
    vault: &Vault,
    memory: &Memory<'_>,
    agent: EntityId,
) -> SelfModelPart {
    let bound = vault
        .store
        .env
        .read_txn()
        .map_err(Error::from)
        .and_then(|txn| bound_self_model_in(&vault.store, &txn, &agent));
    let summary = match bound {
        Ok(Some(summary)) => summary,
        Ok(None) => return SelfModelPart::Absent("no_self_model_binding"),
        Err(_) => return SelfModelPart::Absent("unreadable"),
    };
    match memory.read_self_model_summary(&summary) {
        Ok(SelfModelRead::Read { text, revision }) => SelfModelPart::Worn {
            summary,
            revision,
            text,
        },
        Ok(SelfModelRead::Absent(why)) => SelfModelPart::Absent(why),
        Err(_) => SelfModelPart::Absent("unreadable"),
    }
}

/// Whether `memory`'s actor reads `summary` as its own current self-model.
fn reads_as_own_self_model(memory: &Memory<'_>, summary: &EntityId) -> MemoryResult<bool> {
    Ok(matches!(
        memory.read_self_model_summary(summary)?,
        SelfModelRead::Read { .. }
    ))
}

impl Vault {
    /// The owner binds agent `actor`'s self-model to `summary`, or clears it
    /// with `None` (FIX 4570). The SUMMARY must read, through `actor`'s own
    /// scoped SUMMARY read, as a standing, current `self_model` SUMMARY
    /// `actor` owns.
    ///
    /// # Errors
    ///
    /// A stale owner proof; a SUMMARY `actor` does not read as its own
    /// current self-model; a storage error.
    pub fn bind_self_model_summary(
        &self,
        owner: &AuthenticatedOwner,
        actor: EntityId,
        summary: Option<EntityId>,
    ) -> Result<()> {
        if let Some(summary) = summary {
            let memory = self.memory(actor, EdgeActorClass::Agent);
            if !reads_as_own_self_model(&memory, &summary).unwrap_or(false) {
                return Err(oneiron_store::scope_summary::codec::invalid(
                    "the SUMMARY is not the actor's own current self-model",
                ));
            }
        }
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            put_binding_in_txn(self, txn, actor, summary)
        })
    }
}

impl Memory<'_> {
    /// This agent binds its own self-model to `summary`, or clears it with
    /// `None` (FIX 4570). The SUMMARY must read, through this agent's own
    /// scoped SUMMARY read, as a standing, current `self_model` SUMMARY it
    /// owns.
    ///
    /// # Errors
    ///
    /// A caller that is no agent; a SUMMARY it does not read as its own
    /// current self-model; a storage error.
    pub fn bind_own_self_model_summary(&self, summary: Option<EntityId>) -> MemoryResult<()> {
        if self.actor_class() != EdgeActorClass::Agent {
            return Err(MemoryError::bad_request(
                "only an agent binds its own self-model",
            ));
        }
        if let Some(summary) = summary
            && !reads_as_own_self_model(self, &summary)?
        {
            return Err(MemoryError::bad_request(
                "the SUMMARY is not this agent's own current self-model",
            ));
        }
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            Ok(put_binding_in_txn(self.vault(), txn, actor, summary)?)
        })
    }
}
