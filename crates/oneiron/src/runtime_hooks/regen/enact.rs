//! Hook regen enacted by hand (ARCH-0080 §8, FIX 4690): the owner sets a
//! waiting decision aside ([`Vault::cancel_hook_regen`]) or reverts an
//! adoption to the body it replaced ([`Vault::revert_hook_regen`]). Neither
//! leaves a blank body: a cancel changes no body, and a revert installs the
//! exact body the adoption replaced, through the owner's own pack put. Both
//! decline the contract in force, so the engine's own pass leaves the hook
//! on its body until the contract moves again, and both land a receipt in
//! the hook's regen history. A hook an agent authored takes every new body
//! through that agent's own put ([`HookPut`]), so it stays the agent's.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::{
    HookAuthor, PackHookBinding, PackInstallDisposition, PackInstallReceipt, PackSource,
    PreparedPackPut,
};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault, WriteActor};

use super::history::{self, HookRegenActor, HookRegenEvent};
use super::{
    HookContractStamp, HookRegenOutcome, HookRegenPrior, HookRegenRecord, REGEN, body_hash,
    files_with_hook_body, pending_candidate,
};

/// Whose put installs a hook body a regen enacts (FIX 4692).
#[derive(Clone, Copy)]
pub(crate) enum HookPut<'a> {
    /// The owner's own put, which revalidates the owner in its writer.
    Owner(&'a AuthenticatedOwner),
    /// The authoring agent's own put of the `local` pack: the hook binds as
    /// the agent's again, at its ceiling, its grant carried. `owner` is the
    /// owner's proof when the owner enacts it, revalidated in the writer.
    Agent {
        agent: WriteActor,
        owner: Option<&'a AuthenticatedOwner>,
    },
}

impl HookPut<'_> {
    /// The put that installs a new body for `row`'s hook: a hook an agent
    /// authored installs through that agent's own put whoever enacts it, so
    /// it stays the agent's; an agent enacts only a hook it authored.
    pub(crate) fn for_hook(self, row: &PackHookBinding) -> Result<Self> {
        match (self, &row.author) {
            (Self::Owner(owner), HookAuthor::Agent { agent }) => Ok(Self::Agent {
                agent: WriteActor::new(*agent, EdgeActorClass::Agent),
                owner: Some(owner),
            }),
            (Self::Owner(_), _) => Ok(self),
            (Self::Agent { agent, .. }, HookAuthor::Agent { agent: author })
                if agent.entity_ref() == *author =>
            {
                Ok(self)
            }
            (Self::Agent { .. }, _) => Err(Error::InvalidConfig(
                "an agent enacts a regen only on a hook it authored".to_owned(),
            )),
        }
    }

    /// Prepares the put of `files` outside the writer.
    pub(crate) fn prepare(self, vault: &Vault, files: Vec<HubFile>) -> Result<PreparedPackPut> {
        match self {
            Self::Owner(_) => vault.prepare_owner_pack_put(files),
            Self::Agent { .. } => vault.prepare_agent_local_pack_put(files),
        }
    }

    /// Sets binding `binding`'s dial to `enabled` in the caller's writer, as
    /// this put writes its rows: the owner's, or the authoring agent's.
    fn set_enabled_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        binding: EntityId,
        enabled: bool,
    ) -> Result<()> {
        match self {
            Self::Owner(owner) => {
                vault.set_pack_hook_enabled_by_owner_in_txn(txn, owner, binding, enabled)
            }
            Self::Agent { agent, .. } => {
                vault.set_pack_hook_enabled_by_agent_in_txn(txn, agent, binding, enabled)
            }
        }
    }

    /// The prepared put in the caller's writer.
    pub(crate) fn put_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        prepared: &PreparedPackPut,
    ) -> Result<PackInstallDisposition> {
        match self {
            Self::Owner(owner) => vault.put_owner_pack_prepared_in_txn(txn, owner, prepared),
            Self::Agent { agent, owner } => {
                if let Some(owner) = owner {
                    owner.revalidate_in_txn(vault, txn)?;
                }
                vault.put_agent_pack_prepared_in_txn(txn, &agent, prepared)
            }
        }
    }
}

/// What a cancel set aside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookRegenCancel {
    /// The candidate set aside, as BLAKE3 hex; absent for a failed regen's
    /// decision, which holds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_hash: Option<String>,
    /// The contract the decision targeted, now declined.
    pub declined: HookContractStamp,
}

/// The CALL behind the cancel fence: a cancel sets aside only the decision
/// its caller read. A candidate is named by its hash; a failed regen's
/// decision, which holds none, by no hash.
fn named_pending(record: &HookRegenRecord, candidate_hash: Option<&str>) -> Result<()> {
    let Some(pending) = record.pending.as_ref() else {
        return Err(Error::InvalidConfig("no regen is pending".to_owned()));
    };
    if pending.candidate_hash().as_deref() != candidate_hash {
        return Err(Error::InvalidConfig(
            "the pending regen is not the candidate named: read the record again".to_owned(),
        ));
    }
    Ok(())
}

/// The CALL behind the revert fence: a revert takes out only the adopted
/// body its caller named, and only while the body it replaced is kept.
fn revert_prior<'a>(
    record: Option<&'a HookRegenRecord>,
    adopted_hash: &str,
) -> Result<&'a HookRegenPrior> {
    let record = record.ok_or_else(|| Error::InvalidConfig("no adoption to revert".to_owned()))?;
    if record.body_hash != adopted_hash {
        return Err(Error::InvalidConfig(
            "the hook's body is not the adopted body named: read the record again".to_owned(),
        ));
    }
    record
        .previous
        .as_ref()
        .ok_or_else(|| Error::InvalidConfig("no adoption to revert".to_owned()))
}

impl Vault {
    /// Sets aside the decision waiting on `binding`, as the owner: a
    /// candidate named by `candidate_hash`, or a failed regen's decision
    /// named by none. The hook keeps its body, and the contract the decision
    /// targeted is declined: neither the due list nor the engine's own pass
    /// regenerates the hook again until the contract moves. The owner may
    /// still run a regen by hand.
    ///
    /// # Errors
    ///
    /// An unknown binding, no decision waiting, a decision other than the one
    /// named, the owner's proof, and storage errors.
    pub fn cancel_hook_regen(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
        candidate_hash: Option<&str>,
    ) -> Result<HookRegenCancel> {
        let (_, row) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let mut record = REGEN
                .get(&self.store, txn, &binding)?
                .ok_or_else(|| Error::InvalidConfig("no regen is pending".to_owned()))?;
            named_pending(&record, candidate_hash)?;
            let Some(pending) = record.pending.take() else {
                return Err(Error::InvalidConfig("no regen is pending".to_owned()));
            };
            let cancel = HookRegenCancel {
                candidate_hash: pending.candidate_hash(),
                declined: pending.target().clone(),
            };
            record.declined = Some(cancel.declined.clone());
            REGEN.put(self, txn, &binding, &record)?;
            history::append_in_txn(
                self,
                txn,
                binding,
                &row,
                &record.body_hash,
                &HookRegenActor::Owner { actor },
                HookRegenEvent::Cancelled {
                    candidate_hash: cancel.candidate_hash.clone(),
                    declined: cancel.declined.clone(),
                },
            )?;
            Ok(cancel)
        })
    }

    /// Reverts the adoption `binding` stands on, as the owner: the body the
    /// adoption replaced is installed again through the owner's own pack put,
    /// named by `adopted_hash`, the hash of the adopted body taken out. Only
    /// a put that installs moves the record: back to that body under the
    /// contract it passed under, with the contract in force declined. A
    /// decision waiting on the adopted body is set aside with it. A Candidate
    /// or Blocked put changes nothing and is answered as it is.
    ///
    /// # Errors
    ///
    /// An unknown binding, no adoption kept to revert, a body other than the
    /// one named, the put's own refusals, and storage errors.
    pub fn revert_hook_regen(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
        adopted_hash: &str,
    ) -> Result<PackInstallDisposition> {
        let (_, row) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        let put = HookPut::Owner(owner).for_hook(&row)?;
        on_adopted_body(&row, adopted_hash)?;
        let record = self.hook_regen_record(binding)?;
        let prior = revert_prior(record.as_ref(), adopted_hash)?.clone();
        let (installed, source) = self.installed_hook_pack(&row)?;
        let (files, _) = files_with_hook_body(&source, &row.hook, prior.body.as_bytes());
        let prepared = put.prepare(self, files)?;
        let disposition = self.with_write_txn_grouped(|txn| {
            let (_, current) = self
                .pack_hook_bindings_in_txn(txn)?
                .into_iter()
                .find(|(id, _)| *id == binding)
                .ok_or(Error::EntityNotFound)?;
            pack_unmoved(self, txn, &row, &installed)?;
            on_adopted_body(&current, adopted_hash)?;
            let record = REGEN.get(&self.store, txn, &binding)?;
            let prior = revert_prior(record.as_ref(), adopted_hash)?.clone();
            let disposition = put.put_in_txn(self, txn, &prepared)?;
            if !matches!(disposition, PackInstallDisposition::Installed(_)) {
                return Ok(disposition);
            }
            let rebound = self.rebound_in_txn(txn, &current, &prior.body_hash, binding)?;
            // The restored body takes the dial of the body it replaces: the
            // install keeps a returning binding's own dial, which the
            // adoption turned off.
            if let Some(restored) = rebound {
                put.set_enabled_in_txn(self, txn, restored, current.enabled)?;
            }
            let declined = HookContractStamp::current();
            let reverted = HookRegenRecord {
                body_hash: prior.body_hash.clone(),
                stamp: prior.stamp,
                intent: record.and_then(|record| record.intent),
                pending: None,
                previous: None,
                declined: Some(declined.clone()),
            };
            for id in std::iter::once(binding).chain(rebound) {
                REGEN.put(self, txn, &id, &reverted)?;
            }
            // The receipt names the owner this act's own transaction proves.
            let actor = owner.revalidate_in_txn(self, txn)?;
            history::append_in_txn(
                self,
                txn,
                binding,
                &current,
                &prior.body_hash,
                &HookRegenActor::Owner { actor },
                HookRegenEvent::Reverted {
                    from_hash: adopted_hash.to_owned(),
                    to_hash: prior.body_hash.clone(),
                    declined,
                    rebound,
                },
            )?;
            Ok(disposition)
        })?;
        if matches!(disposition, PackInstallDisposition::Installed(_)) {
            self.verb_hook_bindings_changed();
        }
        Ok(disposition)
    }
}

impl Vault {
    /// The one enactment of a pending regen, through `put` as
    /// [`HookPut::for_hook`] resolves it for the hook, with its receipt
    /// naming `by`.
    pub(in crate::runtime_hooks) fn enact_hook_regen(
        &self,
        put: HookPut<'_>,
        by: &HookRegenActor,
        binding: EntityId,
        candidate_hash: &str,
        stamped: bool,
    ) -> Result<PackInstallDisposition> {
        let (_, row) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        let put = put.for_hook(&row)?;
        let record = self.hook_regen_record(binding)?;
        let (candidate, _) = pending_candidate(record.as_ref(), candidate_hash, stamped)?;
        let (installed, source) = self.installed_hook_pack(&row)?;
        let (files, replaced) = files_with_hook_body(&source, &row.hook, candidate.as_bytes());
        // The body this adoption replaces, kept for a revert (FIX 4690).
        let replaced = replaced.and_then(|bytes| String::from_utf8(bytes).ok());
        let prepared = put.prepare(self, files)?;
        let disposition = self.with_write_txn_grouped(|txn| {
            let (_, current) = self
                .pack_hook_bindings_in_txn(txn)?
                .into_iter()
                .find(|(id, _)| *id == binding)
                .ok_or(Error::EntityNotFound)?;
            pack_unmoved(self, txn, &row, &installed)?;
            let record = REGEN.get(&self.store, txn, &binding)?;
            let (_, target) = pending_candidate(record.as_ref(), candidate_hash, stamped)?;
            let stamped_diff = matches!(
                record.as_ref().and_then(|record| record.pending.as_ref()),
                Some(HookRegenOutcome::NeedsHumanStamp { .. })
            );
            let disposition = put.put_in_txn(self, txn, &prepared)?;
            // A Candidate or Blocked put keeps the pending decision and the
            // native proposal records, without advancing the last good body.
            if !matches!(disposition, PackInstallDisposition::Installed(_)) {
                return Ok(disposition);
            }
            // The new body binds under a new id; resolve it in this writer,
            // before any other regen decision or pack install can intervene.
            let rebound = self.rebound_in_txn(txn, &current, candidate_hash, binding)?;
            // The adopted body takes the dial of the body it replaces: a
            // body the hook ran before returns under its old binding, whose
            // dial an earlier adoption turned off.
            if let Some(adopted) = rebound {
                put.set_enabled_in_txn(self, txn, adopted, current.enabled)?;
            }
            let previous = replaced
                .as_ref()
                .zip(record.as_ref())
                .map(|(body, record)| HookRegenPrior {
                    body: body.clone(),
                    body_hash: body_hash(body),
                    stamp: record.stamp.clone(),
                });
            let adopted = HookRegenRecord {
                body_hash: candidate_hash.to_owned(),
                stamp: target.clone(),
                intent: record.and_then(|record| record.intent),
                pending: None,
                previous,
                declined: None,
            };
            for id in std::iter::once(binding).chain(rebound) {
                REGEN.put(self, txn, &id, &adopted)?;
            }
            history::append_in_txn(
                self,
                txn,
                binding,
                &current,
                candidate_hash,
                by,
                HookRegenEvent::Adopted {
                    candidate_hash: candidate_hash.to_owned(),
                    target,
                    stamped: stamped_diff,
                    rebound,
                },
            )?;
            Ok(disposition)
        })?;
        if matches!(disposition, PackInstallDisposition::Installed(_)) {
            self.verb_hook_bindings_changed();
        }
        Ok(disposition)
    }

    /// The binding a body put under `current`'s hook bound under, in the
    /// acting writer, when it is a new id: the new body binds under a new
    /// id, resolved before any other regen decision or pack install can
    /// intervene.
    fn rebound_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        current: &PackHookBinding,
        body_hash: &str,
        binding: EntityId,
    ) -> Result<Option<EntityId>> {
        Ok(self
            .pack_hook_bindings_in_txn(txn)?
            .into_iter()
            .find(|(_, bound)| {
                bound.pack == current.pack
                    && bound.hook == current.hook
                    && bound.body_hash == body_hash
            })
            .map(|(id, _)| id)
            .filter(|id| *id != binding))
    }
}

impl Vault {
    /// The installed receipt of `row`'s pack and its source: a regen's put
    /// is prepared from the pack as it is installed, never from the source
    /// `row` was bound from, which another binder's put may have left
    /// behind.
    fn installed_hook_pack(
        &self,
        row: &PackHookBinding,
    ) -> Result<(PackInstallReceipt, PackSource)> {
        let installed = self
            .installed_pack(&row.pack)?
            .ok_or(Error::EntityNotFound)?;
        let source = self
            .get_pack_source(&EntityId::from_hex(&installed.source_id)?)?
            .ok_or(Error::EntityNotFound)?;
        Ok((installed, source))
    }
}

/// Refuses a put prepared from an installed pack other than the one
/// installed in the writer. Another put of the pack landed since the files
/// were prepared, and installing the stale prepared pack would undo it. The
/// caller asks again, and a new prepare starts from the pack as it stands.
fn pack_unmoved(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &PackHookBinding,
    prepared: &PackInstallReceipt,
) -> Result<()> {
    let unmoved = vault
        .installed_pack_in_txn(txn, &row.pack)?
        .is_some_and(|current| {
            current.source_id == prepared.source_id && current.content_hash == prepared.content_hash
        });
    if unmoved {
        Ok(())
    } else {
        Err(Error::ConcurrentWrite(
            "the hook's pack changed since this regen was prepared; ask again",
        ))
    }
}

/// Refuses a revert named through a binding whose body is not the adopted
/// one: only the binding the adoption installed reverts, so the restored
/// body takes that binding's dial.
fn on_adopted_body(binding: &PackHookBinding, adopted_hash: &str) -> Result<()> {
    if binding.body_hash == adopted_hash {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "a revert names the binding of the adopted body".to_owned(),
        ))
    }
}
