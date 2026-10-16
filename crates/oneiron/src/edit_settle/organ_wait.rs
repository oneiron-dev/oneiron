//! An organ call that waits for a node (OF-575, owner ruling MESH): a host
//! that cannot start an organ, with none of the owner's other nodes able to
//! run it now, holds the call here and says why. Nothing fails: a redrive
//! runs it when a node can, and its export files land beside the artifact as
//! proposals under the same ref, waiting for Keep like any other.
//!
//! The engine keeps the call's bytes and never reads them; the organ host
//! encodes and decodes them. A ref that waits here cannot also wait as a
//! proposal or settle until the call has run.

use serde::{Deserialize, Serialize};

use super::codec::{RECORD, settlement_key_parts};
use super::pending::{PENDING, validate_pending_ref};
use super::receipts::already_settled;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::provenance::made_by::MadeByTrigger;
use crate::side_table::{self, Named, SideTable};
use crate::write_envelope::WriteActor;

/// Key: id16 + hash32 (blake3 of the run ref), as the proposal landing.
const WAITS: SideTable<(EntityId, [u8; 32]), WaitRow, Named> =
    SideTable::new(&side_table::EDIT_SETTLE_ORGAN_WAIT);

/// The most bytes one held call may keep, its lent inputs included.
pub const ORGAN_WAIT_CALL_MAX_BYTES: usize = 64 << 20;
/// The most bytes of a reason or a failure a row keeps.
const TEXT_MAX_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitRow {
    run_ref: String,
    organ: String,
    verb: String,
    call: Vec<u8>,
    trigger: Option<MadeByTrigger>,
    held_by: EntityId,
    held_by_class: u8,
    held_at: u64,
    reason: String,
    tries: u32,
    last_try_at: u64,
    failed: Option<String>,
}

/// One organ call to hold until a node can run it.
#[derive(Debug, Clone, PartialEq)]
pub struct OrganWait {
    /// The artifact its export files land beside.
    pub artifact_id: EntityId,
    /// The run ref its proposals take: the consume-once key.
    pub run_ref: String,
    pub organ: String,
    pub verb: String,
    /// The call, as the organ host encodes it.
    pub call: Vec<u8>,
    pub trigger: Option<MadeByTrigger>,
    /// Who asked: the actor its proposals are made by.
    pub held_by: WriteActor,
    pub held_at: u64,
}

/// A held call as a surface shows it: what waits, since when, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganWaitView {
    pub artifact_id: EntityId,
    pub run_ref: String,
    pub organ: String,
    pub verb: String,
    pub held_by: EntityId,
    pub held_at: u64,
    /// Why it waits, in the router's words: which nodes it tried and what
    /// each said.
    pub reason: String,
    /// Redrives so far.
    pub tries: u32,
    pub last_try_at: u64,
    /// Set when a node ran the call and it failed there; it no longer
    /// waits, and stays until released so the failure is seen.
    pub failed: Option<String>,
}

impl WaitRow {
    fn view(&self, artifact_id: EntityId) -> OrganWaitView {
        OrganWaitView {
            artifact_id,
            run_ref: self.run_ref.clone(),
            organ: self.organ.clone(),
            verb: self.verb.clone(),
            held_by: self.held_by,
            held_at: self.held_at,
            reason: self.reason.clone(),
            tries: self.tries,
            last_try_at: self.last_try_at,
            failed: self.failed.clone(),
        }
    }

    fn wait(&self, artifact_id: EntityId) -> Result<OrganWait> {
        let class = EdgeActorClass::try_from_u8(self.held_by_class)
            .ok_or(Error::CorruptedIndex("organ wait actor class"))?;
        Ok(OrganWait {
            artifact_id,
            run_ref: self.run_ref.clone(),
            organ: self.organ.clone(),
            verb: self.verb.clone(),
            call: self.call.clone(),
            trigger: self.trigger.clone(),
            held_by: WriteActor::new(self.held_by, class),
            held_at: self.held_at,
        })
    }
}

fn bounded(text: &str) -> String {
    if text.len() <= TEXT_MAX_BYTES {
        return text.to_owned();
    }
    let mut end = TEXT_MAX_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

impl Vault {
    /// Holds one organ call until a node can run it, saying why it waits.
    /// A ref already settled, already waiting as a proposal, or already
    /// held is refused.
    pub fn hold_organ_wait(&self, wait: &OrganWait, reason: &str) -> Result<OrganWaitView> {
        validate_pending_ref(&wait.run_ref)?;
        if wait.call.len() > ORGAN_WAIT_CALL_MAX_BYTES {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "an organ call held for a node is over 64 MiB",
            )));
        }
        if wait.organ.trim().is_empty() || wait.verb.trim().is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "a held organ call names its organ and verb",
            )));
        }
        self.get_blob_artifact(&wait.artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let row = WaitRow {
            run_ref: wait.run_ref.clone(),
            organ: bounded(&wait.organ),
            verb: bounded(&wait.verb),
            call: wait.call.clone(),
            trigger: wait.trigger.clone(),
            held_by: wait.held_by.entity_ref(),
            held_by_class: wait.held_by.actor_class() as u8,
            held_at: wait.held_at,
            reason: bounded(reason),
            tries: 0,
            last_try_at: wait.held_at,
            failed: None,
        };
        let key = settlement_key_parts(&wait.artifact_id, &wait.run_ref);
        self.with_write_txn_grouped(|wtxn| {
            if let Some(existing) = RECORD.get(&self.store, wtxn, &key)? {
                return Err(already_settled(&existing));
            }
            if PENDING.contains(&self.store, wtxn, &key)?
                || WAITS.contains(&self.store, wtxn, &key)?
            {
                return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                    "a proposal or a held organ call already waits under this ref",
                )));
            }
            WAITS.put(&self.store, wtxn, &key, &row)
        })?;
        Ok(row.view(wait.artifact_id))
    }

    /// The organ calls held beside one artifact, oldest ref hash first.
    pub fn organ_waits(&self, artifact_id: &EntityId) -> Result<Vec<OrganWaitView>> {
        let rtxn = self.store.env.read_txn()?;
        WAITS
            .iter_from(&self.store, &rtxn, artifact_id.as_bytes())?
            .map(|row| row.map(|((artifact, _), row)| row.view(artifact)))
            .collect()
    }

    /// Every call still waiting for a node, with its bytes, for a redrive.
    /// Failed calls are not among them.
    pub fn waiting_organ_calls(&self) -> Result<Vec<(OrganWait, OrganWaitView)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for ((artifact, _), row) in WAITS.scan(&self.store, &rtxn)? {
            if row.failed.is_none() {
                out.push((row.wait(artifact)?, row.view(artifact)));
            }
        }
        Ok(out)
    }

    /// Records one redrive that found no node: why it still waits.
    pub fn note_organ_wait(
        &self,
        artifact_id: &EntityId,
        run_ref: &str,
        reason: &str,
        tried_at: u64,
    ) -> Result<()> {
        self.update_organ_wait(artifact_id, run_ref, |row| {
            row.reason = bounded(reason);
            row.tries = row.tries.saturating_add(1);
            row.last_try_at = tried_at;
        })
    }

    /// Records that a node ran the call and it failed there: it stops
    /// waiting, and stays so the failure is seen until released.
    pub fn fail_organ_wait(
        &self,
        artifact_id: &EntityId,
        run_ref: &str,
        detail: &str,
        at: u64,
    ) -> Result<()> {
        self.update_organ_wait(artifact_id, run_ref, |row| {
            row.failed = Some(bounded(detail));
            row.tries = row.tries.saturating_add(1);
            row.last_try_at = at;
        })
    }

    /// Drops a held call: it ran and landed, or a person let it go.
    /// `true` when one was held under the ref.
    pub fn release_organ_wait(&self, artifact_id: &EntityId, run_ref: &str) -> Result<bool> {
        let key = settlement_key_parts(artifact_id, run_ref);
        self.with_write_txn_grouped(|wtxn| WAITS.delete(&self.store, wtxn, &key))
    }

    fn update_organ_wait(
        &self,
        artifact_id: &EntityId,
        run_ref: &str,
        change: impl FnOnce(&mut WaitRow),
    ) -> Result<()> {
        let key = settlement_key_parts(artifact_id, run_ref);
        self.with_write_txn_grouped(|wtxn| {
            let mut row = WAITS
                .get(&self.store, wtxn, &key)?
                .ok_or(Error::EntityNotFound)?;
            if row.run_ref != run_ref {
                return Err(Error::CorruptedIndex("organ wait ref"));
            }
            change(&mut row);
            WAITS.put(&self.store, wtxn, &key, &row)
        })
    }
}
