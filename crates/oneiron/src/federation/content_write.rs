//! Actor-bound content transaction interface. Facades can read a stable
//! snapshot and apply typed programs, but cannot commit a raw batch through
//! this interface. Trusted provisioning and replay use separate Vault doors.
use crate::Vault;
use crate::batch::{EntityMetadataHeader, TxnBatchBuilder};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;
use std::collections::BTreeSet;

/// The logical owner of a direct non-batch content transition. Batches derive
/// their own complete effect set (including reducer-touched parents).
#[derive(Clone, Copy)]
enum ContentOwner {
    Note,
    Claim,
    Artifact,
}
impl ContentOwner {
    const fn kind(self) -> u8 {
        match self {
            Self::Note => crate::registry::ENTITY_TYPE_NOTE,
            Self::Claim => crate::registry::ENTITY_TYPE_CLAIM,
            Self::Artifact => crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
        }
    }
}

// This key lives only inside the active LMDB writer and is deleted before
// commit. It carries no process-global authority and cannot become a grant.
const ACTIVE_ACTOR_KEY: &[u8] = b"federation:actor-content:inflight:v1";

pub(crate) fn actor_for_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<WriteActor>> {
    let Some(raw) = vault.store.vault_meta.get(txn, ACTIVE_ACTOR_KEY)? else {
        return Ok(None);
    };
    if raw.len() != 17 && raw.len() != 49 {
        return Err(Error::CorruptedIndex("actor content in-flight binding"));
    }
    let actor = EntityId::from_bytes(
        raw[..16]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("actor content id"))?,
    )?;
    let class =
        EdgeActorClass::try_from_u8(raw[16]).ok_or(Error::CorruptedIndex("actor content class"))?;
    let writer = WriteActor::new(actor, class);
    Ok(Some(if raw.len() == 49 {
        writer.with_authority_frontier(
            raw[17..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("actor content frontier"))?,
        )
    } else {
        writer
    }))
}

pub(crate) struct ActorContentTxn<'v, 't, 'env> {
    vault: &'v Vault,
    writer: WriteActor,
    txn: &'t mut heed::RwTxn<'env>,
    pending_claim_support: BTreeSet<EntityId>,
}
impl<'v, 't, 'env> ActorContentTxn<'v, 't, 'env> {
    pub(crate) fn new(
        vault: &'v Vault,
        txn: &'t mut heed::RwTxn<'env>,
        writer: WriteActor,
    ) -> Result<Self> {
        if actor_for_txn(vault, txn)?.is_some() {
            return Err(Error::InvariantViolation(
                "nested actor content transaction",
            ));
        }
        let mut bytes = writer.entity_ref().as_bytes().to_vec();
        bytes.push(writer.actor_class() as u8);
        if let Some(frontier) = writer.authority_frontier() {
            bytes.extend_from_slice(&frontier);
        }
        vault.store.vault_meta.put(txn, ACTIVE_ACTOR_KEY, &bytes)?;
        Ok(Self {
            vault,
            txn,
            writer,
            pending_claim_support: BTreeSet::new(),
        })
    }

    /// Read-only view of the committing snapshot, not a mutation escape.
    pub(crate) fn read(&self) -> &heed::RoTxn<'_> {
        self.txn
    }

    /// Record the store clock inside this writer; the clock row is a
    /// supporting effect, not a separately granted content record.
    pub(crate) fn recorded_at(&mut self) -> Result<u64> {
        crate::ports::recorded_at_in_txn(&self.vault.store, self.txn)
    }

    /// The batch derives its semantic effect set and checks both positions
    /// before this actor's transaction can commit.
    pub(crate) fn apply_batch(&mut self, batch: TxnBatchBuilder<'_>) -> Result<()> {
        batch.apply_actor(self.txn, &self.writer)
    }

    /// Candidate admission uses the same effect collector as typed batches.
    /// This retains the caller's Gate decision/pending mode and runs before
    /// any supersession or dependent metadata settles.
    pub(crate) fn apply_claim_ops(
        &mut self,
        ops: Vec<crate::batch::BatchOp>,
        text_index_trusted: bool,
        gate_mode: crate::batch::ApplyOpsGateMode,
    ) -> Result<()> {
        crate::batch::apply_actor_ops(
            self.vault,
            self.txn,
            &self.writer,
            ops,
            text_index_trusted,
            gate_mode,
            crate::batch::BaseWriteOrigin::Ordinary,
        )
    }

    /// The existing claim must be writable before a candidate that will
    /// supersede it is staged in this writer.
    pub(crate) fn require_claim(&self, id: EntityId) -> Result<()> {
        if self.vault.shared_vault_creation_in_txn(self.txn)?.is_some() {
            self.check_record(id, ContentOwner::Claim)?;
        }
        Ok(())
    }

    /// Stage a supporting marker for a claim birth. The claim must be
    /// materialized and the support finished before the transaction commits.
    pub(crate) fn stage_claim_support(
        &mut self,
        id: EntityId,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        if self.vault.get_raw_in(self.txn, &id)?.is_some() {
            self.require_claim(id)?;
        }
        if !self.pending_claim_support.insert(id) {
            return Err(Error::InvariantViolation("duplicate actor claim support"));
        }
        write(self.txn)
    }

    pub(crate) fn finish_claim_support(
        &mut self,
        id: EntityId,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        if !self.pending_claim_support.remove(&id) {
            return Err(Error::InvariantViolation(
                "actor claim support was not staged",
            ));
        }
        self.require_claim(id)?;
        write(self.txn)?;
        self.require_claim(id)
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        if !self.pending_claim_support.is_empty() {
            return Err(Error::InvariantViolation(
                "actor claim support was not completed",
            ));
        }
        if actor_for_txn(self.vault, self.txn)? != Some(self.writer) {
            return Err(Error::CorruptedIndex(
                "actor content in-flight binding changed",
            ));
        }
        self.vault
            .store
            .vault_meta
            .delete(self.txn, ACTIVE_ACTOR_KEY)?;
        Ok(())
    }

    fn record<T, E>(
        &mut self,
        id: EntityId,
        owner: ContentOwner,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        if self.vault.shared_vault_creation_in_txn(self.txn)?.is_some() {
            self.check_record(id, owner)?;
        }
        let result = write(self.txn)?;
        if self.vault.shared_vault_creation_in_txn(self.txn)?.is_some() {
            self.check_record(id, owner)?;
        }
        Ok(result)
    }
    fn check_record(&self, id: EntityId, owner: ContentOwner) -> Result<()> {
        let raw = self
            .vault
            .get_raw_in(self.txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        if EntityMetadataHeader::parse(&raw).is_none_or(|h| h.entity_type != owner.kind()) {
            return Err(Error::InvalidEntityType(owner.kind()));
        }
        self.vault
            .authorize_shared_content_write_in_txn(self.txn, id, &self.writer)
    }

    /// A NOTE adapter owns its document/head writes. New NOTE birth is applied
    /// via `apply_batch`; this door checks existing document mutations.
    pub(crate) fn update_note<T, E>(
        &mut self,
        id: EntityId,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        self.record(id, ContentOwner::Note, write)
    }

    /// A claim-lifecycle adapter owns its target even when no Put op occurs.
    pub(crate) fn update_claim<T, E>(
        &mut self,
        id: EntityId,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        self.record(id, ContentOwner::Claim, write)
    }

    /// Blob bytes, head and version indexes are supporting effects of the
    /// artifact owner; its claim birth uses `apply_batch` in the adapter.
    pub(crate) fn update_artifact<T, E>(
        &mut self,
        id: EntityId,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        self.record(id, ContentOwner::Artifact, write)
    }
}

impl Vault {
    /// The actor-bound content entry. No raw write transaction escapes to a
    /// facade: only the typed context reaches the caller and finalization is
    /// mandatory before LMDB can commit. Host/replay doors remain separate.
    pub(crate) fn try_with_actor_content_write_txn<T, E>(
        &self,
        writer: WriteActor,
        write: impl FnOnce(&mut ActorContentTxn<'_, '_, '_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        self.try_with_write_txn(|txn| {
            // Construction proves the asserted actor's stored type. Shared
            // content effects additionally refold live authority at each
            // position; an unbound personal agent may still park a proposal.
            let raw = self
                .get_raw_in(txn, &writer.entity_ref())?
                .ok_or(Error::InvalidClaimBody("actor content writer is missing"))?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("actor content writer header"))?;
            crate::provenance::validate_actor_class(header.entity_type, writer.actor_class())?;
            let mut content = ActorContentTxn::new(self, txn, writer)?;
            let result = write(&mut content)?;
            content.finish()?;
            Ok(result)
        })
    }
}
