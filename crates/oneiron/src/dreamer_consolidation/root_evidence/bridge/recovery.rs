//! Native grant proofs select retained source revisions, never copied bodies.
use super::*;
use crate::WriteActor;
use crate::claim::{ClaimReadStatus, ScopedReadActorKey, ScopedReadResult};
use crate::dreamer_consolidation::resources::RowRevision;
use crate::vault::entity_revision::{ReadMode, RevisionRef, read_entity_revision_in_txn};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::dreamer_consolidation::root_evidence) struct GrantedClose {
    binding: [u8; 32],
    attempt: [u8; 16],
    actor: EntityId,
    actor_class: u8,
    prior: EntityId,
    replacement: EntityId,
    original: RevisionRef,
    granted: RowRevision,
}

impl GrantedClose {
    pub(super) fn reader_key(&self) -> Result<ScopedReadActorKey> {
        let class = crate::edge::EdgeActorClass::try_from_u8(self.actor_class)
            .ok_or_else(|| invalid_consolidation("invalid root recovery actor class"))?;
        ScopedReadActorKey::with_actor_class(self.actor.to_hex(), class.gate_actor_class())
            .ok_or_else(|| invalid_consolidation("invalid root recovery actor"))
    }
}

impl RootBinding {
    pub(super) fn load_closes(&mut self, root: &Root, actor: WriteActor, attempt: AttemptId) {
        self.closed = root
            .closes
            .iter()
            .filter(|proof| {
                proof.binding == self.identity
                    && proof.attempt == *attempt.as_bytes()
                    && proof.actor == actor.entity_ref()
                    && proof.actor_class == actor.actor_class() as u8
            })
            .map(|proof| (proof.prior, proof.clone()))
            .collect();
    }

    fn source_hash(&self, id: EntityId) -> Result<Option<[u8; 32]>> {
        for pin in &self.pins {
            if EntityId::from_hex(&pin.reference.source_id)? == id {
                return Ok(Some(pin.source_revision));
            }
            for ancestor in &pin.ancestors {
                if EntityId::from_hex(&ancestor.source_ref)? == id {
                    return Ok(Some(ancestor.source_revision));
                }
            }
        }
        Ok(None)
    }

    pub(in crate::dreamer_consolidation) fn closed_revisions(
        &self,
    ) -> BTreeMap<EntityId, RowRevision> {
        self.closed
            .iter()
            .map(|(id, proof)| (*id, proof.granted.clone()))
            .collect()
    }

    pub(in crate::dreamer_consolidation) fn has_closed(&self, id: &EntityId) -> bool {
        self.closed.contains_key(id)
    }

    /// Called only after this fence's native precheck, before that grant closes
    /// its prior. The native revision ledger retains the bytes on replacement.
    pub(in crate::dreamer_consolidation) fn capture_close_revision(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        prior: EntityId,
    ) -> Result<Option<RevisionRef>> {
        let Some(hash) = self.source_hash(prior)? else {
            return Ok(None);
        };
        crate::vault::entity_revision::revision_for_body_hash_in_txn(vault, txn, &prior, &hash)?
            .map(Some)
            .ok_or_else(|| invalid_consolidation("root prior revision is not retained"))
    }

    /// The native grant's LAST callback persists metadata in its SAME writer.
    /// Failure rolls the grant back; no proof can precede or outlive its close.
    pub(in crate::dreamer_consolidation) fn record_close_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        actor: WriteActor,
        attempt: AttemptId,
        prior: EntityId,
        replacement: EntityId,
        original: RevisionRef,
    ) -> Result<()> {
        let old = self.retained_row(vault, txn, prior, original)?;
        if old.0 != ENTITY_TYPE_CLAIM {
            return Err(invalid_consolidation("root grant prior is not a claim"));
        }
        let replacement_body = vault
            .get_claim_in_txn(txn, &replacement)?
            .ok_or_else(|| invalid_consolidation("root grant replacement is missing"))?;
        let prior_body = vault
            .get_claim_in_txn(txn, &prior)?
            .ok_or_else(|| invalid_consolidation("root grant prior is missing"))?;
        if replacement_body.approval != crate::claim::ClaimApprovalStatus::Auto
            || prior_body.lifecycle != crate::claim::ClaimLifecycleStatus::Superseded
            || !crate::ports::EdgeStoreRead::port_edge_consistent(
                &vault.store,
                txn,
                &replacement,
                crate::EdgeKind::Supersedes,
                &prior,
            )?
        {
            return Err(invalid_consolidation(
                "root native grant did not close its prior",
            ));
        }
        let proof = GrantedClose {
            binding: self.identity,
            attempt: *attempt.as_bytes(),
            actor: actor.entity_ref(),
            actor_class: actor.actor_class() as u8,
            prior,
            replacement,
            original,
            granted: RowRevision::read_in(vault, txn, &prior)?
                .ok_or_else(|| invalid_consolidation("root granted prior is missing"))?,
        };
        let mut root = super::super::ROOTS
            .get(&vault.store, txn, &self.root_id)?
            .ok_or_else(|| invalid_consolidation("root bridge root is gone"))?;
        match root.closes.iter().find(|old| {
            old.binding == proof.binding && old.attempt == proof.attempt && old.prior == prior
        }) {
            Some(old) if old != &proof => {
                return Err(invalid_consolidation("root grant proof changed"));
            }
            Some(_) => return Ok(()),
            None => root.closes.push(proof),
        }
        super::super::ROOTS.put(&vault.store, txn, &self.root_id, &root)
    }

    fn retained_row(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        original: RevisionRef,
    ) -> Result<(u8, u64, Vec<u8>)> {
        let raw = read_entity_revision_in_txn(vault, txn, &id, ReadMode::Pinned(original))?
            .ok_or_else(|| invalid_consolidation("root original revision no longer reads"))?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or_else(|| invalid_consolidation("root original revision has no header"))?;
        let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
        if header.entity_type != ENTITY_TYPE_CLAIM
            || self.source_hash(id)? != Some(*blake3::hash(body).as_bytes())
        {
            return Err(invalid_consolidation(
                "root original source revision changed",
            ));
        }
        Ok((header.entity_type, header.learned_at, body.to_vec()))
    }

    pub(super) fn validate_closes(&self, root: &Root) -> Result<()> {
        if self
            .closed
            .values()
            .any(|proof| !root.closes.contains(proof))
        {
            return Err(invalid_consolidation("root native grant proof is gone"));
        }
        Ok(())
    }

    /// Original bytes are available ONLY after the current source passes its
    /// Recorded authority, exact grant revision and the complete root fence.
    /// The native history door still owns custody, deletion and stale checks.
    pub(in crate::dreamer_consolidation) fn read_recovered(
        &self,
        vault: &Vault,
        live: &ScopedRead<'_>,
        id: EntityId,
    ) -> Result<Option<ScopedReadResult<(u8, u64, Vec<u8>)>>> {
        let Some(proof) = self.closed.get(&id) else {
            return Ok(None);
        };
        let key = proof.reader_key()?;
        let recorded = vault
            .scoped_read(key)
            .with_claim_status(ClaimReadStatus::Recorded);
        let row =
            recorded.read_projected(&[crate::claim::PointRead::id(id)], None, |txn, rows| {
                if rows
                    .into_iter()
                    .next()
                    .flatten()
                    .and_then(|row| row.body)
                    .is_none()
                {
                    return Err(invalid_consolidation("root granted prior no longer reads"));
                }
                self.validate_after_closes_in_txn(
                    vault,
                    live,
                    &recorded,
                    txn,
                    &self.closed_revisions(),
                )?;
                self.retained_row(vault, txn, id, proof.original)
            })?;
        Ok(Some(row))
    }
}
