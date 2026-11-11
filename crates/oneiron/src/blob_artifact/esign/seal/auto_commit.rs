//! Native policy checker for the verified SealJob producer.
use super::{
    EsignSealError, SealProfileEvidence, coherent, events_in, live_attempt, snapshot_hash,
};
use crate::attempt_queue::AttemptRecord;
use crate::blob_artifact::BlobVersionProvenance;
use crate::blob_artifact::esign::{
    EsignSealed, EsignState, EsignVerdict, SealActiveContentFacts, SealProfile,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeActorClass;
use crate::gate::{NativeAutoChecker, resolve_policy_manifest};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, Vault};
use sha2::{Digest, Sha256};

/// Only this module can construct one; the producer supplies both verifier results.
pub(super) struct VerifiedSealOutput {
    bytes: Vec<u8>,
    sha256: [u8; 32],
    audit_chain_sha256: [u8; 32],
    profile: SealProfileEvidence,
    active_content: SealActiveContentFacts,
}

impl VerifiedSealOutput {
    pub(super) fn verify(
        mut sealed: EsignSealed,
        mut checked: EsignVerdict,
        profile: SealProfile,
        audit_chain_sha256: [u8; 32],
    ) -> std::result::Result<Self, EsignSealError> {
        let mut verify_reasons = std::mem::take(&mut sealed.self_verify.reasons);
        verify_reasons.append(&mut checked.reasons);
        if !sealed.self_verify.self_verify_ok
            || !checked.self_verify_ok
            || !coherent(&sealed, &checked, profile)
        {
            return Err(EsignSealError::Verification { verify_reasons });
        }
        let sha256: [u8; 32] = Sha256::digest(&sealed.bytes).into();
        if sealed.evidence_sha256 != sha256 {
            return Err(EsignSealError::Verification { verify_reasons });
        }
        Ok(Self {
            bytes: sealed.bytes,
            sha256,
            audit_chain_sha256,
            profile: SealProfileEvidence {
                requested: sealed.requested,
                achieved: sealed.achieved,
                degraded: sealed.degraded,
            },
            active_content: checked.active_content,
        })
    }

    pub(super) fn buffer_capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub(super) fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub(super) fn profile(&self) -> &SealProfileEvidence {
        &self.profile
    }
    pub(super) fn active_content(&self) -> SealActiveContentFacts {
        self.active_content
    }
    pub(super) fn audit_chain_sha256(&self) -> [u8; 32] {
        self.audit_chain_sha256
    }
}

/// One attempt's complete verified output set, allocated by its actual producer.
pub(super) struct VerifiedSealJob<'a> {
    attempt: &'a AttemptRecord,
    document: EntityId,
    snapshot: [u8; 32],
    state: &'a EsignState,
    outputs: &'a [VerifiedSealOutput],
    targets: Vec<EntityId>,
    actor: WriteActor,
    provenance: BlobVersionProvenance,
    now: u64,
}

impl<'a> VerifiedSealJob<'a> {
    pub(super) fn bind(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        attempt: &'a AttemptRecord,
        document: EntityId,
        snapshot: [u8; 32],
        state: &'a EsignState,
        outputs: &'a [VerifiedSealOutput],
        now: u64,
    ) -> Result<Self> {
        live_attempt(vault, txn, attempt)?;
        if snapshot_hash(&events_in(vault, txn, document)?)? != snapshot {
            return Err(Error::ConcurrentWrite("esign changed during seal"));
        }
        if outputs.is_empty() || outputs.len() != state.document.items.len() {
            return Err(super::invalid("seal output set does not match document"));
        }
        let actor = super::super::artifact_actor::seal_actor(vault, txn, now)?;
        let targets = outputs
            .iter()
            .map(|_| vault.new_entity_id())
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            attempt,
            document,
            snapshot,
            state,
            outputs,
            targets,
            actor,
            now,
            provenance: BlobVersionProvenance::SealJob {
                job_ref: format!(
                    "esign.seal:{}",
                    crate::entity_id::bytes_to_hex_lower(attempt.id.as_bytes())
                ),
            },
        })
    }

    pub(super) fn writes(&self) -> impl Iterator<Item = SealJobWrite<'_>> {
        (0..self.targets.len()).map(move |index| SealJobWrite { job: self, index })
    }
}

/// No public constructor: a write borrows its producer's complete output closure.
pub(in crate::blob_artifact) struct SealJobWrite<'a> {
    job: &'a VerifiedSealJob<'a>,
    index: usize,
}

impl SealJobWrite<'_> {
    pub(in crate::blob_artifact) fn artifact(&self) -> EntityId {
        self.job.targets[self.index]
    }
    pub(in crate::blob_artifact) fn actor(&self) -> WriteActor {
        self.job.actor
    }
    pub(in crate::blob_artifact) fn bytes(&self) -> &[u8] {
        &self.job.outputs[self.index].bytes
    }
    pub(in crate::blob_artifact) fn provenance(&self) -> &BlobVersionProvenance {
        &self.job.provenance
    }
    pub(in crate::blob_artifact) fn at(&self) -> u64 {
        self.job.now
    }
    pub(super) fn index(&self) -> usize {
        self.index
    }

    /// Select the manifest's native checker in the final writer, then run it
    /// against the actual append, not a caller's label or a preview of its bytes.
    pub(in crate::blob_artifact) fn check_append(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        content_hash: &[u8; 32],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        version: u64,
        parent: Option<u64>,
        fork: Option<u64>,
    ) -> Result<SealJobAutoPermit<'_>> {
        let policy = resolve_policy_manifest(&vault.store, txn)?;
        let checker =
            policy.source_auto_checker(ClaimSource::Generated, Some(&actor.entity_ref().to_hex()));
        match checker {
            Some(NativeAutoChecker::SealJob) => self.check_native(
                vault,
                txn,
                artifact,
                content_hash,
                provenance,
                actor,
                version,
                parent,
                fork,
            )?,
            None => {
                return Err(super::invalid(
                    "SealJob native policy checker is not selected",
                ));
            }
        }
        Ok(SealJobAutoPermit {
            write: self,
            frontier: policy.read_frontier_hash()?,
        })
    }

    fn check_native(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        content_hash: &[u8; 32],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        version: u64,
        parent: Option<u64>,
        fork: Option<u64>,
    ) -> Result<()> {
        let job = self.job;
        live_attempt(vault, txn, job.attempt)?;
        if snapshot_hash(&events_in(vault, txn, job.document)?)? != job.snapshot {
            return Err(Error::ConcurrentWrite("esign changed during seal"));
        }
        if actor != job.actor
            || actor.actor_class() != EdgeActorClass::System
            || artifact != &self.artifact()
            || provenance != &job.provenance
            || content_hash != blake3::hash(self.bytes()).as_bytes()
            || version != 1
            || parent.is_some()
            || fork.is_some()
            || job.targets.len() != job.outputs.len()
            || job.outputs.len() != job.state.document.items.len()
        {
            return Err(super::invalid(
                "SealJob append does not match verified output closure",
            ));
        }
        Ok(())
    }
}

pub(in crate::blob_artifact) struct SealJobAutoPermit<'a> {
    write: &'a SealJobWrite<'a>,
    frontier: [u8; 32],
}

impl SealJobAutoPermit<'_> {
    pub(in crate::blob_artifact) fn approval(&self) -> ClaimApprovalStatus {
        ClaimApprovalStatus::Auto
    }

    pub(in crate::blob_artifact) fn stamp(&self, value: &mut rmpv::Value) {
        let rmpv::Value::Map(fields) = value else {
            unreachable!("native write provenance is a map")
        };
        fields.extend([
            (
                rmpv::Value::from("auto_checker"),
                rmpv::Value::from(NativeAutoChecker::SealJob.as_str()),
            ),
            (
                rmpv::Value::from("policy_frontier"),
                rmpv::Value::Binary(self.frontier.to_vec()),
            ),
            (
                rmpv::Value::from("seal_document"),
                rmpv::Value::from(self.write.job.document.to_hex()),
            ),
            (
                rmpv::Value::from("seal_snapshot_sha256"),
                rmpv::Value::Binary(self.write.job.snapshot.to_vec()),
            ),
            (
                rmpv::Value::from("seal_target"),
                rmpv::Value::from(self.write.artifact().to_hex()),
            ),
        ]);
    }
}
