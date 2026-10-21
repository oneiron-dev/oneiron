//! The tested queue revision's finalizer (FIX 6868, G2 PR3): one writer
//! co-commits the queue's aggregation SESSION, the revision's CODE_ARTIFACT,
//! its aggregate provenance claim, the finalized record and the source
//! link that names it.
//!
//! Every revision of one queue's tested chain shares one aggregation
//! SESSION, derived from the queue's object store and its checked init, so
//! the existing same-session parent and fold rules hold. It is engine
//! bookkeeping, never a submitting run, a model invocation or an owner:
//! each source keeps its own session, actor and provenance, named in the
//! aggregate claim and never rewritten. Identities are deterministic; a
//! retry finds the finalized record and requires it to be exactly this one.
use heed::{RoTxn, RwTxn};
use rmpv::Value;

use super::CodeRevision;
use super::keys::RECORDS;
use super::proposals::CodeRevisionWriteOutcome;
use super::storage::{read_code_revision_record_in_txn, write_code_revision_in_txn};
use super::tree_inventory::CodeTreeInventory;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::code_artifact::{CodeArtifactBody, encode_code_artifact_body};
use crate::codebase::entity_id_from_hash_material;
use crate::error::{ArtifactError, Error, Result};
use crate::merge_queue::{QueueRevisionSeal, QueueTestedRevision, QueueTestedTarget};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_SESSION};
use crate::{EntityId, TimeRange, Vault};

/// The engine-owned predicate of a tested queue revision's aggregate
/// provenance claim.
pub(crate) const QUEUE_REVISION_PREDICATE: &str = "repo.queue_revision";

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(reason))
}

/// The aggregation SESSION one queue's tested chain shares.
///
/// # Errors
/// An id derivation failure.
pub(crate) fn queue_aggregation_session(store: &str, init_work: &str) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:queue-aggregation-session:v1",
        &[store.as_bytes(), init_work.as_bytes()],
    )
}

/// The deterministic id of one tested revision: the queue's store and
/// checked init, the target, the exact checked commit and tree and the plan.
///
/// # Errors
/// An id derivation failure.
pub(crate) fn queue_revision_id(
    store: &str,
    init_work: &str,
    target: &str,
    commit: &str,
    tree: &str,
    plan_digest: &str,
) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:queue-tested-revision:v1",
        &[
            store.as_bytes(),
            init_work.as_bytes(),
            target.as_bytes(),
            commit.as_bytes(),
            tree.as_bytes(),
            plan_digest.as_bytes(),
        ],
    )
}

/// The aggregate provenance claim's id for `revision`.
///
/// # Errors
/// An id derivation failure.
pub(crate) fn queue_provenance_id(revision: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:queue-revision-provenance:v1",
        &[revision.as_bytes()],
    )
}

/// The aggregation SESSION's body: derived queue bookkeeping, named as such.
fn session_body(tested: &QueueTestedRevision) -> Result<Vec<u8>> {
    super::codec::encode_value(
        &Value::Map(vec![
            (Value::from("kind"), Value::from("merge_queue.aggregation")),
            (Value::from("repo"), Value::from(tested.repo.to_hex())),
            (Value::from("store"), Value::from(tested.store.as_str())),
            (
                Value::from("init_work"),
                Value::from(tested.init_work.as_str()),
            ),
        ]),
        "queue aggregation session encode",
    )
}

impl Vault {
    /// Finalizes the revision `seal` carries and attaches it to its source
    /// row, in one writer. A retry that finds the record requires it to be
    /// exactly this one and only attaches.
    ///
    /// # Errors
    /// A record that fails validation, a source that moved, an identity
    /// already holding another record, or a store failure.
    pub(crate) fn finalize_queue_revision(&self, seal: &QueueRevisionSeal) -> Result<EntityId> {
        let revision = seal.revision();
        let tested = revision
            .tested_queue
            .as_ref()
            .ok_or_else(|| invalid("a queue seal carries a tested queue record"))?;
        super::codec::validate_code_revision_shape(revision)?;
        RECORDS.encode_value(revision)?;
        let mut wtxn = self.store.env.write_txn()?;
        if let Some(existing) =
            read_code_revision_record_in_txn(&self.store, &wtxn, &revision.revision_id)?
        {
            if existing != *revision {
                return Err(Error::ConcurrentWrite(
                    "a tested queue revision identity holds another record",
                ));
            }
            seal.attach_in_txn(self, &mut wtxn)?;
            wtxn.commit()?;
            return Ok(revision.revision_id);
        }
        validate_queue_revision_in_txn(self, &wtxn, revision)?;
        seal.validate_sources_in_txn(self, &wtxn)?;
        self.put_queue_session_in_txn(&mut wtxn, tested, revision)?;
        self.put_queue_artifact_in_txn(&mut wtxn, seal, tested, revision)?;
        record_queue_revision_provenance_in_txn(self, &mut wtxn, seal)?;
        let (outcome, _) = write_code_revision_in_txn(&self.store, &mut wtxn, revision)?;
        if !matches!(outcome, CodeRevisionWriteOutcome::Finalized) {
            return Err(Error::ConcurrentWrite(
                "a tested queue revision must advance its aggregation session",
            ));
        }
        seal.attach_in_txn(self, &mut wtxn)?;
        wtxn.commit()?;
        Ok(revision.revision_id)
    }

    /// The queue's aggregation SESSION, written once; an existing one must
    /// carry exactly this body.
    fn put_queue_session_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        tested: &QueueTestedRevision,
        revision: &CodeRevision,
    ) -> Result<()> {
        let body = session_body(tested)?;
        if let Some(row) = self.store.port_entity_record(wtxn, &revision.session_id)? {
            if row.entity_type != ENTITY_TYPE_SESSION || row.body != body {
                return Err(Error::ConcurrentWrite(
                    "the queue aggregation session id holds another record",
                ));
            }
            return Ok(());
        }
        let at = revision.finalized_at;
        self.batch_in()
            .put(
                &revision.session_id,
                ENTITY_TYPE_SESSION,
                TimeRange { start: at, end: at },
                at,
                &body,
            )
            .apply(wtxn)
    }

    /// The revision's CODE_ARTIFACT, written once with the queue's stored
    /// repository pointer and the inventory digest.
    fn put_queue_artifact_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        seal: &QueueRevisionSeal,
        tested: &QueueTestedRevision,
        revision: &CodeRevision,
    ) -> Result<()> {
        let body = encode_code_artifact_body(&CodeArtifactBody::new(
            format!("Tested queue revision of commit {}.", tested.commit),
            tested.inventory_digest,
            seal.repo_ref(),
        ))?;
        if let Some(row) = self.store.port_entity_record(wtxn, &revision.revision_id)? {
            if row.entity_type != ENTITY_TYPE_CODE_ARTIFACT || row.body != body {
                return Err(Error::ConcurrentWrite(
                    "the tested revision id holds another record",
                ));
            }
            return Ok(());
        }
        let at = revision.finalized_at;
        self.batch_in()
            .put(
                &revision.revision_id,
                ENTITY_TYPE_CODE_ARTIFACT,
                TimeRange { start: at, end: at },
                at,
                &body,
            )
            .apply(wtxn)
    }
}

/// Validates a queue-bearing revision against the rows it names, in the
/// finalizer's writer: its deterministic identities, its inventory digest,
/// its chain parent of the same queue at the exact green it landed on, and
/// its canonical author. A decoded record cannot stand in for issuance.
///
/// # Errors
/// Any disagreement.
pub(crate) fn validate_queue_revision_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    revision: &CodeRevision,
) -> Result<()> {
    let tested = revision
        .tested_queue
        .as_ref()
        .ok_or_else(|| invalid("not a tested queue revision"))?;
    let target = match &tested.target {
        QueueTestedTarget::Baseline => "baseline".to_owned(),
        QueueTestedTarget::Landed { batch, .. } => format!("landed:{batch}"),
    };
    let expected = queue_revision_id(
        &tested.store,
        &tested.init_work,
        &target,
        &tested.commit,
        &tested.tree,
        &tested.plan_digest,
    )?;
    if tested.schema_version != 1
        || revision.revision_id != expected
        || revision.reverted_to_revision_id.is_some()
        // No seal carries an import binding before its reviewed producer
        // lands (G4 PR1): the resolver reads the root. A retired path is
        // proved below from its reviewed removal (G4 PR2).
        || revision.snapshot_anchor.is_some()
        || revision.session_id != queue_aggregation_session(&tested.store, &tested.init_work)?
        || revision.provenance_claim_id != Some(queue_provenance_id(revision.revision_id)?)
        || tested.inventory_digest != CodeTreeInventory::digest(revision)?
        || tested.slow.phase != crate::merge_queue::CheckPhase::Slow
        || tested
            .fast
            .iter()
            .any(|link| link.phase != crate::merge_queue::CheckPhase::Fast)
    {
        return Err(invalid("tested queue revision identity or evidence"));
    }
    validate_queue_retirements_in_txn(vault, txn, revision, tested)?;
    let metadata = revision
        .commit_metadata
        .as_ref()
        .ok_or_else(|| invalid("a tested queue revision needs canonical metadata"))?;
    if vault
        .store
        .port_entity_record(txn, &metadata.author)?
        .is_none()
    {
        return Err(Error::EntityNotFound);
    }
    match (&tested.target, revision.parent_revision_id) {
        (QueueTestedTarget::Baseline, None) => Ok(()),
        (QueueTestedTarget::Landed { expected_head, .. }, Some(parent)) => {
            let parent = read_code_revision_record_in_txn(&vault.store, txn, &parent)?
                .ok_or(Error::EntityNotFound)?;
            match &parent.tested_queue {
                Some(earlier)
                    if earlier.store == tested.store
                        && earlier.init_work == tested.init_work
                        && earlier.commit == *expected_head =>
                {
                    Ok(())
                }
                _ => Err(invalid(
                    "a tested queue revision's parent is the green it landed on",
                )),
            }
        }
        _ => Err(invalid("a tested queue revision's parent is its target's")),
    }
}

/// The first producer of retired paths (G4 PR2): each one is a removal one
/// of this seal's own applied received bundles reviewed, under its
/// deterministic child operation, with the document that operation left
/// when the path had one. The checked baseline retires nothing.
///
/// # Errors
/// A retirement no applied reviewed removal proves.
fn validate_queue_retirements_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    revision: &CodeRevision,
    tested: &QueueTestedRevision,
) -> Result<()> {
    if revision.retired_paths.is_empty() {
        return Ok(());
    }
    let QueueTestedTarget::Landed { applied, .. } = &tested.target else {
        return Err(invalid("the checked baseline retires no path"));
    };
    for (path, retirement) in &revision.retired_paths {
        let source = applied
            .iter()
            .find(|source| source.proposal == retirement.review_ref)
            .ok_or_else(|| invalid("a retired path's review is not an applied source"))?;
        let proposal = vault
            .repo_proposal_in_txn(txn, source.proposal)?
            .ok_or(Error::EntityNotFound)?;
        let removal = proposal
            .files
            .iter()
            .find(|file| file.path == *path && file.content.is_none());
        let proved = proposal.received_candidate().is_some()
            && proposal.status == crate::repo_mutation::proposal::RepoProposalStatus::Applied
            && removal
                .and_then(|file| file.source_operation)
                .map(|op| crate::repo_mutation::received_file_operation(proposal.id, op))
                .transpose()?
                == Some(retirement.operation_receipt);
        if !proved {
            return Err(invalid("a retired path is no applied reviewed removal"));
        }
        let receipt = vault.code_file_edit_receipt_in_txn(txn, retirement.operation_receipt)?;
        if receipt.map(|receipt| receipt.after) != retirement.document {
            return Err(invalid("a retired path's document is not its removal's"));
        }
    }
    Ok(())
}

/// Records `seal`'s aggregate provenance claim: derived engine work naming
/// every source proposal with its own session and provenance, and every
/// receipt it stands on. It is no run's provenance and no approval.
///
/// # Errors
/// An existing claim at the derived id, or a store failure.
pub(crate) fn record_queue_revision_provenance_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    seal: &QueueRevisionSeal,
) -> Result<EntityId> {
    let revision = seal.revision();
    let tested = revision
        .tested_queue
        .as_ref()
        .ok_or_else(|| invalid("not a tested queue revision"))?;
    let id = queue_provenance_id(revision.revision_id)?;
    if vault.store.port_entity_record(wtxn, &id)?.is_some() {
        return Err(Error::ConcurrentWrite(
            "the tested revision's provenance id holds another record",
        ));
    }
    let (target, batch, sources) = match &tested.target {
        QueueTestedTarget::Baseline => ("baseline", Value::Nil, Vec::new()),
        QueueTestedTarget::Landed { batch, applied, .. } => (
            "landed",
            Value::from(batch.as_str()),
            applied
                .iter()
                .map(|source| {
                    Value::Map(vec![
                        (
                            Value::from("proposal"),
                            Value::from(source.proposal.to_hex()),
                        ),
                        (
                            Value::from("operation_seq"),
                            Value::from(source.operation_seq),
                        ),
                        (Value::from("session"), Value::from(source.session.to_hex())),
                        (
                            Value::from("provenance"),
                            Value::from(source.provenance_claim.to_hex()),
                        ),
                    ])
                })
                .collect(),
        ),
    };
    let receipts = tested
        .fast
        .iter()
        .chain(std::iter::once(&tested.slow))
        .map(|link| Value::from(link.inputs_digest.as_str()))
        .collect();
    let mut body = ClaimBody::new(
        QUEUE_REVISION_PREDICATE,
        ClaimSubject::Entity(revision.session_id),
        Value::Map(vec![
            (
                Value::from("revision"),
                Value::from(revision.revision_id.to_hex()),
            ),
            (Value::from("store"), Value::from(tested.store.as_str())),
            (Value::from("commit"), Value::from(tested.commit.as_str())),
            (Value::from("tree"), Value::from(tested.tree.as_str())),
            (Value::from("target"), Value::from(target)),
            (Value::from("batch"), batch),
            (
                Value::from("plan_digest"),
                Value::from(tested.plan_digest.as_str()),
            ),
            (Value::from("sources"), Value::Array(sources)),
            (Value::from("receipts"), Value::Array(receipts)),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    // Observed queue bookkeeping, not a code approval: promotion still
    // reviews every changed file on its own.
    body.source = Some(ClaimSource::Observed);
    let at = revision.finalized_at;
    vault.put_reserved_claim_in_txn(wtxn, &id, &body, TimeRange { start: at, end: at }, at)?;
    Ok(id)
}
