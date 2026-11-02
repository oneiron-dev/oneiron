//! The iterative fold-chain proof behind a revision's integrity record.
//!
//! [`verify_or_build`] proves exactly what the old recursive verifier
//! proved: every ancestor's stored record matches its revision, every
//! artifact hash and fold recomputes, every parent belongs to its child's
//! session, and every revert names an ancestor. The walk runs on an
//! explicit enter/exit stack, so a long valid chain completes instead of
//! refusing past a step count or overflowing the call stack. A revision
//! reached twice reuses its proven record; a revision reached while its
//! own proof is still on the stack is a cycle, as before.

use std::collections::{HashMap, HashSet};

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::Store;

use super::super::codec::CODE_REVISION_HASH_LEN;
use super::super::graph::{
    code_artifact_body_bytes, require_code_revision_ancestor, require_entity_type,
    require_revision_session,
};
use super::super::storage::read_code_revision_record_in_txn;
use super::super::types::{CodeRevision, CodeRevisionIntegrityRecord};
use super::{compute_code_revision_fold, load_optional_code_revision_integrity_record};

/// What one stack entry waits for: a revision whose proof has not started,
/// or one whose parent and revert proofs are done and whose own record can
/// now be checked or built.
enum Frame {
    Enter(CodeRevision),
    Exit(ExitFrame),
}

/// A revision whose dependencies are proven, with what its enter step
/// already read and checked.
struct ExitFrame {
    revision: CodeRevision,
    record: Option<CodeRevisionIntegrityRecord>,
    artifact_hash: [u8; CODE_REVISION_HASH_LEN],
}

/// Verifies or builds `revision`'s integrity record, proving its whole
/// parent and revert ancestry iteratively. `visiting` holds the proof path
/// above this call; on success it is unchanged, as the recursive proof
/// left it. Past its threshold row the walk raises one advisory
/// [`EngineScan::DagWalkRecords`] check and reads on.
pub(super) fn verify_or_build(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: &CodeRevision,
    visiting: &mut HashSet<EntityId>,
) -> Result<CodeRevisionIntegrityRecord> {
    let mut count = ScanCount::start(
        store,
        rtxn,
        EngineScan::DagWalkRecords,
        revision.revision_id.as_bytes(),
    )?;
    let outcome = walk(store, rtxn, revision, visiting, &mut count);
    count.defer(store);
    outcome
}

fn walk(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: &CodeRevision,
    visiting: &mut HashSet<EntityId>,
    count: &mut ScanCount,
) -> Result<CodeRevisionIntegrityRecord> {
    let root_id = revision.revision_id;
    let mut proven: HashMap<EntityId, CodeRevisionIntegrityRecord> = HashMap::new();
    let mut stack = vec![Frame::Enter(revision.clone())];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(revision) => {
                enter(store, rtxn, revision, visiting, count, &proven, &mut stack)?;
            }
            Frame::Exit(pending) => exit(store, rtxn, pending, visiting, &mut proven)?,
        }
    }
    proven
        .remove(&root_id)
        .ok_or(Error::CorruptedIndex("code revision integrity walk"))
}

/// Checks what one revision proves on its own, then queues its exit behind
/// the parent and revert proofs it still needs. A dependency already
/// proven is reused; one still on the stack is a cycle.
#[allow(
    clippy::too_many_arguments,
    reason = "the walk's shared proof state, one revision at a time"
)]
fn enter(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: CodeRevision,
    visiting: &mut HashSet<EntityId>,
    count: &mut ScanCount,
    proven: &HashMap<EntityId, CodeRevisionIntegrityRecord>,
    stack: &mut Vec<Frame>,
) -> Result<()> {
    if proven.contains_key(&revision.revision_id) {
        return Ok(());
    }
    if !visiting.insert(revision.revision_id) {
        return Err(cycle());
    }
    count.row();

    let record = load_optional_code_revision_integrity_record(store, rtxn, &revision.revision_id)?;
    if let Some(record) = &record
        && (record.revision_id != revision.revision_id
            || record.session_id != revision.session_id
            || record.parent_revision_id != revision.parent_revision_id
            || record.reverted_to_revision_id != revision.reverted_to_revision_id
            || record.provenance_claim_id != revision.provenance_claim_id
            || record.finalized_at != revision.finalized_at
            || record.parent_fold.is_some() != revision.parent_revision_id.is_some()
            || record.reverted_to_fold.is_some() != revision.reverted_to_revision_id.is_some())
    {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision integrity record does not match revision record",
        )));
    }

    let artifact_body = code_artifact_body_bytes(store, rtxn, &revision.revision_id)?;
    let artifact_hash =
        super::super::file_frontiers::artifact_hash(store, rtxn, &revision, &artifact_body)?;
    if let Some(record) = &record
        && artifact_hash != record.artifact_hash
    {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision artifact hash mismatch",
        )));
    }
    if let Some(provenance_claim_id) = revision.provenance_claim_id {
        require_entity_type(
            store,
            rtxn,
            &provenance_claim_id,
            ENTITY_TYPE_CLAIM,
            "provenance_claim_id must be a CLAIM entity",
        )?;
    }

    let parent = match revision.parent_revision_id {
        Some(parent_id) => {
            let parent = read_code_revision_record_in_txn(store, rtxn, &parent_id)?.ok_or(
                Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "code revision integrity parent record missing",
                )),
            )?;
            require_revision_session(
                &parent,
                revision.session_id,
                "parent_revision_id must belong to session_id",
            )?;
            Some(parent)
        }
        None => None,
    };
    let reverted_to = match revision.reverted_to_revision_id {
        Some(reverted_to_id) => Some(
            read_code_revision_record_in_txn(store, rtxn, &reverted_to_id)?.ok_or(
                Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "code revision integrity parent record missing",
                )),
            )?,
        ),
        None => None,
    };

    stack.push(Frame::Exit(ExitFrame {
        revision,
        record,
        artifact_hash,
    }));
    for dependency in [reverted_to, parent] {
        if let Some(dependency) = dependency
            && !proven.contains_key(&dependency.revision_id)
        {
            if visiting.contains(&dependency.revision_id) {
                return Err(cycle());
            }
            stack.push(Frame::Enter(dependency));
        }
    }
    Ok(())
}

/// Checks or builds one revision's record once its parent and revert folds
/// are proven, in postorder. The revision leaves the proof path, as the
/// recursive proof removed it on its way out.
fn exit(
    store: &Store,
    rtxn: &RoTxn<'_>,
    pending: ExitFrame,
    visiting: &mut HashSet<EntityId>,
    proven: &mut HashMap<EntityId, CodeRevisionIntegrityRecord>,
) -> Result<()> {
    let ExitFrame {
        revision,
        record,
        artifact_hash,
    } = pending;
    let parent_fold = match revision.parent_revision_id {
        Some(parent_id) => {
            let parent_fold = proven
                .get(&parent_id)
                .ok_or(Error::CorruptedIndex("code revision integrity walk"))?
                .revision_fold;
            if let Some(record) = &record
                && record.parent_fold != Some(parent_fold)
            {
                return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "code revision parent fold mismatch",
                )));
            }
            Some(parent_fold)
        }
        None => None,
    };
    let reverted_to_fold = match revision.reverted_to_revision_id {
        Some(reverted_to_id) => {
            let reverted_to_fold = proven
                .get(&reverted_to_id)
                .ok_or(Error::CorruptedIndex("code revision integrity walk"))?
                .revision_fold;
            if let Some(record) = &record
                && record.reverted_to_fold != Some(reverted_to_fold)
            {
                return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "code revision reverted-to fold mismatch",
                )));
            }
            Some(reverted_to_fold)
        }
        None => None,
    };
    if let (Some(parent_id), Some(reverted_to_id)) = (
        revision.parent_revision_id,
        revision.reverted_to_revision_id,
    ) {
        require_code_revision_ancestor(store, rtxn, &parent_id, &reverted_to_id)?;
    }

    let expected_fold = compute_code_revision_fold(
        revision.kind,
        &artifact_hash,
        revision.provenance_claim_id,
        parent_fold,
        reverted_to_fold,
    );
    let built = if let Some(record) = record {
        if expected_fold != record.revision_fold {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision fold mismatch",
            )));
        }
        record
    } else {
        CodeRevisionIntegrityRecord {
            revision_id: revision.revision_id,
            session_id: revision.session_id,
            parent_revision_id: revision.parent_revision_id,
            reverted_to_revision_id: revision.reverted_to_revision_id,
            provenance_claim_id: revision.provenance_claim_id,
            artifact_hash,
            parent_fold,
            reverted_to_fold,
            revision_fold: expected_fold,
            finalized_at: revision.finalized_at,
        }
    };
    proven.insert(revision.revision_id, built);
    visiting.remove(&revision.revision_id);
    Ok(())
}

fn cycle() -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
        "code revision parent chain contains a cycle",
    ))
}
