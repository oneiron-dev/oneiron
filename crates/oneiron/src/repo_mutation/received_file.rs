//! A received push bundle (FIX 6869, G4 PR2): every file of ONE accepted
//! pushed ref update as one reviewed proposal, one merge-queue proposal,
//! one stack slot, one prepared commit and one grouped document ingress.
//!
//! Nothing here trusts a caller. The bundle's bytes and modes come from
//! the retained source its candidate resolved, its actor is the push's own
//! live pusher at the ingress System class, its session is the candidate's
//! fork, and it carries no run. Raw push authority approves nothing: the
//! bundle waits for the owner's review catalog, its independent critics
//! and the owner's explicit enqueue, like any other proposal.
use heed::{RoTxn, RwTxn};

use super::mount::RepoMountRef;
use super::proposal::persist::PreparedRepoProposal;
use super::proposal::{
    PROPOSAL, RepoProposal, RepoProposalOperation, RepoProposalStatus, RepoProposedFile, invalid,
};
use super::types::{RepoMutationOperation, RepoMutationRequest};
use crate::code_document::{CodeFileEdit, CodeFileIngress, CodeOpProvenance};
use crate::codebase::{RepoRef, entity_id_from_hash_material};
use crate::critic::LensCatalog;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWireRepo};
use crate::merge_queue::{MergeFile, MergeProposal};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

pub(crate) mod tree;

/// What one resolved candidate proposes: its deterministic identities,
/// the queue's folder and the exact base commit, its pusher, fork and push
/// provenance, and every file with its exact state change.
pub(crate) struct ReceivedFilesProposalInput {
    pub(crate) candidate: EntityId,
    pub(crate) proposal: EntityId,
    pub(crate) folder: String,
    pub(crate) base_commit: GitOid,
    pub(crate) pusher: EntityId,
    pub(crate) session: EntityId,
    pub(crate) provenance: EntityId,
    pub(crate) message: String,
    pub(crate) files: Vec<RepoProposedFile>,
    pub(crate) catalog: LensCatalog,
    pub(crate) created_at: u64,
}

/// The deterministic id of a received bundle's proposal.
///
/// # Errors
/// An id derivation failure.
pub(crate) fn received_proposal_id(candidate: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:push-candidate-proposal:v1",
        &[candidate.as_bytes()],
    )
}

/// The deterministic document operation one bundle file lowers to, distinct
/// from the receive audit's own operation ids.
///
/// # Errors
/// An id derivation failure.
pub(crate) fn received_file_operation(proposal: EntityId, source: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:push-candidate-file-op:v1",
        &[proposal.as_bytes(), source.as_bytes()],
    )
}

impl Vault {
    /// The bundle `input` names, prepared before its writer: the exact base
    /// commit's pinned snapshot, every file's expected state checked
    /// against it and its custody, and its journal claims. `Ok(Err(_))`
    /// names a shape that holds the candidate.
    ///
    /// # Errors
    /// A base that cannot be read, or a claim that does not encode.
    pub(crate) fn prepare_received_files_proposal(
        &self,
        repo: &GitWireRepo,
        input: ReceivedFilesProposalInput,
    ) -> Result<std::result::Result<PreparedRepoProposal, String>> {
        let base = self.capture_repo_snapshot_at_commit(repo, &input.base_commit)?;
        let snapshot = super::snapshot::decode_snapshot(&base.encoded)?;
        let custody = super::snapshot::SnapshotCustody::of(self, repo.repo_root())?;
        for file in &input.files {
            let Some(state) = &file.metadata_edit else {
                return Ok(Err(format!("{}: no reviewed state change", file.path)));
            };
            let entry = snapshot
                .entries
                .iter()
                .find(|entry| entry.path == file.path);
            if !super::reviewed_file::snapshot_state_is(entry, &state.expected) {
                return Ok(Err(format!(
                    "{}: the base snapshot does not hold the pushed old entry",
                    file.path
                )));
            }
            if let Some(content) = &file.content
                && custody.withholds(&file.path, content).is_some()
            {
                return Ok(Err(format!("{}: snapshot custody withholds it", file.path)));
            }
        }
        if crate::batch::secret_scan::scan_file_content("", input.message.as_bytes()).is_some() {
            return Ok(Err("the bundle message holds a secret".to_owned()));
        }
        let repo_ref = RepoRef::LocalFolder {
            path: input.folder,
            commit: input.base_commit.as_str().to_owned(),
        };
        let row = RepoProposal {
            id: input.proposal,
            repo: repo_ref.canonical(),
            actor: super::proposal::actor_erase::ProposalActor::Actor(input.pusher),
            session: input.session,
            provenance_claim: input.provenance,
            op_provenance: CodeOpProvenance::default(),
            files: input.files,
            message: input.message,
            operation: RepoProposalOperation::ReceivedFiles {
                candidate: input.candidate,
            },
            merge_stack: None,
            pre_action_fork_hash: base.fork_hash,
            catalog: input.catalog,
            critiques: Vec::new(),
            status: RepoProposalStatus::Proposed,
            settlement: None,
            operation_seq: None,
            created_at: input.created_at,
            run: None,
            actor_class: Some(EdgeActorClass::System as u8),
        };
        PreparedRepoProposal::new(row, base.encoded).map(Ok)
    }

    /// Persists a prepared bundle in the candidate's writer. A repeat finds
    /// the same immutable bundle and keeps its reviews, status, sequence and
    /// settlement; another body under that id is corruption.
    ///
    /// # Errors
    /// Another body under the id, a binding that fails, or a store failure.
    pub(crate) fn persist_received_files_proposal_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        prepared: &PreparedRepoProposal,
    ) -> Result<()> {
        let row = &prepared.row;
        if let Some(stored) = PROPOSAL.get(&self.store, txn, &row.id)? {
            if stored.repo != row.repo
                || stored.actor != row.actor
                || stored.session != row.session
                || stored.provenance_claim != row.provenance_claim
                || stored.files != row.files
                || stored.message != row.message
                || stored.operation != row.operation
                || stored.pre_action_fork_hash != row.pre_action_fork_hash
            {
                return Err(Error::CorruptedIndex(
                    "a received bundle id holds another proposal",
                ));
            }
            return Ok(());
        }
        prepared.persist_in_txn(self, txn)
    }
}

/// The source proof of a received bundle's request, in `txn`: its
/// candidate resolved to exactly this proposal, fork and file list, and
/// the push it came from is still a Published publication of its live
/// pusher. Runs before any optional-provenance shortcut.
///
/// # Errors
/// Any binding that does not hold, or a store failure.
pub(in crate::repo_mutation) fn require_received_files_source_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    request: &RepoMutationRequest,
) -> Result<()> {
    let RepoMutationOperation::ReceivedFiles {
        candidate,
        source_operations,
        ..
    } = &request.operation
    else {
        return Err(invalid("not a received push bundle"));
    };
    let provenance = request
        .provenance_claim_id
        .ok_or(invalid("a received bundle names its push provenance"))?;
    let resolved = vault
        .received_candidate_resolution_in_txn(txn, provenance, *candidate)?
        .ok_or(invalid("a received bundle's candidate is not resolved"))?;
    let sources: Vec<EntityId> = resolved
        .files
        .iter()
        .map(|file| file.source_operation)
        .collect();
    if resolved.proposal_id != received_proposal_id(*candidate)?
        || request.session_id != Some(resolved.fork_session)
        || *source_operations != sources
    {
        return Err(invalid("a received bundle is not its candidate's"));
    }
    let record = vault
        .origin_publication_in_txn(txn, resolved.publication)?
        .ok_or(Error::EntityNotFound)?;
    if record.status != crate::origin::publication::OriginPublicationStatus::Published
        || record.provenance_claim_id != provenance
        || record.actor_id.id().is_none()
        || record.actor_id.id() != request.actor_id
    {
        return Err(invalid(
            "a received bundle's push is no longer its live pusher's publication",
        ));
    }
    Ok(())
}

/// [`require_received_files_source_in_txn`] in its own snapshot.
///
/// # Errors
/// As there.
pub(in crate::repo_mutation) fn require_received_files_source(
    vault: &Vault,
    request: &RepoMutationRequest,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    require_received_files_source_in_txn(vault, &txn, request)
}

/// Lowers every file of the received bundle `row` into its document, in
/// ONE grouped ingress under each file's deterministic operation: text
/// and metadata together, a removal keeping its text and freeing its path,
/// and a removed untouched blob lowering to no document at all. A replay
/// with the same operations appends nothing.
///
/// # Errors
/// A document that moved since the bundle's base, bytes that are not
/// UTF-8, or a store failure.
pub(in crate::repo_mutation) fn land_received_files_documents(
    vault: &Vault,
    row: &RepoProposal,
) -> Result<()> {
    let repo = RepoRef::parse(&row.repo)?;
    let before = vault.mount_repo_ref(&repo, RepoMountRef::Fork(row.pre_action_fork_hash))?;
    let scope = super::oplog::repo_mutation_repo_key(&repo);
    let actor = WriteActor::new(row.actor.live()?, row.document_class()?);
    let utf8 = |bytes: &[u8]| -> Result<String> {
        String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::InvalidClaimBody("code document requires UTF-8"))
    };
    let mut items = Vec::new();
    for file in &row.files {
        let state = file
            .metadata_edit
            .as_ref()
            .ok_or(invalid("a received file carries its reviewed state change"))?;
        let source = file
            .source_operation
            .ok_or(invalid("a received file names its source operation"))?;
        let old = utf8(before.read_file(&file.path)?.unwrap_or(b""))?;
        let changed_state = state.expected != state.replacement;
        let (edit, metadata_edit) = match &file.content {
            None => {
                // An untouched blob has no document to retire.
                if vault.code_document_frontier(&scope, &file.path)?.is_none() {
                    continue;
                }
                (
                    CodeFileEdit::between(&file.path, &old, &old),
                    Some(state.clone()),
                )
            }
            Some(new) => {
                let new = utf8(new)?;
                if new == old && !changed_state {
                    continue;
                }
                (
                    CodeFileEdit::between(&file.path, &old, &new),
                    changed_state.then(|| state.clone()),
                )
            }
        };
        let session = vault.open_code_document(&scope, &file.path, &old, row.session)?;
        items.push(CodeFileIngress {
            operation: received_file_operation(row.id, source)?,
            session,
            edit,
            metadata_edit,
            actor,
            expected_text: old,
        });
    }
    vault.apply_code_file_ingress_exact(&mut items)?;
    Ok(())
}

/// The ONE queue proposal a stored received bundle is: its id, the green
/// it is pinned at, and every file with the bytes its base fork holds
/// there, its reviewed bytes and its reviewed state change. The caller
/// supplies no file, mode or removal.
///
/// # Errors
/// A row that is no received bundle, or a base fork that cannot be read.
pub(crate) fn received_merge_proposal(
    vault: &Vault,
    row: &RepoProposal,
    base_green: &str,
) -> Result<MergeProposal> {
    if row.received_candidate().is_none() {
        return Err(invalid("not a received push bundle"));
    }
    let base = vault.mount_repo_ref(
        &RepoRef::parse(&row.repo)?,
        RepoMountRef::Fork(row.pre_action_fork_hash),
    )?;
    let files = row
        .files
        .iter()
        .map(|file| {
            Ok(MergeFile {
                path: file.path.clone(),
                expected: base.read_file(&file.path)?.map(<[u8]>::to_vec),
                content: file.content.clone(),
                metadata_edit: file.metadata_edit.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(MergeProposal {
        id: row.id.to_hex(),
        base_green: base_green.to_owned(),
        files,
    })
}
