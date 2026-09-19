//! Review-approved repository file updates lower to idempotent document edits.
use super::mount::RepoMountRef;
use crate::code_document::CodeFileEdit;
use crate::codebase::RepoRef;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

pub(super) fn land_reviewed_document(vault: &Vault, proposal_id: EntityId) -> Result<()> {
    let proposal = vault
        .repo_proposal(proposal_id)?
        .ok_or(Error::EntityNotFound)?;
    let repo = RepoRef::parse(&proposal.repo)?;
    let before = vault.mount_repo_ref(&repo, RepoMountRef::Fork(proposal.pre_action_fork_hash))?;
    let old = before.read_file(&proposal.path)?.unwrap_or(b"");
    let old = std::str::from_utf8(old)
        .map_err(|_| Error::InvalidClaimBody("code document requires UTF-8"))?;
    let new = std::str::from_utf8(&proposal.content)
        .map_err(|_| Error::InvalidClaimBody("code document requires UTF-8"))?;
    if old == new {
        return Ok(());
    }
    let scope = super::oplog::repo_mutation_repo_key(&repo);
    let mut session = vault.open_code_document(&scope, &proposal.path, old, proposal.session)?;
    // A document can be ahead of its last commit. Do not reinterpret an old
    // whole-file proposal as deletion of unseen live operations.
    if vault.code_file_edit_receipt(proposal_id)?.is_none() && session.text() != old {
        return Err(Error::ConcurrentWrite(
            "document changed since review; no automatic rebase",
        ));
    }
    vault.apply_code_file_edit_once(
        proposal_id,
        &mut session,
        &CodeFileEdit::between(&proposal.path, old, new),
        WriteActor::new(proposal.actor, EdgeActorClass::Agent),
    )?;
    Ok(())
}
