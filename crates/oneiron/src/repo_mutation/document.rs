//! Review-approved repository file updates lower to idempotent document edits.
use super::mount::RepoMountRef;
use crate::code_document::{CodeFileEdit, CodeFileIngress};
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
    let session = vault.open_code_document(&scope, &proposal.path, old, proposal.session)?;
    vault.apply_code_file_ingress_exact(&mut [CodeFileIngress {
        operation: proposal_id,
        session,
        edit: CodeFileEdit::between(&proposal.path, old, new),
        actor: WriteActor::new(proposal.actor, EdgeActorClass::Agent),
        expected_text: old.to_owned(),
    }])?;
    Ok(())
}
