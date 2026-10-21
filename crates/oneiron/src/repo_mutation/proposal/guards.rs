use super::*;

pub(super) fn validate_conflict_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: &RepoProposal,
) -> Result<()> {
    let RepoProposalOperation::ResolveConflictFile {
        branch_subject,
        open_conflict_claim_id,
        branch_name,
    } = &proposal.operation
    else {
        return Ok(());
    };
    let (resolved, _) = proposal.ordinary_file()?;
    let claim = vault
        .get_claim_in_txn(txn, open_conflict_claim_id)?
        .ok_or(Error::EntityNotFound)?;
    let value =
        crate::repo_mutation::conflict_value::decode_repo_conflict_open_value(&claim.value)?;
    if claim.predicate != crate::claim::PREDICATE_CONFLICT_OPEN
        || claim.lifecycle != ClaimLifecycleStatus::Active
        || claim.subject != ClaimSubject::Entity(*branch_subject)
        || !crate::repo_mutation::oplog::same_repository(
            &value.repo_ref,
            &RepoRef::parse(&proposal.repo)?,
        )
        || value.branch != *branch_name
        || !value.conflicted_paths.iter().any(|path| path == resolved)
    {
        return Err(invalid(
            "resolution does not name its active repository conflict",
        ));
    }
    let task = vault
        .repo_reconciliation_task_in_txn(txn, *open_conflict_claim_id)?
        .ok_or(Error::EntityNotFound)?;
    require_entity_kind(vault, txn, task, crate::registry::ENTITY_TYPE_TASK)?;
    Ok(())
}

pub(in crate::repo_mutation) fn require_repo_artifact_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    repository: EntityId,
    expected: &RepoRef,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &repository)?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("code artifact header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CODE_ARTIFACT {
        return Err(invalid("repository must be a code artifact"));
    }
    let body = crate::code_artifact::decode_code_artifact_body(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    if RepoRef::parse(&body.repo_ref)? != *expected {
        return Err(Error::ConcurrentWrite("repository pointer changed"));
    }
    Ok(())
}

pub(super) fn require_entity_kind(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("code door source header"))?;
    if header.entity_type != kind {
        return Err(invalid("code door source has the wrong entity kind"));
    }
    Ok(())
}
