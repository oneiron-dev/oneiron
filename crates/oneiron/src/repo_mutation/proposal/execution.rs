//! A proposal's execution bookkeeping (moved from `proposal.rs`): the
//! prepared operation it binds, the read of the proposal behind one
//! operation, and the status its finished operation sets.

use super::*;

pub(in crate::repo_mutation) fn bind_prepared(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: Option<EntityId>,
    repo: &RepoRef,
    seq: u64,
) -> Result<()> {
    let Some(id) = id else {
        return Ok(());
    };
    let mut row = PROPOSAL
        .get(&vault.store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    if row.operation_seq.is_some() || row.status != RepoProposalStatus::Approved {
        return Err(invalid("proposal already consumed"));
    }
    row.operation_seq = Some(seq);
    store(vault, txn, &row)?;
    PROPOSAL_OP.put(&vault.store, txn, &op_key(repo, seq), &id)?;
    Ok(())
}
pub(in crate::repo_mutation) fn for_operation(
    vault: &Vault,
    repo: &RepoRef,
    seq: u64,
) -> Result<Option<RepoProposal>> {
    let txn = vault.store.env.read_txn()?;
    let Some(id) = PROPOSAL_OP.get(&vault.store, &txn, &op_key(repo, seq))? else {
        return Ok(None);
    };
    let row = PROPOSAL
        .get(&vault.store, &txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    if row.id != id || row.operation_seq != Some(seq) || RepoRef::parse(&row.repo)? != *repo {
        return Err(invalid("proposal operation binding differs"));
    }
    Ok(Some(row))
}

/// Sets the proposal bound to `repo`'s operation `seq` to that operation's
/// finished `status`, in the oplog's final writer, and keeps the attempt's
/// completion receipt (FIX 4338): applied or failed for this attempt alone.
pub(in crate::repo_mutation) fn finish(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    repo: &RepoRef,
    seq: u64,
    status: RepoMutationStatus,
) -> Result<()> {
    let Some(id) = PROPOSAL_OP.get(&vault.store, txn, &op_key(repo, seq))? else {
        return Ok(());
    };
    let mut row = PROPOSAL
        .get(&vault.store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    row.status = match status {
        RepoMutationStatus::Applied => RepoProposalStatus::Applied,
        RepoMutationStatus::Failed => RepoProposalStatus::Failed,
        RepoMutationStatus::Prepared => RepoProposalStatus::Approved,
    };
    // An erased actor's applied write approves its journal naming no one (FIX 4479).
    if status == RepoMutationStatus::Applied {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        let bytes = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("proposal entity header"))?;
        let mut claim = crate::claim::decode_claim_body(bytes, true)?;
        if claim.predicate != "repo.proposed_diff"
            || crate::claim::session_claim_producer(&claim) != row.actor.id()
        {
            return Err(Error::CorruptedIndex("proposal claim binding changed"));
        }
        claim.approval = ClaimApprovalStatus::Approved;
        // Keep the producer envelope on the approval transition as well as
        // admission. A reserved raw put is not a session-write capability.
        // A stack member keeps the review its stack's admission sealed (FIX
        // 8268); a proposal applied alone, its own catalog's critics.
        let reviewed = match row.merge_stack.as_deref() {
            Some(batch) => row.stack_review_admitted(batch)?,
            None => row.eligible()?,
        };
        if !reviewed {
            return Err(invalid("proposal approval lost critic coverage"));
        }
        put_journal_claim(vault, txn, id, row.actor.id(), &claim, row.created_at)?;
    }
    // This attempt's own completion receipt, kept as history (FIX 4338).
    super::receipts::record_attempt_in_txn(vault, txn, &row, repo, seq, status)?;
    store(vault, txn, &row)
}
