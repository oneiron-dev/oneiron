//! The executor's signed result for one request, and the receipt door that
//! reads where a request stands.

use super::OwnerWorkReceipt;
use crate::authority::{
    AuthorityEntryHash, AuthorityKey, AuthorityOp, MAX_PARENTS, OwnerWorkOutcome, OwnerWorkResult,
    authority_entry_hash, invalid_authority, next_sequence, owner_act_signer_admits,
    sign_side_entry,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault};

/// This install cannot sign the result: the roster holds no live profile of
/// it under its install key. Key possession; the transaction is refused and
/// the request stays pending.
fn no_executor_key() -> Error {
    Error::InvalidConfig(
        "this install has no live machine profile in the vault's roster to sign its owner work \
         result; the request stays pending"
            .to_owned(),
    )
}

impl Vault {
    /// Appends `executor`'s result for the request signed as entry `request`
    /// in the caller's write transaction, after the work it reports, signed
    /// with this install's key. Its parents are the main-log heads alone,
    /// which carry the request in its causal past (FIX 4987), never a key
    /// record. The fold is the judge: a result it does not take as the
    /// request's one terminal state refuses the transaction.
    pub(crate) fn append_owner_work_result_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: AuthorityEntryHash,
        executor: EntityId,
        outcome: OwnerWorkOutcome,
    ) -> Result<AuthorityEntryHash> {
        let signing = self.door_signing_key_in_txn(txn, executor)?;
        let public_key = signing.verifying_key().to_bytes();
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if !owner_act_signer_admits(fold.machine(executor), &fold.roster, &public_key) {
            return Err(no_executor_key());
        }
        let parents = fold.owner_work_parents();
        if parents.len() > MAX_PARENTS {
            return Err(Error::InvalidConfig(format!(
                "this owner work result would name {} parent rows, more than the {MAX_PARENTS} one \
                 authority entry names; the request stays pending",
                parents.len()
            )));
        }
        let seq = next_sequence(&fold, &AuthorityKey::Ed25519(public_key))?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &signing,
            seq,
            parents,
            AuthorityOp::OwnerWorkResult(OwnerWorkResult {
                request,
                executor,
                outcome,
            }),
            now,
        )?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if after
            .owner_work_result(&request)
            .is_none_or(|answer| answer.entry != hash)
        {
            return Err(invalid_authority());
        }
        Ok(hash)
    }

    /// Where the owner work request signed as entry `request` stands, derived
    /// from this install's fold: recorded and awaiting a holder until its
    /// executor's result arrives, then enacted or refused. An owner's read:
    /// the proof is revalidated as a live vault owner. `None` when this
    /// install folds no such request. "Enacted" says the executor did the
    /// work and committed it, never that every replica holds it.
    pub fn owner_work_receipt(
        &self,
        owner: &AuthenticatedOwner,
        request: AuthorityEntryHash,
    ) -> Result<Option<OwnerWorkReceipt>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(OwnerWorkReceipt::of(&fold, request))
    }
}
