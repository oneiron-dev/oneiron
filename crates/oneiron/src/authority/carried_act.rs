//! The signed half of the owner's setting and export doors (FIX 4624, FIX
//! 5660): an act a door already applied lands as one op this install
//! carries, so every machine the owner admits folds and checks it.
//!
//! The door keeps its own local record (a side table or the setting's own
//! row) as before, and in the same write calls [`Vault::record_carried_act_in_txn`].
//! That signs the op with this install's machine key under the one carrier
//! rule ([`super::owner_act_signer_admits`]), appends it and folds it, in a
//! savepoint of the door's transaction. Whatever it meets (no carrier, a
//! frontier too wide, a fold that does not count it, a storage fault) is
//! logged and rolls the savepoint back alone: the door's change stands as it
//! did before the op existed (rubric 1, no new refusal).

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::{TimeRange, Vault};

use super::*;

/// This install cannot carry the act: it has no machine identity or install
/// key, or no live profile of it stands under that key. No roster key, the
/// host root included, carries an owner act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's act";
/// The act would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str =
    "the authority log has more concurrent heads than one owner act may name";
/// The fold did not count the signed act here.
const NOT_COUNTED: &str = "the authority fold did not count the owner's act";

impl Vault {
    /// Records the act `op` builds, given the carrier, as a signed op in a
    /// savepoint of `txn`, best effort: a fault is logged under `what` and
    /// leaves `txn` as it was. The entry hash when the fold counted it.
    pub(super) fn record_carried_act_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        what: &'static str,
        op: impl FnOnce(EntityId) -> AuthorityOp,
    ) -> Option<AuthorityEntryHash> {
        match self.append_carried_act_in_savepoint(txn, op) {
            Ok(hash) => Some(hash),
            Err(error) => {
                tracing::warn!(
                    act = what,
                    %error,
                    "the owner act stands on this install alone: no signed record of it was appended"
                );
                None
            }
        }
    }

    fn append_carried_act_in_savepoint(
        &self,
        txn: &mut heed::RwTxn<'_>,
        op: impl FnOnce(EntityId) -> AuthorityOp,
    ) -> Result<AuthorityEntryHash> {
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let hash = self.append_carried_act_in_txn(&mut savepoint, op)?;
        savepoint.commit()?;
        Ok(hash)
    }

    /// Signs, appends and folds the act `op` builds in `txn`, naming the
    /// main-log heads alone, as every owner act does; returns only once the
    /// fold in `txn` counted it.
    fn append_carried_act_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        op: impl FnOnce(EntityId) -> AuthorityOp,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        if !super::owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Install(machine, &key);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(&fold, &key, seq, parents, op(machine), now)?;
        let entry_hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after.valid_entries.contains(&entry_hash)
            || after.install.held_back.contains(&entry_hash)
        {
            return Err(authority_refused(NOT_COUNTED));
        }
        Ok(entry_hash)
    }
}
