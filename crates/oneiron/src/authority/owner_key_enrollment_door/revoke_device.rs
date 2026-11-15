//! The one `RevokeDevice` writer: an entry signed by the host root or a live
//! roster key, in the caller's write transaction (pass 27 R4).

use super::*;

/// The fold did not count a key revocation signed by a roster key in this
/// transaction. Nothing was written.
const REVOKE_NOT_COUNTED: &str = "this install's fold does not count the key revocation; nothing \
                                  was written";

/// The signer of one authority entry a door writes in its own write
/// transaction (the one `RevokeDevice` writer, pass 27 R4).
pub(crate) enum EntrySigner<'a> {
    /// This vault's live host root, through its slip issuer.
    Host(&'a HostSlipIssuer),
    /// A live roster key held behind the caller's signing callback, which
    /// signs the entry's authority transcript: the recovery root's
    /// authority key at the root's door.
    Key(&'a AuthorityKey, &'a dyn Fn(&[u8]) -> Result<Vec<u8>>),
}

impl Vault {
    /// One `RevokeDevice` of `revoked_key`, signed by `signer`, in the
    /// caller's write transaction: the one writer of the act (the
    /// membership move signs it with the host root, the recovery root's door
    /// with the root's authority key). It joins a frontier wider than one
    /// entry names, names the main-log heads, takes the signer's next
    /// sequence, and answers the entry's hash only once the fold counts it.
    ///
    /// # Errors
    /// The log's: a signer that is not a live roster key of this vault, or
    /// an entry the fold does not count.
    pub(crate) fn append_revoke_device_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        signer: EntrySigner<'_>,
        revoked_key: AuthorityKey,
    ) -> Result<AuthorityEntryHash> {
        let op = AuthorityOp::RevokeDevice { revoked_key };
        let (key, sign) = match signer {
            EntrySigner::Host(issuer) => return self.append_hashed_slip_op_in_txn(txn, issuer, op),
            EntrySigner::Key(key, sign) => (key, sign),
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let joiner = FrontierSigner::Callback(key, sign);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let parents = fold.append_heads.clone();
        if parents.is_empty() {
            return Err(invalid_authority());
        }
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(&fold, key)?,
            parent_hashes: parents.into_iter().collect(),
            op,
            signer: AuthoritySignature {
                suite: key.suite(),
                public_key: key.clone(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        entry.signer.signature = sign(&authority_transcript(&entry)?)?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        if !self
            .authority_view_readonly_in_txn(txn)?
            .valid_entries
            .contains(&hash)
        {
            return Err(authority_refused(REVOKE_NOT_COUNTED));
        }
        Ok(hash)
    }
}
