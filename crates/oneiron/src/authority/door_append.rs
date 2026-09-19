//! Door-local signing, but authority-log-owned immutable ledger and atomic admission.

use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::credential_door::{CredentialDoorError, DoorResult, log_unreachable};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::{TimeRange, Vault};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;

impl Vault {
    /// Appends only a mint/spend/revoke, deriving seq and complete frontier in
    /// the caller's write transaction. No caller supplies expanded authority.
    pub(crate) fn append_local_door_op_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        op: AuthorityOp,
    ) -> DoorResult<AuthorityEntryHash> {
        if !matches!(
            op,
            AuthorityOp::MintDoorSlip(_)
                | AuthorityOp::SpendDoorSlip { .. }
                | AuthorityOp::RevokeDoorSlip { .. }
        ) {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        let fold = self
            .authority_fold_readonly_in_txn(txn)
            .map_err(log_unreachable)?;
        let raw = self
            .store
            .sync_state
            .get(txn, crate::identity::KEY_DEVICE_SK)
            .map_err(log_unreachable)?
            .ok_or(CredentialDoorError::AuthorityRejected)?;
        let seed: [u8; 32] = raw
            .as_ref()
            .try_into()
            .map_err(|_| CredentialDoorError::AuthorityRejected)?;
        let signing = SigningKey::from_bytes(&seed);
        let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
        if !fold
            .roster
            .get(&key)
            .is_some_and(folded_device_can_authority_consent)
            || fold
                .authority_forks
                .iter()
                .any(|fork| fork.signer == key && fork.status == AuthorityForkStatus::Quarantined)
        {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        let mut frontier: BTreeSet<_> = fold.valid_entries.clone();
        let mut seq = 0u64;
        for row in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_AUTHORITY_LOG])
            .map_err(log_unreachable)?
        {
            let (index, _) = row.map_err(log_unreachable)?;
            let id =
                crate::vault::entity_id_from_type_index_key(&index).map_err(log_unreachable)?;
            let raw = self
                .store
                .entities
                .get(txn, id.as_bytes())
                .map_err(log_unreachable)?
                .ok_or(CredentialDoorError::AuthorityLogUnreachable)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(CredentialDoorError::AuthorityLogUnreachable)?;
            if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
                return Err(CredentialDoorError::AuthorityLogUnreachable);
            }
            let entry = decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                .map_err(log_unreachable)?;
            let hash = authority_entry_hash(&entry).map_err(log_unreachable)?;
            // Advance beyond even a signed rejected local entry. Reusing a seq
            // would create an equivocation, not a retry.
            if entry.signer.public_key == key {
                seq = seq.max(entry.seq);
            }
            if fold.valid_entries.contains(&hash) {
                for parent in entry.parent_hashes {
                    frontier.remove(&parent);
                }
            }
        }
        if frontier.is_empty() || frontier.len() > MAX_PARENTS {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        let now = self.instant_in_txn(txn).map_err(log_unreachable)?.secs();
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: fold.vault_id,
            seq: seq
                .checked_add(1)
                .ok_or(CredentialDoorError::AuthorityRejected)?,
            parent_hashes: frontier.into_iter().collect(),
            op,
            signer: AuthoritySignature {
                suite: key.suite(),
                public_key: key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        entry.signer.signature = signing
            .sign(&authority_transcript(&entry).map_err(log_unreachable)?)
            .to_bytes()
            .to_vec();
        let hash = authority_entry_hash(&entry).map_err(log_unreachable)?;
        self.put_authority_log_entries_in_txn(
            txn,
            &[(
                entry,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )],
        )
        .map_err(log_unreachable)?;
        let after = self
            .authority_fold_readonly_in_txn(txn)
            .map_err(log_unreachable)?;
        if !after.valid_entries.contains(&hash) || after.pending_widens.contains_key(&hash) {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        Ok(hash)
    }
}
