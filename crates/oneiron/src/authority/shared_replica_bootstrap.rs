//! Signed authority and holder checks for one isolated shared-replica root write.

use super::history_transfer::DecodedRow;
use super::*;
use crate::error::Result;
use crate::{EntityId, Vault};

/// Original signed inputs, not a verified grant or a commit receipt.
/// The isolated caller imports history, stages native rows, then admits the
/// request against those rows before its one root writer may commit.
pub(crate) struct PreparedSharedReplicaAuthority {
    history: Vec<DecodedRow>,
    slip: CapabilitySlip,
    timestamp: u64,
    signature: Vec<u8>,
    nonce: Vec<u8>,
    member: EntityId,
    binding_key: [u8; 32],
}

impl PreparedSharedReplicaAuthority {
    pub(crate) fn prepare(
        history: Vec<Vec<u8>>,
        slip: CapabilitySlip,
        timestamp: u64,
        signature: Vec<u8>,
        nonce: Vec<u8>,
        member: EntityId,
        binding_key: [u8; 32],
    ) -> Result<Self> {
        let history = history
            .into_iter()
            .map(|bytes| {
                let entry = decode_authority_log_entry_body(&bytes)?;
                Ok((authority_entry_hash(&entry)?, bytes, entry))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            history,
            slip,
            timestamp,
            signature,
            nonce,
            member,
            binding_key,
        })
    }

    /// Original signed bodies, keyed exactly as the native import stores them.
    /// Keep these outside staging so the final same-writer read check binds
    /// every carried byte, not only the import-time metadata header.
    pub(crate) fn original_history_rows(
        &self,
    ) -> Result<std::collections::BTreeMap<EntityId, Vec<u8>>> {
        self.history
            .iter()
            .map(|(_, bytes, entry)| Ok((authority_log_entity_id(entry)?, bytes.clone())))
            .collect()
    }

    /// Checks the log's mint and the original holder proof before content
    /// staging. It does not claim that the member GRANT has landed yet.
    pub(crate) fn stage_history_in_txn(
        &mut self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<Vec<EntityId>> {
        if !vault.authority_is_unstarted_in_txn(txn)? {
            return Err(invalid_authority());
        }
        let ids = vault
            .import_decoded_authority_history_in_txn(txn, std::mem::take(&mut self.history))?;
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        let challenge = super::slip_replay::request_challenge(
            self.timestamp,
            &self.nonce,
            super::slip_replay::request_now_in_txn(vault, txn)?,
        )?;
        let mint = fold
            .slips
            .mints
            .get(&self.slip.claims.slip_id)
            .ok_or_else(invalid_authority)?;
        let verified = self.slip.verify(
            &mint.signer,
            &fold,
            vault.instant_in_txn(txn)?.secs(),
            &challenge,
            &self.signature,
        )?;
        self.check_recipient(&verified)?;
        Ok(ids)
    }

    /// Final native admission uses the same writer after PERSON and GRANT
    /// materialization. Its current grant checks and nonce spend are not
    /// replaced by the earlier cryptographic check.
    pub(crate) fn admit_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<VerifiedSlip> {
        let verified = vault.admit_capability_slip_request_in_txn(
            txn,
            &self.slip,
            self.timestamp,
            &self.signature,
            &self.nonce,
        )?;
        self.check_recipient(&verified)?;
        Ok(verified)
    }

    fn check_recipient(&self, verified: &VerifiedSlip) -> Result<()> {
        let claims = verified.claims();
        if claims.holder_ref != self.member.to_hex()
            || claims.binding_key != self.binding_key
            || claims.grant_ref.is_none()
            || claims.invitation_ref.is_some()
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

impl Vault {
    /// Whether native authority has never started in this replica target.
    /// This is an early host check only. Import repeats the same predicate
    /// on its actual writer before any authority history may land.
    pub fn is_unstarted_replica_target(&self) -> Result<bool> {
        self.authority_is_unstarted()
    }
}
