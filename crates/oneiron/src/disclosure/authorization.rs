//! Exact-action owner intent. Speaker labels and caller-supplied actor IDs
//! are not authority. A live owner-bound key must sign this utterance.

use super::{ScopeCeiling, encode_scope_ceiling_body};
use crate::authority::{
    ActorBindingStatus, AuthoritySignature, AuthorityVaultId, verify_authority_signature,
};
use crate::error::{Error, GateError, Result};
use crate::{EntityId, Vault};

/// Per-utterance authorization for an exact contact clearance. A host signs
/// only after the owner explicitly requests this action. Voice attribution
/// and inferred behavior cannot produce a valid signature.
#[derive(Debug, Clone)]
pub struct DisclosureScopeAuthorization {
    pub vault_id: AuthorityVaultId,
    pub actor: EntityId,
    pub epoch: u64,
    pub utterance: EntityId,
    pub signature: AuthoritySignature,
}

impl DisclosureScopeAuthorization {
    /// Canonical domain-separated bytes to sign. The target, all five axes,
    /// vault, speaker binding epoch and utterance nonce are bound together.
    pub fn transcript(&self, contact: &EntityId, ceiling: &ScopeCeiling) -> Result<Vec<u8>> {
        let mut bytes = self.intent_prefix(b"clearance");

        bytes.extend_from_slice(contact.as_bytes());
        bytes.extend_from_slice(&encode_scope_ceiling_body(ceiling)?);
        Ok(bytes)
    }

    /// Exact signed action for clearing an owner Tier-A mark.
    pub fn clear_tier_a_transcript(&self, id: &EntityId, cleared_at: u64) -> Vec<u8> {
        let mut bytes = self.intent_prefix(b"clear-tier-a");
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&cleared_at.to_be_bytes());
        bytes
    }

    /// Exact signed restamp bound to the current record body digest.
    pub fn restamp_transcript(
        &self,
        id: &EntityId,
        position: &super::ScopePosition,
        body_sha256: [u8; 32],
    ) -> Result<Vec<u8>> {
        let mut bytes = self.intent_prefix(b"restamp-position");
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&body_sha256);
        bytes.extend_from_slice(&super::encode_scope_position_body(position)?);
        Ok(bytes)
    }

    pub(super) fn roster_transcript(
        &self,
        session: EntityId,
        revision: u64,
        roster: &crate::interlocutor::InterlocutorSet,
    ) -> Result<Vec<u8>> {
        let mut bytes = self.intent_prefix(b"confirm-roster");
        bytes.extend_from_slice(session.as_bytes());
        bytes.extend_from_slice(&revision.to_be_bytes());
        let roster = serde_json::to_vec(roster)
            .map_err(|_| Error::InvariantViolation("roster encoding failed"))?;
        bytes.extend_from_slice(&roster);
        Ok(bytes)
    }

    fn intent_prefix(&self, action: &[u8]) -> Vec<u8> {
        let mut bytes = b"oneiron.disclosure.owner-intent.v2\0".to_vec();
        bytes.extend_from_slice(&(action.len() as u64).to_be_bytes());
        bytes.extend_from_slice(action);
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(self.actor.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(self.utterance.as_bytes());
        bytes
    }

    pub(super) fn consume(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        contact: &EntityId,
        ceiling: &ScopeCeiling,
    ) -> Result<()> {
        self.consume_transcript(vault, txn, self.transcript(contact, ceiling)?)
    }

    pub(super) fn consume_transcript(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        transcript: Vec<u8>,
    ) -> Result<()> {
        let fold = vault.authority_fold_readonly_in_txn(txn)?;
        let denied = || {
            Error::Gate(GateError::DisclosureClampViolation(
                "owner-signed disclosure intent required",
            ))
        };
        if fold.vault_id != Some(self.vault_id) {
            return Err(denied());
        }
        let Some(binding) = fold.actor_bindings.get(&self.signature.public_key) else {
            return Err(denied());
        };
        if binding.status != ActorBindingStatus::Active
            || binding.actor_class != "human"
            || binding.actor_ref != self.actor
            || binding.epoch != self.epoch
        {
            return Err(denied());
        }
        if !verify_authority_signature(&self.signature, &transcript) {
            return Err(denied());
        }
        let mut key = b"disclosure.intent.v2:".to_vec();
        key.extend_from_slice(self.utterance.as_bytes());
        if vault.store.vault_meta.get(txn, &key)?.is_some() {
            return Err(denied());
        }
        // Audit and replay refusal commit in the same transaction as the grant.
        let mut audit = transcript;
        audit.extend_from_slice(&self.signature.signature);
        vault.store.vault_meta.put(txn, &key, &audit)?;
        Ok(())
    }
}
