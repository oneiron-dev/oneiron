//! Host-landed MACHINE enrollment: one EnrollDevice and its BindActor.
use ed25519_dalek::VerifyingKey;

use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::{EntityId, TimeRange, Vault};

use super::machine_write::denied;
use super::slip_vault::require_host;
use super::{
    AuthorityAttestation, AuthorityKey, AuthorityOp, AuthoritySignature, AuthoritySignatureSuite,
    AuthorityTier, DeviceAuthority, HostSlipIssuer, ROLE_AGENT, authority_entry_hash,
    authority_transcript, invalid_authority,
};

/// Bind an existing MACHINE row to a fresh per-vault Ed25519 authority key.
/// The retained host root signs both enrollment and actor binding in one transaction.
/// This door never creates, holds or exports the machine's private key.
impl Vault {
    pub fn enroll_machine_identity(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        public_key: [u8; 32],
        transport_key_binding: [u8; 32],
        sign_binding: impl FnOnce(&[u8]) -> Result<[u8; 64]>,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.enroll_machine_identity_in_txn(
            &mut txn,
            issuer,
            machine,
            public_key,
            transport_key_binding,
            sign_binding,
        )?;
        // A host-landed enrollment takes effect at once: the device-key widen
        // delay is dead (identity.md, "Device-key widen ceremony").
        txn.commit()?;
        self.retain_machine_history_issuer(issuer)?;
        Ok(())
    }

    pub(super) fn enroll_machine_identity_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        public_key: [u8; 32],
        transport_key_binding: [u8; 32],
        sign_binding: impl FnOnce(&[u8]) -> Result<[u8; 64]>,
    ) -> Result<()> {
        let raw = self
            .store
            .entities
            .get(txn, machine.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_MACHINE)
        {
            return Err(denied());
        }
        VerifyingKey::from_bytes(&public_key).map_err(|_| denied())?;
        if transport_key_binding == public_key {
            return Err(denied());
        }
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        let key = AuthorityKey::Ed25519(public_key);
        if fold.roster.contains_key(&key) || fold.actor_bindings.contains_key(&key) {
            return Err(denied());
        }
        let seq = fold
            .append_sequences
            .get(&issuer.public_key())
            .ok_or_else(invalid_authority)?
            .checked_add(1)
            .ok_or_else(invalid_authority)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let now = self.instant_in_txn(txn)?.secs();
        let enroll = issuer.sign_entry(
            Some(vault_id),
            seq,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::EnrollDevice {
                device: DeviceAuthority {
                    key: key.clone(),
                    transport_key_binding,
                    attestation: AuthorityAttestation {
                        kind: "SoftwareArgon2id".into(),
                        evidence: Vec::new(),
                    },
                    tier: AuthorityTier::Software,
                    roles: ROLE_AGENT,
                },
            },
            now,
        )?;
        let enroll_hash = authority_entry_hash(&enroll)?;
        let mut bind = issuer.sign_entry(
            Some(vault_id),
            seq.checked_add(1).ok_or_else(invalid_authority)?,
            vec![enroll_hash],
            AuthorityOp::BindActor {
                authority_key: key.clone(),
                actor_ref: machine,
                actor_class: "system".into(),
                epoch: 1,
            },
            now,
        )?;
        bind.cosigns.push(AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: key,
            signature: vec![0; 64],
        });
        let transcript = authority_transcript(&bind)?;
        bind.cosigns[0].signature = sign_binding(&transcript)?.to_vec();
        issuer.resign_entry(&mut bind)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(enroll, at, now), (bind, at, now)])?;
        Ok(())
    }
}
