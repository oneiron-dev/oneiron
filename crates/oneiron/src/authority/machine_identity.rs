//! A physical machine's identity: this install's own machine, the owner's
//! enrolment door, and the proof a connection carries.
//!
//! Three identities stay apart. The MACHINE row an install is (its id lives
//! with its own machine key, `identity.rs`); the engine's writer actors, which
//! are MACHINE rows bound as `system` actors and never get a profile; and the
//! Loro client id, a CRDT peer id that names no machine.

use ed25519_dalek::{Signature, Signer, VerifyingKey};

use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::ports::{EntityRecord, EntityStore, EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::{EntityId, TimeRange, Vault};

use super::slip_vault::{next_entry, require_host};
use super::*;

const MACHINE_CONNECTION_DOMAIN: &[u8] = b"oneiron/machine-proof/v1\0";
/// The request header a machine names itself in, beside the slip proof.
pub const MACHINE_PROOF_HEADER: &str = "x-oneiron-machine";
/// An empty MessagePack map: a MACHINE row the enrolment had to create.
const EMPTY_MACHINE_BODY: &[u8] = &[0x80];

/// What a machine sends to join a vault: its row, its keys, and its own
/// signature over them for that vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineEnrolmentRequest {
    pub vault_id: [u8; 32],
    pub machine: EntityId,
    pub machine_key: [u8; 32],
    pub encryption_key: MachineEncryptionKey,
    pub machine_proof: [u8; 64],
}

/// This install's machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMachine {
    pub id: EntityId,
    /// The owner's profile for this row, only when it names this install's key.
    pub profile: Option<FoldedMachine>,
}

/// The machine at the other end of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMachine {
    /// A live profiled machine that proved its machine key on this connection.
    Proven(EntityId),
    /// No proof, a proof that did not verify, or a machine not live here. It
    /// is never read as this machine or as one of the owner's.
    Unknown,
}

/// The bytes a machine signs to name itself on one authenticated request. They
/// bind the request's own slip proof (token, timestamp, nonce), so the
/// machine proof is exactly as fresh, and as single-use, as that proof.
#[must_use]
pub fn machine_connection_transcript(
    vault_id: &[u8; 32],
    machine: EntityId,
    token: &str,
    timestamp: u64,
    nonce: &str,
) -> Vec<u8> {
    let mut bytes = MACHINE_CONNECTION_DOMAIN.to_vec();
    bytes.extend_from_slice(vault_id);
    bytes.extend_from_slice(machine.as_bytes());
    bytes.extend_from_slice(blake3::hash(token.as_bytes()).as_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(nonce.as_bytes());
    bytes
}

/// The [`MACHINE_PROOF_HEADER`] value: the machine and its machine key's
/// signature over [`machine_connection_transcript`].
#[must_use]
pub fn machine_proof_header_value(machine: EntityId, signature: &[u8; 64]) -> String {
    let signature: String = signature.iter().map(|byte| format!("{byte:02x}")).collect();
    serde_json::json!({ "machine": machine.to_hex(), "signature": signature }).to_string()
}

impl Vault {
    /// This install's machine and, once the owner enrolled it, its profile.
    pub fn local_machine(&self) -> Result<Option<LocalMachine>> {
        let txn = self.store.env.read_txn()?;
        let Some(id) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .map(|key| key.verifying_key().to_bytes());
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let profile = fold
            .machine(id)
            .filter(|machine| key == Some(machine.profile.machine_key))
            .cloned();
        Ok(Some(LocalMachine { id, profile }))
    }

    /// Called on the machine that joins: mints (once) and keeps this install's
    /// machine id and key, and signs its identity for `vault_id` with that key.
    pub fn machine_enrolment_request(
        &self,
        vault_id: [u8; 32],
        encryption_key: MachineEncryptionKey,
    ) -> Result<MachineEnrolmentRequest> {
        encryption_key.validate()?;
        let mut request = None;
        self.with_write_txn_grouped(|wtxn| {
            let (machine, key) = crate::identity::load_or_mint_machine_in_txn(self, wtxn)?;
            let machine_key = key.verifying_key().to_bytes();
            let machine_proof = key
                .sign(&machine_profile_proof_transcript(
                    &vault_id,
                    machine,
                    &machine_key,
                    &encryption_key,
                ))
                .to_bytes();
            request = Some(MachineEnrolmentRequest {
                vault_id,
                machine,
                machine_key,
                encryption_key: encryption_key.clone(),
                machine_proof,
            });
            Ok(())
        })?;
        Ok(request.expect("closure ran on Ok"))
    }

    /// The owner adds a machine. `role` is the owner's answer: only
    /// `Owned(Yours)` makes it mine; a hosted or rented node is never mine.
    /// The MACHINE row is created when absent. Lands one `MachineProfile`
    /// under the host root, revalidating the owner in the write transaction.
    pub fn enroll_machine(
        &self,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        request: &MachineEnrolmentRequest,
        role: MachineRole,
    ) -> Result<FoldedMachine> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let folded = self.enroll_machine_in_txn(&mut txn, issuer, owner.actor(), request, role)?;
        txn.commit()?;
        Ok(folded)
    }

    /// The owner changes a machine's answer or removes it. Removal is terminal.
    pub fn set_machine_role(
        &self,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        machine: EntityId,
        role: MachineRole,
    ) -> Result<FoldedMachine> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let current = fold
            .machine(machine)
            .filter(|folded| !folded.removed)
            .ok_or_else(invalid_authority)?;
        let profile = MachineProfile {
            owner: owner.actor(),
            role,
            revision: current
                .profile
                .revision
                .checked_add(1)
                .ok_or_else(invalid_authority)?,
            ..current.profile.clone()
        };
        let folded = self.append_machine_profile_in_txn(&mut txn, issuer, &fold, profile)?;
        txn.commit()?;
        Ok(folded)
    }

    /// Enrols in the caller's transaction; the caller has checked `owner`.
    pub(super) fn enroll_machine_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        owner: EntityId,
        request: &MachineEnrolmentRequest,
        role: MachineRole,
    ) -> Result<FoldedMachine> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        // A machine joins once. A later answer changes its role through
        // `set_machine_role`; nothing that joins replaces its key.
        if role == MachineRole::Removed
            || fold.vault_id != Some(request.vault_id)
            || fold.machine(request.machine).is_some()
        {
            return Err(invalid_authority());
        }
        self.ensure_machine_row_in_txn(txn, request.machine)?;
        let profile = MachineProfile {
            machine: request.machine,
            owner,
            machine_key: request.machine_key,
            encryption_key: request.encryption_key.clone(),
            role,
            revision: 1,
            machine_proof: request.machine_proof,
        };
        self.append_machine_profile_in_txn(txn, issuer, &fold, profile)
    }

    fn append_machine_profile_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        fold: &AuthorityFold,
        profile: MachineProfile,
    ) -> Result<FoldedMachine> {
        profile.validate()?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = next_entry(
            issuer,
            fold,
            AuthorityOp::MachineProfile(profile.clone()),
            now,
        )?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        // The fold is the judge: a profile it refused never reports success.
        let removal = profile.role == MachineRole::Removed;
        self.authority_view_readonly_in_txn(txn)?
            .machine(profile.machine)
            .filter(|folded| folded.profile == profile && (folded.is_live() || removal))
            .cloned()
            .ok_or_else(invalid_authority)
    }

    /// A live MACHINE row, created empty when absent. Never another kind, and
    /// never a deleted, archived or stale row.
    fn ensure_machine_row_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        machine: EntityId,
    ) -> Result<()> {
        let visibility = TombstoneStoreRead::port_deletion_state(&self.store, txn, &machine)?;
        if visibility.deleted || visibility.archived || visibility.stale {
            return Err(invalid_authority());
        }
        if let Some(existing) = EntityStoreRead::port_entity_record(&self.store, txn, &machine)? {
            return if existing.entity_type == ENTITY_TYPE_MACHINE {
                Ok(())
            } else {
                Err(invalid_authority())
            };
        }
        let now = self.instant_in_txn(txn)?.secs();
        EntityStore::port_entity_put(
            self,
            txn,
            &machine,
            &EntityRecord {
                entity_type: ENTITY_TYPE_MACHINE,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                body: EMPTY_MACHINE_BODY.to_vec(),
            },
        )
    }

    /// The client half: this install's proof for one request, or `None` when
    /// it is not a machine of this vault yet. Sending it is harmless before
    /// the profile syncs; the receiver decides.
    pub fn machine_connection_proof(
        &self,
        token: &str,
        timestamp: u64,
        nonce: &str,
    ) -> Result<Option<(EntityId, [u8; 64])>> {
        let txn = self.store.env.read_txn()?;
        let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let Some(key) = crate::identity::read_machine_signing_key_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let Some(vault_id) = self.authority_view_readonly_in_txn(&txn)?.vault_id else {
            return Ok(None);
        };
        let transcript = machine_connection_transcript(&vault_id, machine, token, timestamp, nonce);
        Ok(Some((machine, key.sign(&transcript).to_bytes())))
    }

    /// The server half: the machine one request's proof names. Anything that
    /// does not verify against a live profile is `Unknown`, never an error, so
    /// a machine whose profile has not synced here yet can still sync.
    pub fn verify_machine_connection_proof(
        &self,
        machine: EntityId,
        signature: &[u8; 64],
        token: &str,
        timestamp: u64,
        nonce: &str,
    ) -> Result<PeerMachine> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let (Some(vault_id), Some(folded)) = (
            fold.vault_id,
            fold.machine(machine).filter(|folded| folded.is_live()),
        ) else {
            return Ok(PeerMachine::Unknown);
        };
        let Ok(key) = VerifyingKey::from_bytes(&folded.profile.machine_key) else {
            return Ok(PeerMachine::Unknown);
        };
        let transcript = machine_connection_transcript(&vault_id, machine, token, timestamp, nonce);
        Ok(
            if key
                .verify_strict(&transcript, &Signature::from_bytes(signature))
                .is_ok()
            {
                PeerMachine::Proven(machine)
            } else {
                PeerMachine::Unknown
            },
        )
    }
}
