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
const REQUEST_CODE_CONTEXT: &str = "oneiron/machine-request-code/v1";

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

/// What a new machine shows the owner, as a QR code or 26 base32 characters,
/// for the owner to scan or type on the machine that approves its request. It
/// commits to every field of the request, so a host that relays the request
/// cannot swap in its own with the same code: at 128 bits it cannot grind one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestCode(pub [u8; 16]);

impl MachineEnrolmentRequest {
    /// The first 16 bytes of `BLAKE3-derive_key("oneiron/machine-request-code/v1",
    /// vault_id ‖ machine ‖ machine_key ‖ suite (u16 BE) ‖ key length (u32 BE) ‖ key
    /// ‖ machine_proof)`.
    #[must_use]
    pub fn code(&self) -> RequestCode {
        let key = &self.encryption_key.key;
        let mut hasher = blake3::Hasher::new_derive_key(REQUEST_CODE_CONTEXT);
        hasher.update(&self.vault_id);
        hasher.update(self.machine.as_bytes());
        hasher.update(&self.machine_key);
        hasher.update(&self.encryption_key.suite.to_be_bytes());
        hasher.update(&u32::try_from(key.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(key);
        hasher.update(&self.machine_proof);
        let mut code = [0; 16];
        code.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        RequestCode(code)
    }
}

/// This install's machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMachine {
    pub id: EntityId,
    /// Every admitter's chain for this row, once one of them names this
    /// install's key.
    pub profile: Option<FoldedMachine>,
    /// Mine under this install's pin, through a trusted identity that names
    /// this install's key. A chain that clones the row with other keys never
    /// makes it so.
    pub mine: bool,
}

/// The machine at the other end of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMachine {
    /// A machine that proved, on this connection, the key it stands on here
    /// ([`AuthorityFold::machine_proof_key`]). The key stays with the proof:
    /// a later trusted identity under other keys is not this connection's.
    Proven { machine: EntityId, key: [u8; 32] },
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
            .filter(|machine| key.is_some_and(|key| machine.names_key(&key)))
            .cloned();
        let mine = fold
            .trusted_machine(id)
            .is_some_and(|trusted| key == Some(trusted.profile.machine_key));
        Ok(Some(LocalMachine { id, profile, mine }))
    }

    /// Called on the machine that joins: mints (once) and keeps this install's
    /// machine id and key, and signs its identity for `vault_id` with that key.
    /// `encryption_key` must be this install's own for `vault_id`
    /// ([`Vault::machine_encryption_key`]), derived under the machine id the request
    /// signs: a key from another slot, or one taken before the id changed, is refused.
    pub fn machine_enrolment_request(
        &self,
        vault_id: [u8; 32],
        encryption_key: MachineEncryptionKey,
    ) -> Result<MachineEnrolmentRequest> {
        encryption_key.validate()?;
        let (derived_under, own_key) = self.machine_encryption_key_with_id(vault_id)?;
        if encryption_key != own_key {
            return Err(crate::world_keys::refused(
                "the encryption key is not this install's own for this vault",
            ));
        }
        let mut request = None;
        self.with_write_txn_grouped(|wtxn| {
            let (machine, key) = crate::identity::load_or_mint_machine_in_txn(self, wtxn)?;
            if machine != derived_under {
                return Err(crate::world_keys::refused(
                    "the machine identity changed after its encryption key was read",
                ));
            }
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

    /// The owner changes a machine's answer or removes it, in the roster's
    /// chain. Removal is terminal there. An anchor's chain is the anchor's.
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
            .and_then(|folded| folded.roster.as_ref())
            .filter(|roster| !roster.removed)
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
        // A machine joins the roster's chain once. A later answer changes its
        // role through `set_machine_role`; nothing that joins replaces its key.
        if role == MachineRole::Removed
            || fold.vault_id != Some(request.vault_id)
            || fold
                .machine(request.machine)
                .is_some_and(|folded| folded.roster.is_some())
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

    /// Signs every live roster standing again under `next`, in the caller's
    /// transaction. A re-root revokes every roster key, and a standing that
    /// rests on a revoked key goes stale. An anchor's chain rests on no
    /// roster key and is not the roster's to carry.
    pub(super) fn carry_machine_standing_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        before: &AuthorityFold,
        next: &HostSlipIssuer,
    ) -> Result<usize> {
        let mut carried = 0;
        for machine in before
            .machines
            .iter()
            .filter(|(_, folded)| folded.roster.as_ref().is_some_and(MachineRevision::is_live))
            .map(|(machine, _)| *machine)
        {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let current = fold
                .machine(machine)
                .and_then(|folded| folded.roster.as_ref())
                .ok_or_else(invalid_authority)?;
            let profile = MachineProfile {
                revision: current
                    .profile
                    .revision
                    .checked_add(1)
                    .ok_or_else(invalid_authority)?,
                ..current.profile.clone()
            };
            self.append_machine_profile_in_txn(txn, next, &fold, profile)?;
            carried += 1;
        }
        Ok(carried)
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
            .filter(|folded| {
                folded.roster.as_ref().is_some_and(|roster| {
                    roster.profile == profile && (roster.is_live() || removal)
                })
            })
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
    /// does not verify under the key the machine stands on here is `Unknown`,
    /// never an error, so a machine whose profile has not synced here yet can
    /// still sync. A key only an untrusted chain names never proves it.
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
        let (Some(vault_id), Some(machine_key)) = (fold.vault_id, fold.machine_proof_key(machine))
        else {
            return Ok(PeerMachine::Unknown);
        };
        let Ok(key) = VerifyingKey::from_bytes(&machine_key) else {
            return Ok(PeerMachine::Unknown);
        };
        let transcript = machine_connection_transcript(&vault_id, machine, token, timestamp, nonce);
        Ok(
            if key
                .verify_strict(&transcript, &Signature::from_bytes(signature))
                .is_ok()
            {
                PeerMachine::Proven {
                    machine,
                    key: machine_key,
                }
            } else {
                PeerMachine::Unknown
            },
        )
    }

    /// A machine one connection proved earlier, while it still stands here
    /// on the key it proved. A socket outlives its proof: a machine removed,
    /// poisoned, gone stale or trusted under other keys since is `Unknown`,
    /// as is one the fold cannot be read for.
    #[must_use]
    pub fn peer_machine_stands(&self, peer: PeerMachine) -> PeerMachine {
        match peer {
            PeerMachine::Proven { machine, key }
                if self
                    .authority_fold()
                    .is_ok_and(|fold| fold.machine_proof_key(machine) == Some(key)) =>
            {
                peer
            }
            _ => PeerMachine::Unknown,
        }
    }
}
