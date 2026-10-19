//! A physical machine's identity: this install's own machine, the owner's
//! enrolment door, and the proof a connection carries.
//!
//! Three identities stay apart. The MACHINE row an install is (its id lives
//! with its own machine key, `identity.rs`); the engine's writer actors, which
//! are MACHINE rows bound as `system` actors and never get a profile; and the
//! Loro client id, a CRDT peer id that names no machine.

use ed25519_dalek::{Signature, Signer, VerifyingKey};

use crate::error::Result;
use crate::ports::{EntityRecord, EntityStore, EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::{EntityId, TimeRange, Vault};

use super::*;

const MACHINE_CONNECTION_DOMAIN: &[u8] = b"oneiron/machine-proof/v1\0";
/// The request header a machine names itself in, beside the slip proof.
pub const MACHINE_PROOF_HEADER: &str = "x-oneiron-machine";
/// An empty MessagePack map: a MACHINE row the enrolment had to create.
const EMPTY_MACHINE_BODY: &[u8] = &[0x80];
const REQUEST_CODE_CONTEXT: &str = "oneiron/machine-request-code/v1";

/// The role the install that serves a vault takes when no profile of its own
/// stands yet (FIX 4648; CALLS "selfprofile serving-install role"): a linked
/// install whose owner has not answered whose it is. It carries his acts and
/// reaches no further than an unprofiled install until he answers. Never
/// mine, and never a hosted node, which only the managed host's own node is.
pub(crate) const SERVING_INSTALL_ROLE: MachineRole = MachineRole::Unanswered;

/// Why this install's own profile does not stand after an ensure (FIX 4648):
/// each refusal's typed reason. The owner's acts then refuse "no carrier" on
/// this install, as they did before it had one.
const SERVING_PROFILE_REMOVED: &str =
    "this install's machine profile was removed; a removed machine is never enrolled again";
const SERVING_PROFILE_CONFLICTED: &str =
    "this install's machine profile is conflicted; nothing is enrolled over it";
const SERVING_PROFILE_KEY_MISMATCH: &str =
    "this install's machine profile names other keys; its keys are never replaced";
const SERVING_PROFILE_NOT_LIVE: &str = "this install's machine profile does not stand here \
     (stale, held or unsettled); nothing is enrolled over it";
/// FIX 3835: a standing profile whose class its host no longer declares
/// stands as enrolled; a start never rewrites it on config alone
/// (MACHINE_CLASS_REVISION).
const SERVING_PROFILE_CLASS_DIFFERS: &str = "this install's machine profile names another class \
     than its host declares; it stands as enrolled until the owner approves this install's \
     class-only revision through the enrolment door";
const SERVING_ROOT_ABSENT: &str =
    "the vault has no root yet; its first rooted serving start profiles this install";
const SERVING_ROOT_CONFLICTED: &str =
    "the vault's root is conflicted; this install is profiled once it settles";
pub(super) const SERVING_ROOT_NOT_ISSUER: &str =
    "this start's host root issuer is not the vault's live root; no root is minted for it";
const SERVING_NO_OWNER: &str = "the vault names no owner to profile this install for";
pub(super) const SERVING_NO_ISSUER: &str =
    "no host root issuer on this start; this install stays unprofiled";

/// What a machine sends to join a vault: its row, its class, its keys, and
/// its own signature over them for that vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineEnrolmentRequest {
    pub vault_id: [u8; 32],
    pub machine: EntityId,
    pub machine_key: [u8; 32],
    /// The class this machine's host declares (`VaultConfig::machine_device_class`).
    /// The owner approves it by approving the request.
    pub device_class: MachineDeviceClass,
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
    /// vault_id ‖ machine ‖ machine_key ‖ class name ‖ 0 ‖ suite (u16 BE) ‖ key
    /// length (u32 BE) ‖ key ‖ machine_proof)`.
    #[must_use]
    pub fn code(&self) -> RequestCode {
        let key = &self.encryption_key.key;
        let mut hasher = blake3::Hasher::new_derive_key(REQUEST_CODE_CONTEXT);
        hasher.update(&self.vault_id);
        hasher.update(self.machine.as_bytes());
        hasher.update(&self.machine_key);
        hasher.update(self.device_class.wire().as_bytes());
        hasher.update(&[0]);
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

/// The vault id this install's resident signed Genesis roots (its hash, as
/// the fold derives it), read without folding the log (OF-469). Only a
/// well-formed Genesis its own device key signed at seq 0 counts, as in the
/// fold; none resident is `None`, and more than one refuses. Never the
/// store's own id, a checkpoint's asserted id or another entry's `vault_id`.
///
/// On a vault that adopted a checkpoint image, the genesis its adopted,
/// verified pin names is a root as well (OF-469, slice E): with no resident
/// Genesis it is the vault's, and a resident one that differs refuses as a
/// second root does. An image this vault has not adopted never names one,
/// and an adoption that no longer verifies is an error (CALLS: OF-469 slice
/// E adopted genesis).
pub(super) fn resident_genesis_vault_id_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<AuthorityVaultId>> {
    let mut roots = std::collections::BTreeSet::new();
    for (_, bytes) in authority_log_rows_in_txn(store, txn)? {
        let entry = decode_authority_log_entry_body(&bytes)?;
        let AuthorityOp::Genesis { device, .. } = &entry.op else {
            continue;
        };
        if entry.validate_shape().is_err()
            || verify_entry_signatures(&entry).is_err()
            || *entry.signer_key() != device.key
            || entry.seq != 0
        {
            continue;
        }
        if let Ok(root) = genesis_vault_id(&entry) {
            roots.insert(root);
        }
    }
    if let Some(adopted) = super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(store, txn)?
    {
        roots.insert(adopted.pin().genesis);
    }
    if roots.len() > 1 {
        return Err(invalid_authority());
    }
    Ok(roots.pop_first())
}

/// Whether this install's own profile already stands as a carrier: the one
/// carrier rule admits its install key, and a live chain names both its keys.
/// The full predicate the owner-act writers ask, not the roster head alone.
pub(super) fn serving_profile_stands(
    fold: &AuthorityFold,
    folded: &FoldedMachine,
    request: &MachineEnrolmentRequest,
) -> bool {
    owner_act_signer_admits(Some(folded), &fold.roster, &request.machine_key)
        && folded.chains().any(|(_, chain)| {
            chain.is_live()
                && chain.profile.machine_key == request.machine_key
                && chain.profile.encryption_key == request.encryption_key
        })
}

impl Vault {
    /// This install's own MACHINE id while a profile of it names this
    /// install's machine key, in any role and any standing (FIX 4728): the
    /// one machine row an authority-preserving restore keeps live. Read in
    /// `txn`'s snapshot alone: nothing is minted, loaded or ensured, and no
    /// role selects it. `None` with no machine id, no signer loaded for it,
    /// no profile of it naming that key, or a fold this snapshot cannot
    /// answer: the restore then judges the row as it did before.
    pub(crate) fn serving_machine_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<Option<EntityId>> {
        let Some(machine) = crate::identity::read_machine_id_in_txn(self, txn)? else {
            return Ok(None);
        };
        let Some(signer) = self
            .loaded_install_signer()
            .filter(|signer| signer.machine == machine)
        else {
            return Ok(None);
        };
        let key = signer.machine_key.verifying_key().to_bytes();
        let Ok(fold) = self.authority_view_readonly_in_txn(txn) else {
            return Ok(None);
        };
        Ok(fold
            .machine(machine)
            .is_some_and(|folded| folded.names_key(&key))
            .then_some(machine))
    }
}

/// Whether a live chain of this install's standing profile names another
/// class than the one its host declares now (FIX 3835).
fn serving_class_differs(folded: &FoldedMachine, request: &MachineEnrolmentRequest) -> bool {
    folded.chains().any(|(_, chain)| {
        chain.is_live()
            && chain.profile.machine_key == request.machine_key
            && chain.profile.device_class != request.device_class
    })
}

/// Why a profile under this install's id that does not stand is never
/// enrolled over: the first of removed, conflicted, other keys and not live.
fn serving_profile_refusal(
    folded: &FoldedMachine,
    request: &MachineEnrolmentRequest,
) -> &'static str {
    let chains = move || folded.chains().map(|(_, chain)| chain);
    if chains().any(|chain| chain.removed) {
        SERVING_PROFILE_REMOVED
    } else if chains().any(|chain| chain.conflicted) {
        SERVING_PROFILE_CONFLICTED
    } else if chains().any(|chain| {
        chain.profile.machine_key != request.machine_key
            || chain.profile.encryption_key != request.encryption_key
    }) {
        SERVING_PROFILE_KEY_MISMATCH
    } else {
        SERVING_PROFILE_NOT_LIVE
    }
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
        self.load_install_signing_if_minted()?;
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
    /// machine id, loads its machine key from the keystore, and signs its identity
    /// for `vault_id` with that key. The identity carries the class this host
    /// declares in its config (`VaultConfig::machine_device_class`).
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
            let (machine, key) = crate::identity::machine_signer_in_txn(self, wtxn)?;
            if machine != derived_under {
                return Err(crate::world_keys::refused(
                    "the machine identity changed after its encryption key was read",
                ));
            }
            let machine_key = key.verifying_key().to_bytes();
            let device_class = self.config.machine_device_class;
            let machine_proof = key
                .sign(&machine_profile_proof_transcript(
                    &vault_id,
                    machine,
                    &machine_key,
                    device_class,
                    &encryption_key,
                ))
                .to_bytes();
            request = Some(MachineEnrolmentRequest {
                vault_id,
                machine,
                machine_key,
                device_class,
                encryption_key: encryption_key.clone(),
                machine_proof,
            });
            Ok(())
        })?;
        Ok(request.expect("closure ran on Ok"))
    }

    /// Seals the portable credentials again for the roster a committed
    /// machine admission changed (FIX 1780), outside its writer. The
    /// admission stands whatever happens here: a failure is returned as a
    /// re-seal after a committed admission, never a rollback. A sync lane's
    /// upkeep re-seal runs again later; nothing else retries it.
    ///
    /// First it queues the admitted machine for the home, for an old reader
    /// to grant it each kept sealed pad object (FIX 4271). A queue that fails
    /// is logged, never returned: the machine's own sweep asks again.
    #[cfg(feature = "sync")]
    pub(super) fn reseal_after_machine_admission(&self) -> Result<()> {
        if let Err(error) = self.queue_sealed_bundle_pad_admissions() {
            tracing::warn!(
                error = %error,
                "queueing a machine admission for sealed pad access failed; its sweep asks again"
            );
        }
        self.reseal_custody_for_roster().map(drop).map_err(|error| {
            crate::error::Error::sync_engine(
                crate::error::SyncEngineContext::CustodyResealAfterMachineAdmission,
                error,
            )
        })
    }

    /// The host's own node: [`Self::ensure_serving_install_profile`] as a
    /// `HostedNode`, the managed host's truth. The node is never mine and
    /// never a wrap recipient.
    pub fn provision_host_node(&self, issuer: &HostSlipIssuer) -> Result<FoldedMachine> {
        self.ensure_serving_install_profile(issuer, MachineRole::HostedNode)
    }

    /// This install's own machine in the roster, so it carries the owner's
    /// acts from its first start (FIX 4648): signed by the host root, which
    /// may register an install but never vouch for one as the owner's, on
    /// the explicit bootstrap arm with no owner act (C4), after which the
    /// install carries the owner's answers like any linked machine. Its
    /// profile names the machine and its keys so the carrier rule
    /// ([`owner_act_signer_admits`]) admits its install key, and the vault's
    /// owner PERSON, since no owner answered here. There is no new record
    /// kind and no root-key exception: the root signs the enrolment, never
    /// an act.
    ///
    /// A no-op when a live profile of this install already names both its
    /// keys and the carrier rule admits its install key, in any role: no
    /// revision moves and the owner's answers stand. A class its host no
    /// longer declares is compared and logged there, never rewritten: the
    /// owner's enrolment door takes its class-only revision (FIX 3835,
    /// [`Self::enroll_machine`]). Otherwise a profile under this install's
    /// id refuses, naming why (removed, conflicted, other keys, not live
    /// here): its keys are never replaced and a removed machine never comes
    /// back. With none, the bootstrap arm enrols it in `role`. The vault must
    /// already be rooted under `issuer`; no root is minted here.
    pub fn ensure_serving_install_profile(
        &self,
        issuer: &HostSlipIssuer,
        role: MachineRole,
    ) -> Result<FoldedMachine> {
        self.ensure_install_profile_reporting(issuer, role)
            .map(|(folded, _)| folded)
    }

    /// [`Self::ensure_serving_install_profile`], and what it did: `None` when
    /// it enrolled the install. `Some` is the no-op over a profile that
    /// already stands, carrying whether `issuer` is this vault's settled live
    /// root, read by `require_host` in the same snapshot before that return
    /// (FIX 4730). A `false` there is reported, never refused, and nothing is
    /// written with that issuer (Engine 10-19 15:3x).
    pub(super) fn ensure_install_profile_reporting(
        &self,
        issuer: &HostSlipIssuer,
        role: MachineRole,
    ) -> Result<(FoldedMachine, Option<bool>)> {
        let vault_id = self
            .authority_fold()?
            .vault_id
            .ok_or_else(|| authority_refused(SERVING_ROOT_ABSENT))?;
        // The install's identity, minted and signed outside the writer.
        let encryption_key = self.machine_encryption_key(vault_id)?;
        let request = self.machine_enrolment_request(vault_id, encryption_key)?;
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if let Some(folded) = fold.machine(request.machine) {
            return if serving_profile_stands(&fold, folded, &request) {
                let issuer_is_root = super::slip_vault::require_host(&fold, issuer).is_ok();
                if serving_class_differs(folded, &request) {
                    tracing::warn!(
                        declared = request.device_class.wire(),
                        reason = SERVING_PROFILE_CLASS_DIFFERS,
                        "this install's machine profile stands as enrolled"
                    );
                }
                Ok((folded.clone(), Some(issuer_is_root)))
            } else {
                Err(authority_refused(serving_profile_refusal(folded, &request)))
            };
        }
        if fold.vault_root_is_conflicted() {
            return Err(authority_refused(SERVING_ROOT_CONFLICTED));
        }
        super::slip_vault::require_host(&fold, issuer)
            .map_err(|_| authority_refused(SERVING_ROOT_NOT_ISSUER))?;
        let owner = crate::policy_model::owners_in_txn(self, &txn)?
            .first()
            .copied()
            .ok_or_else(|| authority_refused(SERVING_NO_OWNER))?;
        let folded = self.enroll_bootstrap_in_txn(&mut txn, issuer, owner, &request, role)?;
        txn.commit()?;
        Ok((folded, None))
    }

    /// [`Self::ensure_serving_install_profile`] in [`SERVING_INSTALL_ROLE`]
    /// at a start that goes on whatever it says: every start that works
    /// without a profile still starts (FIX 4648). A skip or a refusal is
    /// logged with its reason, and the owner's acts then refuse "no carrier"
    /// here, as before. No issuer, or a vault no root roots yet, is a skip:
    /// the first rooted serving start profiles the install, and nothing here
    /// mints a root. A start whose issuer is not the vault's settled root,
    /// over a profile that already stands, is logged as a warning and starts
    /// on under the settled root, never refused (FIX 5345, Engine 10-19
    /// 15:3x). `start` names the start in the log.
    pub fn ensure_serving_install_profile_at_start(
        &self,
        issuer: Option<&HostSlipIssuer>,
        start: &'static str,
    ) {
        let Some(issuer) = issuer else {
            tracing::debug!(
                start,
                reason = SERVING_NO_ISSUER,
                "no machine profile ensured"
            );
            return;
        };
        match self.ensure_install_profile_reporting(issuer, SERVING_INSTALL_ROLE) {
            // FIX 5345: the wrong-root fact the profile door reports is kept,
            // not dropped; the standing profile carries on as before.
            Ok((_, Some(false))) => tracing::warn!(
                start,
                reason = SERVING_ROOT_NOT_ISSUER,
                "this start's host root is not the vault's settled root, so it went unused; \
                 this install's standing profile carries on under the settled root"
            ),
            Ok(_) => {}
            Err(crate::error::Error::Record(crate::error::RecordError::AuthorityRefused(
                SERVING_ROOT_ABSENT,
            ))) => {
                tracing::debug!(
                    start,
                    reason = SERVING_ROOT_ABSENT,
                    "no machine profile ensured"
                );
            }
            Err(error) => tracing::warn!(
                start,
                kind = ?error.kind(),
                reason = %error,
                "this install has no live machine profile, so the owner's acts refuse \
                 \"no carrier\" here until one stands; starting on"
            ),
        }
    }

    /// A live MACHINE row, created empty when absent. Never another kind, and
    /// never a deleted, archived or stale row.
    pub(super) fn ensure_machine_row_in_txn(
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
    /// the profile syncs; the receiver decides. It signs for the vault this
    /// install's fold names, or, while that fold cannot answer (its history
    /// is incomplete, OF-469), for the vault its own resident Genesis or its
    /// adopted pin's genesis roots (`resident_genesis_vault_id_in_txn`): a
    /// machine missing history
    /// still proves itself to its home for the tail, and claims nothing here.
    pub fn machine_connection_proof(
        &self,
        token: &str,
        timestamp: u64,
        nonce: &str,
    ) -> Result<Option<(EntityId, [u8; 64])>> {
        self.load_install_signing_if_minted()?;
        let txn = self.store.env.read_txn()?;
        let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let Some(key) = crate::identity::read_machine_signing_key_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let vault_id = match self.authority_view_readonly_in_txn(&txn) {
            Ok(view) => view.vault_id,
            Err(_) => resident_genesis_vault_id_in_txn(&self.store, &txn)?,
        };
        let Some(vault_id) = vault_id else {
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
