//! The protected input of an active custody change (WILL L04 row 04): what a
//! register or rotate hands its holder, sealed to the holder's encryption
//! key alone.
//!
//! A register's input is the whole record, metadata and value; a rotate's is
//! the new value. The envelope's key id binds the vault, the secret's id, the
//! change, the generation it approves, the custody revision the owner saw,
//! the holder and every permit, so an input never opens as another change's.
//! The request names only the digest of its ciphertext, never a hash of the
//! value. A door that is the holder executes from what it holds in the
//! request's own commit and keeps no input; any other door keeps the input
//! to relay beside the custody transitions, under its digest, with the
//! request it is for, until the holder answers (`crate::sync::custody`). A
//! surface that seals the input itself hands the console no plaintext; an
//! upload of the raw value to the holder stays an explicit choice.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, OpenKey, OpenPolicy, Purpose, SealKey, SealParams,
    SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use crate::authority::{AuthorityEntryHash, CustodyChange, CustodyRecipientPermit, WrapRecipient};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::Vault;
use crate::store::Store;
use crate::world_keys::MachineSecret;

const INPUT_LABEL: &[u8] = b"oneiron/custody-input/v1";
const KEY_ID_LABEL: &[u8] = b"custody-input/v1";
const BINDING_DOMAIN: &[u8] = b"oneiron/custody-input-binding/v1";
const DIGEST_DOMAIN: &[u8] = b"oneiron/custody-input-digest/v1";
const EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The largest input envelope a door takes or a relay carries, as for a
/// custody transition.
pub(crate) const MAX_INPUT_BYTES: usize = 4 << 20;
/// A relayed input's frame: the second it was sealed at, then the request.
const FRAME_BYTES: usize = 8 + 32;

/// Each input this vault keeps to relay, or keeps as its holder until it
/// answers, by its ciphertext digest.
const INPUTS: SideTable<[u8; 32], Vec<u8>, Raw> = SideTable::new(&side_table::SECRET_CUSTODY_INPUT);

/// What one input binds: every field of the request it is for but the
/// request's own hash, which it precedes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InputBinding<'a> {
    pub(crate) vault_id: [u8; 32],
    pub(crate) id: EntityId,
    pub(crate) change: CustodyChange,
    pub(crate) generation: u32,
    pub(crate) seen: [u8; 32],
    pub(crate) holder: EntityId,
    pub(crate) permits: &'a [CustodyRecipientPermit],
}

impl InputBinding<'_> {
    /// The envelope key id: a label, then a digest of every bound field,
    /// within the envelope's 64-byte id.
    fn key_id(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BINDING_DOMAIN);
        hasher.update(&self.vault_id);
        hasher.update(self.id.as_bytes());
        hasher.update(self.change.as_str().as_bytes());
        hasher.update(&[0]);
        hasher.update(&self.generation.to_be_bytes());
        hasher.update(&self.seen);
        hasher.update(self.holder.as_bytes());
        hasher.update(&(self.permits.len() as u32).to_be_bytes());
        for permit in self.permits {
            hasher.update(permit.machine.as_bytes());
            hasher.update(&permit.profile);
            hasher.update(&permit.encryption_key);
        }
        let mut out = Vec::with_capacity(KEY_ID_LABEL.len() + 32);
        out.extend_from_slice(KEY_ID_LABEL);
        out.extend_from_slice(hasher.finalize().as_bytes());
        out
    }

    /// Seals `body` to the holder's `key` under this binding: the input's
    /// envelope bytes.
    pub(crate) fn seal(&self, key: &HybridPublicKey, body: &[u8]) -> Result<Vec<u8>> {
        let key_id = self.key_id();
        let recipient = WrapRecipient::Machine(self.holder).envelope_recipient();
        let mut payload = Zeroizing::new(Vec::with_capacity(INPUT_LABEL.len() + body.len()));
        payload.extend_from_slice(INPUT_LABEL);
        payload.extend_from_slice(body);
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::SecretFile,
            epoch: EPOCH,
            key_id: &key_id,
            recipient: &recipient,
            vault_id: &self.vault_id,
        };
        let envelope = seal(
            &params,
            SealKey::Hybrid {
                recipient: key,
                kem_suite: KEM,
            },
            &payload,
            &mut SysRng,
        )
        .map(|envelope| envelope.to_bytes())
        .map_err(|_| refused("sealing the custody input to its holder failed"))?;
        if envelope.len() > MAX_INPUT_BYTES {
            return Err(refused(
                "the custody input is larger than one custody transition carries",
            ));
        }
        Ok(envelope)
    }

    /// The body `envelope` holds, opened with the holder's `secret` under
    /// this binding. `None` when `secret` is not the holder's, or the
    /// envelope was sealed to another key or under another binding.
    pub(crate) fn open(
        &self,
        envelope: &[u8],
        secret: &MachineSecret,
    ) -> Option<Zeroizing<Vec<u8>>> {
        if secret.machine != self.holder || envelope.len() > MAX_INPUT_BYTES {
            return None;
        }
        let envelope = Envelope::parse(envelope).ok()?;
        let key_id = self.key_id();
        let recipient = WrapRecipient::Machine(self.holder).envelope_recipient();
        let policy = OpenPolicy {
            purpose: Purpose::SecretFile,
            vault_id: &self.vault_id,
            recipient: &recipient,
            key_id: &key_id,
            wraps: &[WrapType::HybridCapsule],
            aead_suites: &[AEAD],
            kem_suites: &[KEM],
            min_epoch: EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let payload = envelope.open(OpenKey::Hybrid(&secret.secret), &policy).ok()?;
        let body = payload.strip_prefix(INPUT_LABEL)?;
        Some(Zeroizing::new(body.to_vec()))
    }
}

/// The digest a request names of its input: over the ciphertext alone, so
/// it says nothing of the value.
pub(crate) fn input_digest(envelope: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(envelope);
    *hasher.finalize().as_bytes()
}

/// One input as it is kept and relayed: the second it was sealed at, whose
/// month's base window carries it, the request it is for and its envelope.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RelayedInput {
    pub(crate) sealed_at: u64,
    pub(crate) request: AuthorityEntryHash,
    pub(crate) envelope: Vec<u8>,
}

// Never print the ciphertext.
impl std::fmt::Debug for RelayedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayedInput")
            .field("sealed_at", &self.sealed_at)
            .field("bytes", &self.envelope.len())
            .finish_non_exhaustive()
    }
}

impl RelayedInput {
    /// The frame, then the envelope.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_BYTES + self.envelope.len());
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&self.envelope);
        out
    }

    /// Decodes a kept or relayed input strictly; `None` for a short frame,
    /// an empty or oversized envelope or a zero request.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() <= FRAME_BYTES || bytes.len() > FRAME_BYTES + MAX_INPUT_BYTES {
            return None;
        }
        let (sealed_at, rest) = bytes.split_at(8);
        let (request, envelope) = rest.split_at(32);
        let request: AuthorityEntryHash = request.try_into().ok()?;
        if request == [0; 32] {
            return None;
        }
        Some(Self {
            sealed_at: u64::from_be_bytes(sealed_at.try_into().ok()?),
            request,
            envelope: envelope.to_vec(),
        })
    }

    /// The digest the request names.
    pub(crate) fn digest(&self) -> [u8; 32] {
        input_digest(&self.envelope)
    }
}

/// Keeps `input` under its digest in `wtxn`.
pub(crate) fn keep_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: &RelayedInput,
) -> Result<()> {
    INPUTS.put(&vault.store, wtxn, &input.digest(), &input.encode())
}

/// The input kept under `digest`, when it decodes.
pub(crate) fn held_input_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<RelayedInput>> {
    Ok(INPUTS
        .get(store, txn, digest)?
        .and_then(|bytes| RelayedInput::decode(&bytes)))
}

/// Forgets the input kept under `digest`.
pub(crate) fn drop_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    INPUTS.delete(&vault.store, wtxn, digest).map(drop)
}

/// Every input this vault keeps, by digest, as stored.
pub(crate) fn held_inputs(vault: &Vault) -> Result<Vec<([u8; 32], Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    INPUTS.scan(&vault.store, &rtxn)
}

impl Vault {
    /// Forgets every kept input whose request is answered, or that this
    /// install folds as no admitted request at all: what remains is the
    /// relay of work still awaiting its holder. The owner work drain runs it
    /// beside the revoke settle. Returns how many it forgot.
    pub(crate) fn settle_custody_inputs(&self) -> Result<usize> {
        let done: Vec<[u8; 32]> = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            INPUTS
                .scan(&self.store, &txn)?
                .into_iter()
                .filter(|(_, bytes)| {
                    RelayedInput::decode(bytes).is_none_or(|input| {
                        fold.owner_work_result(&input.request).is_some()
                            || fold.owner_work_request(&input.request).is_none()
                    })
                })
                .map(|(digest, _)| digest)
                .collect()
        };
        if done.is_empty() {
            return Ok(0);
        }
        self.with_write_txn(|txn| {
            for digest in &done {
                drop_input_in_txn(self, txn, digest)?;
            }
            Ok(done.len())
        })
    }
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("{reason}; nothing was written"))
}
