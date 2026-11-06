//! The live delivery of a carrier's key (KS-6, FIX 7402 and 11785; Engine
//! 10-30 ruling A): the L02 halves of the ask and the answer an L03 sync
//! frame carries between live sockets, sealed to the asker's machine key and
//! bound to the ask's id, its asker and a short expiry.
//!
//! An install that must open a carrier sealed under a key it does not hold
//! (an executor's request input, a recipient's transition) asks the install
//! that holds it: `Vault::pending_leaf_key_requests`, each ask signed by
//! its install key and naming the encryption key the answer seals to. The
//! holder answers (`Vault::answer_leaf_key_request`) only on the ask's own
//! signature, never on the socket it came by, and only to the exact current
//! request's executor or one of its recipient permits
//! (`carrier_release_admits`); the asker takes the answer
//! (`Vault::accept_leaf_key_answer`) into memory alone, never a row, an
//! image or a log, and its pending work opens on its next run. Windows,
//! custody heads and the authority log all retain what they carry, so none
//! of them ever carries the key or a permanent key's wrap of it; the home
//! relays both in memory between live sockets. A dead socket or a passed
//! expiry is a named failure ([`LeafKeyFailureCause`]), never a store and
//! forward. Nothing here runs while `CUSTODY_CARRIER_LEAF_WIRE` is off.
//!
//! The asks an install has out live in memory beside the keys it was
//! answered: each is sent again, same id and signature, on every live tick
//! until it is answered or expires, then a fresh one is minted. A key goes
//! from memory once no work here needs it.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, OpenKey, OpenPolicy, Purpose, SealKey, SealParams,
    SuiteId, WrapType, seal,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::carrier_custody::{CARRIER_REF_BYTES, CarrierRef};
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, FoldedMachine, WrapRecipient, authority_refused,
    owner_act_signer_admits,
};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::store::CredentialLeaf;
use crate::world_keys::MachineSecret;

mod doors;

/// The wire version of an ask and of its answer.
const LEAF_KEY_WIRE_VERSION: u8 = 1;
/// How long one ask stands, in milliseconds (ruling A: a short expiry, one
/// policy value). The relay drops a passed one unopened.
pub const LEAF_KEY_REQUEST_TTL_MS: u64 = 120_000;
/// How long a carrier whose holder refused the ask waits before a new one,
/// in milliseconds.
pub const LEAF_KEY_REFUSED_BACKOFF_MS: u64 = 300_000;

const REQUEST_DOMAIN: &[u8] = b"oneiron/custody-leaf-key-request/v1\0";
const ANSWER_DOMAIN: &[u8] = b"oneiron/custody-leaf-key-answer/v1\0";
const SEAL_BINDING_DOMAIN: &[u8] = b"oneiron/custody-leaf-key-seal/v1\0";
const KEY_ID_LABEL: &[u8] = b"custody-leaf/v1";
const LEAF_LABEL: &[u8] = b"oneiron/custody-leaf/v1";
const EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;

/// The carrier wire is off here: no carrier needs a live key.
const REFUSED_WIRE_OFF: &str = "leaf_key_wire_off";
/// The ask or answer does not decode, or names another wire version.
const REFUSED_MALFORMED: &str = "leaf_key_malformed";
/// The ask's expiry passed.
const REFUSED_EXPIRED: &str = "leaf_key_expired";
/// The ask names another install as the key's holder.
const REFUSED_NOT_HOLDER: &str = "leaf_key_not_holder";
/// The ask, or its answer, is not its named machine's live signature.
const REFUSED_SIGNATURE: &str = "leaf_key_signature";
/// The key the answer would seal to is not the asker's live encryption key.
const REFUSED_ASKER_KEY: &str = "leaf_key_asker_key";
/// The release rule does not let the key go to the asker.
const REFUSED_NOT_ADMITTED: &str = "leaf_key_not_admitted";
/// No such carrier key is held here: unknown, retired or erased.
const REFUSED_UNKNOWN_CARRIER: &str = "leaf_key_unknown_carrier";
/// The answer is not bound to the ask it is taken for, or does not open.
const REFUSED_NOT_BOUND: &str = "leaf_key_answer_not_bound";
/// No such ask is out here: answered already, expired or never made.
const REFUSED_REPLAYED: &str = "leaf_key_replayed";

/// Why an ask came back without a key, as L03's failure frame carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeafKeyFailureCause {
    /// The holder's socket is dead or absent: the ask stays pending.
    HolderOffline,
    /// The asker's socket is dead or absent: the ask stays pending.
    ExecutorOffline,
    /// The ask's expiry passed: a fresh one is minted next.
    Expired,
    /// The relay already carried an answer for this id: a fresh one is
    /// minted next.
    Replayed,
    /// The holder refused, with its reason code: never a key or a secret.
    /// The carrier waits [`LEAF_KEY_REFUSED_BACKOFF_MS`] before a new ask.
    HolderRefused(String),
    /// The holder met a fault that is no refusal (its storage or keystore):
    /// the ask stays pending and is sent again, as for an offline holder.
    HolderFault,
}

impl LeafKeyFailureCause {
    /// The cause a holder's refusal of an ask travels as: an expired ask, a
    /// replayed one, or the refusal's own reason code. `None` for a fault
    /// that is no refusal (storage, keystore), which travels as
    /// [`Self::HolderFault`]: the asker keeps the ask pending and sends it
    /// again.
    #[must_use]
    pub fn of_refusal(error: &Error) -> Option<Self> {
        match error {
            Error::Record(RecordError::AuthorityRefused(reason)) => Some(match *reason {
                REFUSED_EXPIRED => Self::Expired,
                REFUSED_REPLAYED => Self::Replayed,
                reason => Self::HolderRefused(reason.to_owned()),
            }),
            _ => None,
        }
    }
}

/// One install's ask for a carrier key it must open with: opaque to the
/// relay, which routes it by its id, holder, asker and expiry alone.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafKeyRequest {
    version: u8,
    request_id: [u8; 32],
    /// The carrier key's reference ([`CarrierRef::encode`]).
    carrier: Vec<u8>,
    /// The custody request the carrier serves: the input's, or the one the
    /// transition enacts.
    work: AuthorityEntryHash,
    holder: EntityId,
    executor: EntityId,
    expires_at_ms: u64,
    /// The asker's live encryption key the answer seals to: its suite and
    /// public bytes.
    key_suite: u16,
    key: Vec<u8>,
    /// The asker's install key's signature over all of the above.
    signature: Vec<u8>,
}

/// The holder's answer to one ask: the carrier key sealed to the asker's
/// encryption key, signed by the holder's install key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafKeyAnswer {
    version: u8,
    request_id: [u8; 32],
    holder: EntityId,
    executor: EntityId,
    expires_at_ms: u64,
    sealed: Vec<u8>,
    signature: Vec<u8>,
}

// Never print a key, a sealed key or a signature.
impl std::fmt::Debug for LeafKeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafKeyRequest")
            .field("holder", &self.holder)
            .field("executor", &self.executor)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LeafKeyAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafKeyAnswer")
            .field("holder", &self.holder)
            .field("executor", &self.executor)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// Integers, ids and byte lists in MessagePack: never refused, so an
/// encode that fails is the empty frame, which no decode takes.
fn encode_frame<T: Serialize>(frame: &T) -> Vec<u8> {
    rmp_serde::to_vec_named(frame).unwrap_or_default()
}

/// `bytes` decoded strictly: one frame, at this wire version, that encodes
/// back to exactly `bytes`.
fn decode_frame<T>(bytes: &[u8], version: impl Fn(&T) -> u8) -> Result<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let frame: T =
        rmp_serde::from_slice(bytes).map_err(|_| authority_refused(REFUSED_MALFORMED))?;
    if version(&frame) != LEAF_KEY_WIRE_VERSION || encode_frame(&frame) != bytes {
        return Err(authority_refused(REFUSED_MALFORMED));
    }
    Ok(frame)
}

/// One digest over `fields`, each length-prefixed.
fn fields_digest(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(fields.len() as u64).to_be_bytes());
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

impl LeafKeyRequest {
    /// The ask's random id, minted with it: the relay carries one answer
    /// per id.
    #[must_use]
    pub fn request_id(&self) -> [u8; 32] {
        self.request_id
    }

    /// The install that holds the key.
    #[must_use]
    pub fn holder_machine(&self) -> EntityId {
        self.holder
    }

    /// The install that asks: an executor, or a recipient permit.
    #[must_use]
    pub fn executor_machine(&self) -> EntityId {
        self.executor
    }

    /// When the ask stops standing, unix milliseconds.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// The ask's opaque bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_frame(self)
    }

    /// An ask read back strictly. Decoding proves nothing; the holder's
    /// answer checks its signature.
    ///
    /// # Errors
    /// Bytes that are no ask at this wire version.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_frame(bytes, |request: &Self| request.version)
    }

    fn carrier_ref(&self) -> Option<CarrierRef> {
        CarrierRef::decode(&self.carrier)
    }

    /// What the asker's install key signs: the vault, then one digest over
    /// every other field.
    fn transcript(&self, vault_id: &[u8; 32]) -> Vec<u8> {
        let expires = self.expires_at_ms.to_be_bytes();
        let suite = self.key_suite.to_be_bytes();
        let digest = fields_digest(&[
            std::slice::from_ref(&self.version),
            &self.request_id[..],
            self.carrier.as_slice(),
            &self.work[..],
            &self.holder.as_bytes()[..],
            &self.executor.as_bytes()[..],
            &expires[..],
            &suite[..],
            self.key.as_slice(),
        ]);
        let mut out = REQUEST_DOMAIN.to_vec();
        out.extend_from_slice(vault_id);
        out.extend_from_slice(&digest);
        out
    }

    /// The key id the answer's envelope binds: the ask's id, asker, holder,
    /// expiry, carrier key and work.
    fn seal_key_id(&self) -> Vec<u8> {
        let expires = self.expires_at_ms.to_be_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(SEAL_BINDING_DOMAIN);
        hasher.update(&fields_digest(&[
            &self.request_id[..],
            &self.executor.as_bytes()[..],
            &self.holder.as_bytes()[..],
            &expires[..],
            self.carrier.as_slice(),
            &self.work[..],
        ]));
        let mut out = KEY_ID_LABEL.to_vec();
        out.extend_from_slice(hasher.finalize().as_bytes());
        out
    }
}

impl LeafKeyAnswer {
    /// The id of the ask it answers.
    #[must_use]
    pub fn request_id(&self) -> [u8; 32] {
        self.request_id
    }

    /// The install that holds the key.
    #[must_use]
    pub fn holder_machine(&self) -> EntityId {
        self.holder
    }

    /// The install that asked.
    #[must_use]
    pub fn executor_machine(&self) -> EntityId {
        self.executor
    }

    /// The ask's expiry, unix milliseconds.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// The answer's opaque bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_frame(self)
    }

    /// An answer read back strictly. Decoding proves nothing; the asker's
    /// accept checks it against its own ask.
    ///
    /// # Errors
    /// Bytes that are no answer at this wire version.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_frame(bytes, |answer: &Self| answer.version)
    }

    /// What the holder's install key signs: the vault, then one digest over
    /// the whole ask it answers and every field of its own.
    fn transcript(&self, vault_id: &[u8; 32], request: &LeafKeyRequest) -> Vec<u8> {
        let expires = self.expires_at_ms.to_be_bytes();
        let request = request.encode();
        let digest = fields_digest(&[
            request.as_slice(),
            std::slice::from_ref(&self.version),
            &self.request_id[..],
            &self.holder.as_bytes()[..],
            &self.executor.as_bytes()[..],
            &expires[..],
            self.sealed.as_slice(),
        ]);
        let mut out = ANSWER_DOMAIN.to_vec();
        out.extend_from_slice(vault_id);
        out.extend_from_slice(&digest);
        out
    }

    /// Whether this answers exactly `request`.
    fn answers(&self, request: &LeafKeyRequest) -> bool {
        self.version == LEAF_KEY_WIRE_VERSION
            && self.request_id == request.request_id
            && self.holder == request.holder
            && self.executor == request.executor
            && self.expires_at_ms == request.expires_at_ms
    }
}

/// One carrier this install must open without its key here: the key's
/// reference, the custody request it serves and the install that holds it.
pub(crate) struct LeafNeed {
    pub(crate) carrier: CarrierRef,
    pub(crate) work: AuthorityEntryHash,
    pub(crate) holder: EntityId,
}

/// What one vault handle keeps of live leaf delivery, in memory only: the
/// keys it was answered, its asks out and the carriers whose holder
/// refused. Never persisted, never shared across vaults, wiped with the
/// handle.
#[derive(Default)]
pub(crate) struct CustodyLeafSession {
    leaves: BTreeMap<[u8; CARRIER_REF_BYTES], CredentialLeaf>,
    asks: BTreeMap<[u8; 32], LeafKeyRequest>,
    held_back: BTreeMap<[u8; CARRIER_REF_BYTES], u64>,
}

impl CustodyLeafSession {
    /// The key of `carrier` this install was answered, if any.
    pub(crate) fn leaf(&self, carrier: &CarrierRef) -> Option<CredentialLeaf> {
        self.leaves.get(&carrier.encode()).cloned()
    }

    /// Forgets the key of `carrier` this install was answered: what it
    /// sealed is answered, replaced or gone.
    pub(crate) fn forget(&mut self, carrier: &CarrierRef) {
        self.leaves.remove(&carrier.encode());
    }

    /// Keeps only what `needs` still asks for, at `now`: each key a carrier
    /// pending here needs, each unexpired ask for one, each refusal still
    /// waiting.
    fn prune(&mut self, needs: &[LeafNeed], now: u64) {
        let needed = |carrier: &[u8], work: Option<&AuthorityEntryHash>| {
            needs.iter().any(|need| {
                need.carrier.encode().as_slice() == carrier
                    && work.is_none_or(|work| need.work == *work)
            })
        };
        self.leaves
            .retain(|carrier, _| needed(carrier.as_slice(), None));
        self.asks.retain(|_, ask| {
            ask.expires_at_ms > now && needed(ask.carrier.as_slice(), Some(&ask.work))
        });
        self.held_back.retain(|_, until| *until > now);
    }

    /// Whether `need` waits on nothing new: its key is here, its holder's
    /// refusal still waits, or an ask for it is out.
    fn covered(&self, need: &LeafNeed) -> bool {
        let carrier = need.carrier.encode();
        self.leaves.contains_key(&carrier)
            || self.held_back.contains_key(&carrier)
            || self
                .asks
                .values()
                .any(|ask| ask.carrier.as_slice() == carrier.as_slice() && ask.work == need.work)
    }
}

/// What an ask is minted with: the vault, this install and its keys.
struct Asker {
    vault_id: [u8; 32],
    machine: EntityId,
    signing: SigningKey,
    key_suite: u16,
    key: Vec<u8>,
}

impl Asker {
    /// A fresh ask for `need`, standing until `now` plus the ask's span.
    fn ask(&self, need: &LeafNeed, now: u64) -> LeafKeyRequest {
        let mut request_id = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut request_id);
        let mut request = LeafKeyRequest {
            version: LEAF_KEY_WIRE_VERSION,
            request_id,
            carrier: need.carrier.encode().to_vec(),
            work: need.work,
            holder: need.holder,
            executor: self.machine,
            expires_at_ms: now.saturating_add(LEAF_KEY_REQUEST_TTL_MS),
            key_suite: self.key_suite,
            key: self.key.clone(),
            signature: Vec::new(),
        };
        request.signature = self
            .signing
            .sign(&request.transcript(&self.vault_id))
            .to_bytes()
            .to_vec();
        request
    }
}

/// Whether `signature` over `transcript` is `machine`'s: the install key of
/// a live profile of it verifies it, and the one carrier rule admits that
/// key (any role, no chain removed, never a roster key).
fn machine_signed(
    fold: &AuthorityFold,
    machine: EntityId,
    transcript: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature);
    let folded = fold.machine(machine);
    folded
        .into_iter()
        .flat_map(FoldedMachine::chains)
        .filter(|(_, chain)| chain.is_live())
        .map(|(_, chain)| chain.profile.machine_key)
        .find(|key| {
            VerifyingKey::from_bytes(key)
                .is_ok_and(|key| key.verify_strict(transcript, &signature).is_ok())
        })
        .is_some_and(|key| owner_act_signer_admits(folded, &fold.roster, &key))
}

/// `leaf` sealed to the asker's encryption key `key` under `request`'s
/// binding.
fn seal_leaf(
    vault_id: &[u8; 32],
    request: &LeafKeyRequest,
    key: &HybridPublicKey,
    leaf: &CredentialLeaf,
) -> Result<Vec<u8>> {
    let recipient = WrapRecipient::Machine(request.executor).envelope_recipient();
    let key_id = request.seal_key_id();
    let mut payload = Zeroizing::new(Vec::with_capacity(LEAF_LABEL.len() + leaf.len()));
    payload.extend_from_slice(LEAF_LABEL);
    payload.extend_from_slice(&leaf[..]);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::SecretFile,
        epoch: EPOCH,
        key_id: &key_id,
        recipient: &recipient,
        vault_id,
    };
    seal(
        &params,
        SealKey::Hybrid {
            recipient: key,
            kem_suite: KEM,
        },
        &payload,
        &mut SysRng,
    )
    .map(|envelope| envelope.to_bytes())
    .map_err(|_| authority_refused(REFUSED_ASKER_KEY))
}

/// The key `sealed` holds, opened with the asker's `secret` under
/// `request`'s binding; `None` when it does not open there.
fn open_leaf(
    vault_id: &[u8; 32],
    request: &LeafKeyRequest,
    sealed: &[u8],
    secret: &MachineSecret,
) -> Option<CredentialLeaf> {
    let envelope = Envelope::parse(sealed).ok()?;
    let recipient = WrapRecipient::Machine(request.executor).envelope_recipient();
    let key_id = request.seal_key_id();
    let policy = OpenPolicy {
        purpose: Purpose::SecretFile,
        vault_id,
        recipient: &recipient,
        key_id: &key_id,
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let payload = envelope
        .open(OpenKey::Hybrid(&secret.secret), &policy)
        .ok()?;
    let bytes = payload.strip_prefix(LEAF_LABEL)?;
    let mut leaf: CredentialLeaf = Zeroizing::new([0; 32]);
    if bytes.len() != leaf.len() {
        return None;
    }
    leaf.copy_from_slice(bytes);
    Some(leaf)
}
