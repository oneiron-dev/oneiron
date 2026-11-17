//! The protected input of an active custody change (WILL L04 row 04): what a
//! register, rotate or bind hands its holder, sealed to the holder's
//! encryption key alone.
//!
//! A register's input is the whole record, metadata and value, framed with
//! the text of the manifest its recorder resolved it from, when there is one
//! (CALLS CUSTODY_MANIFEST_RECHECK); a rotate's is the new value; a bind's
//! rewrap carries the record's new bindings (CALLS CUSTODY_BIND_TRAVEL). A
//! rewrap that only seals again carries none. The envelope's key id binds
//! the vault, the secret's id, the change, the generation it approves, the
//! custody revision the owner saw, the holder and every permit, so an input
//! never opens as another change's.
//! The request names only the digest of its ciphertext, never a hash of the
//! value. A door that is the holder executes from what it holds in the
//! request's own commit and keeps no input; any other door keeps the input
//! to relay beside the custody transitions, under its digest, with the
//! request it is for, until the holder answers (`crate::sync::custody`). A
//! surface that seals the input itself hands the console no plaintext; an
//! upload of the raw value to the holder stays an explicit choice.
//!
//! A kept or relayed input carries its request's signed entry as a witness
//! (FIX 4996), beside the envelope and outside the digest the request names,
//! since the request names that digest: a window admits an input row only
//! on a witness that proves the row names a real request for it.
//!
//! An input longer than one row carries, as a register framed with its
//! manifest's text or a sealed register with every manifest the vault
//! publishes attached may be, travels in numbered parts (Rule 5: split,
//! never skip; CALLS CUSTODY_MANIFEST_UNSTATED_MULTI). No seal, door or
//! open refuses an input for its whole length (FIX 5445): a body past one
//! envelope's plaintext bound seals as numbered envelopes, each within it
//! (FIX 5521, `envelopes`), and each row keeps the 4 MiB bound. Each
//! part row carries its index, every part's digest and its own bytes, and
//! the digest the request names is over that list, so one 32-byte digest
//! commits to the whole input and each part is checked on its own as it is
//! admitted. The holder reads the parts in order as it opens the input,
//! never joining them; while one is missing, the request stays pending.
//!
//! A door reads the input its owner's surface sealed where it lies, a file
//! or a buffer, never as one buffer (FIX 11140, `stream`): it computes the
//! digest part by part and keeps the input row by row. One it seals in
//! numbered carrier parts it reads once, staging each row as it is sealed
//! and digesting it as it is staged (FIX 12177, `door_rows`).
//!
//! A witness past one row's bound travels in signed numbered parts of its
//! own, and each input row carries a signed reference to them (FIX 8088,
//! `witness`).
//!
//! While the carrier wire is on, an input is sealed under its own erasable
//! carrier key first, a surface's past one row in numbered parts (FIX
//! 12148), and the recorder retires that key once its request is answered
//! (FIX 7402, `carrier_seal`).

mod attached;
mod carrier_seal;
mod door_rows;
mod envelopes;
mod stream;
mod surface_seal;
mod witness;

use std::io::Read;

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, OpenKey, OpenPolicy, Purpose, SealKey, SealParams,
    SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use crate::Vault;
use crate::authority::{AuthorityEntryHash, CustodyChange, CustodyPermitSet, WrapRecipient};
#[cfg(feature = "sync")]
use crate::authority::{
    AuthorityFold, AuthorityFoldIssue, AuthorityKey, AuthorityOp, OwnerWorkBody, OwnerWorkRequest,
    authority_entry_hash, decode_authority_log_entry_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::world_keys::MachineSecret;

#[cfg(oneiron_test_support)]
use super::super::codec::{decode_register_input, encode_register_input};
#[cfg(oneiron_test_support)]
use super::super::types::{
    CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
    SecretCustodyStatus,
};
#[cfg(oneiron_test_support)]
use crate::authority::CustodyRecipientPermit;
#[cfg(oneiron_test_support)]
use oneiron_crypto::HybridSecretKey;

pub(crate) use self::attached::{
    Attached, AttachedManifest, Attachment, attach_manifest, attach_no_manifest,
    attach_published_manifests, attach_unread,
};
pub(crate) use self::carrier_seal::{
    LeafSource, SurfaceLeaf, SurfaceRetry, input_carrier_binds, input_carrier_in_txn,
    open_leaf_input, retire_input_carriers_in_txn, seal_leaf_input_in_txn, seal_leaf_parts_in_txn,
    surface_leaf_input, surface_retry_in_txn,
};
pub(crate) use self::door_rows::DoorInput;
#[cfg(oneiron_test_support)]
pub(crate) use self::envelopes::{
    frame_envelope_count_for_test, tamper_drop_first_envelope_for_test,
    tamper_rewrite_envelope_count_for_test, tamper_swap_first_two_envelopes_for_test,
};
pub use self::stream::SealedInput;
pub(crate) use self::stream::{InputDigests, SealedFrame, kept_input_in_txn};
pub use self::surface_seal::{CustodyInputBinding, seal_custody_input};
pub(crate) use self::witness::{WitnessJoin, keep_witnessed_input_in_txn, witness_joined_in_txn};
#[cfg(feature = "sync")]
pub(crate) use self::witness::{
    WitnessPart, held_witness_in_txn, held_witnesses, keep_witness_in_txn,
};

const INPUT_LABEL: &[u8] = b"oneiron/custody-input/v1";
const KEY_ID_LABEL: &[u8] = b"custody-input/v1";
const BINDING_DOMAIN: &[u8] = b"oneiron/custody-input-binding/v1";
const DIGEST_DOMAIN: &[u8] = b"oneiron/custody-input-digest/v1";
const EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The most bytes of an input one relayed row carries, as for a custody
/// transition: a longer input, its envelope with whatever its recorder
/// attached, splits into parts of at most this many bytes. It bounds a row,
/// never the whole input (FIX 5445).
pub(crate) const MAX_INPUT_BYTES: usize = 4 << 20;
/// A relayed input's frame: the second it was sealed at, the request, then
/// its witness's length. The witness and the row's body follow, each at most
/// [`MAX_INPUT_BYTES`]: the whole input, or one part of it.
const FRAME_BYTES: usize = 8 + 32 + 4;
/// The most bytes of an input one part carries.
const PART_BYTES: usize = MAX_INPUT_BYTES;
/// The most parts one split input lists: its part digests fill at most one
/// row's bound (the part list's own codec bound, past 500 GiB of input).
const MAX_PARTS: usize = MAX_INPUT_BYTES / 32;
/// The label of one part of a split input's row body: the part's index and
/// the part count, each a `u32`, every part's digest in order, then the
/// part's bytes.
const PART_LABEL: &[u8] = b"oneiron/custody-input-part/v1\0";
const PART_DIGEST_DOMAIN: &[u8] = b"oneiron/custody-input-part-digest/v1";
const PARTS_DIGEST_DOMAIN: &[u8] = b"oneiron/custody-input-parts-digest/v1";
const PART_KEY_DOMAIN: &[u8] = b"oneiron/custody-input-part-key/v1";

/// Each input row this vault keeps to relay, or keeps as its holder until
/// it answers: a whole input by the digest its request names, a part of a
/// split one by its own key.
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
    pub(crate) permits: &'a CustodyPermitSet,
}

impl InputBinding<'_> {
    /// A one-envelope input's key id: a label, then a digest of every bound
    /// field, within the envelope's 64-byte id. A numbered envelope's adds
    /// its place (`envelopes`).
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
    /// bytes. A body that fits one envelope seals as one, the form an input
    /// has always had; a longer one as numbered envelopes in one frame
    /// (FIX 5521, `envelopes`). Either is carried past one row's bound in
    /// numbered parts (FIX 5445). Nothing refuses its length but the codec
    /// bounds of one envelope and of the frame.
    pub(crate) fn seal(&self, key: &HybridPublicKey, body: &[u8]) -> Result<Vec<u8>> {
        if envelopes::fits_one(body) {
            self.seal_one(key, body, &self.key_id())
        } else {
            self.seal_numbered(key, body)
        }
    }

    /// Seals `body`, within one envelope's bound, to the holder's `key` as
    /// one envelope under `key_id`.
    fn seal_one(&self, key: &HybridPublicKey, body: &[u8], key_id: &[u8]) -> Result<Vec<u8>> {
        let recipient = WrapRecipient::Machine(self.holder).envelope_recipient();
        let mut payload = Zeroizing::new(Vec::with_capacity(INPUT_LABEL.len() + body.len()));
        payload.extend_from_slice(INPUT_LABEL);
        payload.extend_from_slice(body);
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::SecretFile,
            epoch: EPOCH,
            key_id,
            recipient: &recipient,
            vault_id: &self.vault_id,
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
        .map_err(|_| refused("sealing the custody input to its holder failed"))
    }

    /// The body the input of `len` bytes `reader` holds, opened with the
    /// holder's `secret` under this binding as it is read: one envelope, or
    /// every numbered envelope of a frame, each opened and verified at its
    /// place before the next is read and the runs joined (FIX 5521, 11140).
    /// `None` when `secret` is not the holder's, an envelope does not parse
    /// under its codec, or one was sealed to another key, under another
    /// binding or at another place. Its length past one row's bound is no
    /// reason: such an input is read from its parts in order (FIX 5445).
    pub(crate) fn open(
        &self,
        reader: impl Read,
        len: u64,
        secret: &MachineSecret,
    ) -> Option<Zeroizing<Vec<u8>>> {
        if secret.machine != self.holder {
            return None;
        }
        self.open_read(reader, len, secret)
    }

    /// The body one `envelope` holds, opened with the holder's `secret`
    /// under `key_id`.
    fn open_one(
        &self,
        envelope: &[u8],
        secret: &MachineSecret,
        key_id: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let envelope = Envelope::parse(envelope).ok()?;
        let recipient = WrapRecipient::Machine(self.holder).envelope_recipient();
        let policy = OpenPolicy {
            purpose: Purpose::SecretFile,
            vault_id: &self.vault_id,
            recipient: &recipient,
            key_id,
            wraps: &[WrapType::HybridCapsule],
            aead_suites: &[AEAD],
            kem_suites: &[KEM],
            min_epoch: EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let payload = envelope
            .open(OpenKey::Hybrid(&secret.secret), &policy)
            .ok()?;
        let body = payload.strip_prefix(INPUT_LABEL)?;
        Some(Zeroizing::new(body.to_vec()))
    }
}

/// The digest a request names of its input: over the ciphertext alone, so
/// it says nothing of the value. For an input that travels in parts, over
/// the list of its parts' digests, each over that part's bytes alone.
pub(crate) fn input_digest(input: &[u8]) -> [u8; 32] {
    if splits(input) {
        parts_digest(
            &input
                .chunks(PART_BYTES)
                .map(part_digest)
                .collect::<Vec<_>>(),
        )
    } else {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(input);
        *hasher.finalize().as_bytes()
    }
}

/// Whether `input` travels in parts: it is longer than one row carries, or
/// its own bytes would read as a part.
fn splits(input: &[u8]) -> bool {
    input.len() > PART_BYTES || input.starts_with(PART_LABEL)
}

/// One part's digest, over its bytes alone.
fn part_digest(bytes: &[u8]) -> [u8; 32] {
    *part_hasher().update(bytes).finalize().as_bytes()
}

/// A part's digest before its bytes, which [`part_digest`] takes whole and
/// a reader may feed in runs (FIX 12177).
fn part_hasher() -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PART_DIGEST_DOMAIN);
    hasher
}

/// A split input's digest: over its part count and every part's digest, in
/// order.
fn parts_digest(digests: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PARTS_DIGEST_DOMAIN);
    hasher.update(&(digests.len() as u64).to_be_bytes());
    for digest in digests {
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

/// The key part `index` of the split input the request names `digest` of
/// is kept and relayed under.
fn part_key(digest: &[u8; 32], index: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PART_KEY_DOMAIN);
    hasher.update(digest);
    hasher.update(&index.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Where one row's bytes sit in a split input: the part's index, and every
/// part's digest in order, which the digest the request names is over.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct InputPart {
    index: u32,
    digests: Vec<[u8; 32]>,
}

/// One input as it is kept and relayed: the second it was sealed at, whose
/// month's base window carries it, the request it is for, that request's
/// witness and its envelope, whole or one part of it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RelayedInput {
    pub(crate) sealed_at: u64,
    pub(crate) request: AuthorityEntryHash,
    /// The request's signed authority entry, canonical (FIX 4996). It rides
    /// outside the envelope's digest, which the request names.
    pub(crate) witness: Vec<u8>,
    /// Where `envelope` sits in the input the request names; `None` while
    /// it is the whole.
    pub(crate) part: Option<InputPart>,
    /// The whole input, or this part's bytes.
    pub(crate) envelope: Vec<u8>,
}

/// What an input's witness proves: the request, and the install key that
/// signed it, when it is one.
#[cfg(feature = "sync")]
pub(crate) struct Witnessed {
    key: Option<[u8; 32]>,
    request: OwnerWorkRequest,
}

#[cfg(feature = "sync")]
impl Witnessed {
    /// Whether `fold` judged the request entry `hash` invalid with its
    /// signer folded (FIX 4996): a chain of its carrier names the key that
    /// signed it, and the fold holds an issue for exactly this entry, other
    /// than one that waits on a parent not here yet.
    pub(crate) fn folded_invalid(&self, fold: &AuthorityFold, hash: &AuthorityEntryHash) -> bool {
        let Some(key) = &self.key else {
            return false;
        };
        fold.machine(self.request.carrier)
            .is_some_and(|machine| machine.names_key(key))
            && fold.issues.iter().any(|issue| match issue {
                AuthorityFoldIssue::InvalidEntry(entry)
                | AuthorityFoldIssue::RetiredSigner(entry)
                | AuthorityFoldIssue::SignerNotInAncestry(entry)
                | AuthorityFoldIssue::NonMonotonicSeq(entry)
                | AuthorityFoldIssue::WrongVault(entry) => entry == hash,
                _ => false,
            })
    }
}

// Never print the ciphertext.
impl std::fmt::Debug for RelayedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayedInput")
            .field("sealed_at", &self.sealed_at)
            .field(
                "part",
                &self
                    .part
                    .as_ref()
                    .map(|part| (part.index, part.digests.len())),
            )
            .field("bytes", &self.envelope.len())
            .finish_non_exhaustive()
    }
}

impl RelayedInput {
    /// The frame, the witness, then the body: the envelope, or for a part
    /// its label, index, part count and part digests, then its bytes. A
    /// witness longer than a `u32` is never framed: [`Self::decode`] refuses
    /// one past [`MAX_INPUT_BYTES`].
    pub(crate) fn encode(&self) -> Vec<u8> {
        let witness_len = u32::try_from(self.witness.len()).unwrap_or(u32::MAX);
        let listed = self.part.as_ref().map_or(0, |part| part.digests.len());
        let mut out = Vec::with_capacity(
            FRAME_BYTES
                + self.witness.len()
                + PART_LABEL.len()
                + 8
                + 32 * listed
                + self.envelope.len(),
        );
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&witness_len.to_be_bytes());
        out.extend_from_slice(&self.witness);
        if let Some(part) = &self.part {
            out.extend_from_slice(PART_LABEL);
            out.extend_from_slice(&part.index.to_be_bytes());
            out.extend_from_slice(&u32::try_from(listed).unwrap_or(u32::MAX).to_be_bytes());
            for digest in &part.digests {
                out.extend_from_slice(digest);
            }
        }
        out.extend_from_slice(&self.envelope);
        out
    }

    /// Decodes a kept or relayed input strictly; `None` for a short frame,
    /// a zero request, an empty or oversized witness or envelope, or a part
    /// whose index is outside its list, whose list is empty or past
    /// [`MAX_PARTS`], or whose bytes are not the digest its list names for
    /// it. The witness is read, not judged: [`Self::witnessed`] judges it.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (sealed_at, rest) = bytes.split_first_chunk::<8>()?;
        let (request, rest) = rest.split_first_chunk::<32>()?;
        let (witness_len, rest) = rest.split_first_chunk::<4>()?;
        let (witness, body) =
            rest.split_at_checked(usize::try_from(u32::from_be_bytes(*witness_len)).ok()?)?;
        let (part, envelope) = match body.strip_prefix(PART_LABEL) {
            None => (None, body),
            Some(rest) => {
                let (part, bytes) = InputPart::decode(rest)?;
                (Some(part), bytes)
            }
        };
        if *request == [0; 32]
            || witness.is_empty()
            || witness.len() > MAX_INPUT_BYTES
            || envelope.is_empty()
            || envelope.len() > MAX_INPUT_BYTES
        {
            return None;
        }
        Some(Self {
            sealed_at: u64::from_be_bytes(*sealed_at),
            request: *request,
            witness: witness.to_vec(),
            part,
            envelope: envelope.to_vec(),
        })
    }

    /// The key this row is kept and relayed under: the digest the request
    /// names for a whole input, else this part's own key under it.
    pub(crate) fn row_key(&self) -> [u8; 32] {
        match &self.part {
            Some(part) => part_key(&self.digest(), part.index),
            None => self.digest(),
        }
    }

    /// The rows that carry this whole input when it travels in parts: each
    /// numbered part, in order, every one with the witness and the part
    /// list. `None` when it fits one row, or is a part already. Refused only
    /// past the part list's own bound. A door's own input is kept as it is
    /// read instead (`stream`, FIX 11140).
    #[cfg(feature = "sync")]
    fn parts(&self) -> Result<Option<Vec<Self>>> {
        if self.part.is_some() || !splits(&self.envelope) {
            return Ok(None);
        }
        let digests: Vec<[u8; 32]> = self.envelope.chunks(PART_BYTES).map(part_digest).collect();
        if digests.len() > MAX_PARTS {
            return Err(refused(
                "the custody input splits into more parts than one part list names",
            ));
        }
        Ok(Some(
            self.envelope
                .chunks(PART_BYTES)
                .zip(0_u32..)
                .map(|(bytes, index)| Self {
                    sealed_at: self.sealed_at,
                    request: self.request,
                    witness: self.witness.clone(),
                    part: Some(InputPart {
                        index,
                        digests: digests.clone(),
                    }),
                    envelope: bytes.to_vec(),
                })
                .collect(),
        ))
    }

    /// The request this input's witness proves (FIX 4996): the witness is a
    /// canonical authority entry whose signature verifies, it hashes to
    /// `request`, and it is a custody request naming this input's digest.
    /// `None` otherwise. It proves the row self-consistent, not its signer
    /// one of this vault's machines: a row a key no machine here ever holds
    /// signed is kept until its window retires, so an input that arrives
    /// before its request still reaches its holder (CALLS
    /// CUSTODY_INPUT_PRUNE, FIX 5405).
    #[cfg(feature = "sync")]
    pub(crate) fn witnessed(&self) -> Option<Witnessed> {
        let entry = decode_authority_log_entry_body(&self.witness).ok()?;
        if authority_entry_hash(&entry).ok()? != self.request {
            return None;
        }
        let key = match entry.signer_key() {
            AuthorityKey::Ed25519(key) => Some(*key),
            _ => None,
        };
        let AuthorityOp::OwnerWorkRequest(request) = entry.op else {
            return None;
        };
        let digest = self.digest();
        matches!(
            &request.work,
            OwnerWorkBody::Custody { input: Some(named), .. } if *named == digest
        )
        .then_some(Witnessed { key, request })
    }

    /// The digest the request names: of the whole input, or for a part,
    /// over its list of part digests.
    pub(crate) fn digest(&self) -> [u8; 32] {
        match &self.part {
            Some(part) => parts_digest(&part.digests),
            None => input_digest(&self.envelope),
        }
    }
}

impl InputPart {
    /// A part's index, part count and part digests, then its bytes, which
    /// must be the digest its list names for it.
    fn decode(body: &[u8]) -> Option<(Self, &[u8])> {
        let (index, rest) = body.split_first_chunk::<4>()?;
        let (count, rest) = rest.split_first_chunk::<4>()?;
        let count = usize::try_from(u32::from_be_bytes(*count)).ok()?;
        if count == 0 || count > MAX_PARTS {
            return None;
        }
        let (listed, bytes) = rest.split_at_checked(count.checked_mul(32)?)?;
        let digests = listed
            .chunks_exact(32)
            .map(|digest| <[u8; 32]>::try_from(digest).ok())
            .collect::<Option<Vec<_>>>()?;
        let index = u32::from_be_bytes(*index);
        let named = digests.get(usize::try_from(index).ok()?)?;
        (part_digest(bytes) == *named).then_some((Self { index, digests }, bytes))
    }
}

/// The witness of the request signed as entry `hash` (FIX 4996): its stored
/// entry, canonical, which hashes to `hash`.
///
/// # Errors
/// No authority row is stored under `hash`; storage errors.
pub(crate) fn request_witness_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hash: &AuthorityEntryHash,
) -> Result<Vec<u8>> {
    let entry = crate::authority::stored_authority_row(&vault.store, txn, hash)?
        .ok_or_else(crate::authority::invalid_authority)?;
    crate::authority::encode_authority_log_entry_body(&entry)
}

/// Keeps `input` in `wtxn`, each row under its key: a whole input that
/// fits one row as it is, a longer one as its numbered parts, and a relayed
/// part as it came.
#[cfg(feature = "sync")]
pub(crate) fn keep_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: &RelayedInput,
) -> Result<()> {
    let parts = input.parts()?;
    for row in parts.as_deref().unwrap_or(std::slice::from_ref(input)) {
        INPUTS.put(&vault.store, wtxn, &row.row_key(), &row.encode())?;
    }
    Ok(())
}

/// The input row kept under `key`, when it decodes.
pub(crate) fn held_input_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
) -> Result<Option<RelayedInput>> {
    Ok(INPUTS
        .get(store, txn, key)?
        .and_then(|bytes| RelayedInput::decode(&bytes)))
}

/// Forgets the input the request names `digest` of: its whole row, or each
/// of its parts, then each other row found by the digest it names, a first
/// part missing included, and every part of its witness (FIX 8088). A fault
/// finding those is warned and never undoes the rest: they, and a part
/// that arrives later, go with the answered request
/// ([`Vault::settle_custody_inputs`]).
pub(crate) fn drop_input_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    let parts = held_input_in_txn(&vault.store, wtxn, &part_key(digest, 0))?
        .and_then(|row| row.part)
        .map_or(0, |part| part.digests.len());
    INPUTS.delete(&vault.store, wtxn, digest)?;
    for index in (0_u32..).take(parts) {
        INPUTS.delete(&vault.store, wtxn, &part_key(digest, index))?;
    }
    if let Err(error) = witness::drop_rows_of_in_txn(vault, wtxn, digest) {
        tracing::warn!(kind = ?error.kind(), "an input's other rows stay for its settle");
    }
    Ok(())
}

/// Forgets every input row kept for a request on record `id`, each part of
/// a split one too: a revoke leaves no pending input of it (CALLS
/// CUSTODY_REVOKE_ERASE). Returns how many rows it forgot.
pub(crate) fn drop_inputs_for_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<usize> {
    let fold = vault.authority_view_readonly_in_txn(wtxn)?;
    drop_inputs_with_fold_in_txn(&vault.store, wtxn, id, &fold)
}

pub(super) fn drop_inputs_with_fold_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    fold: &crate::authority::AuthorityFold,
) -> Result<usize> {
    let doomed: Vec<([u8; 32], Vec<u8>)> = INPUTS
        .scan(store, wtxn)?
        .into_iter()
        .filter(|(_, bytes)| {
            RelayedInput::decode(bytes).is_some_and(|input| {
                fold.owner_work_request(&input.request)
                    .is_some_and(|request| request.act.target == *id)
            })
        })
        .collect();
    // Their carrier keys go with them (FIX 7402).
    let carriers: Vec<_> = doomed
        .iter()
        .filter_map(|(_, bytes)| carrier_seal::row_carrier(bytes))
        .collect();
    retire_input_carriers_in_txn(store, wtxn, &carriers);
    for (key, _) in &doomed {
        INPUTS.delete(store, wtxn, key)?;
    }
    // Every witness part kept for such a request goes too (FIX 8088); a
    // fault finding them is warned, and they go with the settle.
    let witnesses = witness::drop_witnesses_for_store_in_txn(store, wtxn, |group| {
        witness::witness_target(fold, group) == Some(*id)
    })
    .unwrap_or_else(|error| {
        tracing::warn!(kind = ?error.kind(), "a revoked secret's witness parts stay for its settle");
        0
    });
    Ok(doomed.len() + witnesses)
}

/// Every input row this vault keeps, by its key, as stored.
#[cfg(feature = "sync")]
pub(crate) fn held_inputs(vault: &Vault) -> Result<Vec<([u8; 32], Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    INPUTS.scan(&vault.store, &rtxn)
}

impl Vault {
    /// Forgets every kept input row, whole or part, whose request is
    /// answered, is on a secret an admitted revoke ended, or that this
    /// install folds as no admitted request at all: what remains is the
    /// relay of work still awaiting its holder. The owner work drain runs it
    /// beside the revoke settle. Returns how many rows it forgot.
    pub(crate) fn settle_custody_inputs(&self) -> Result<usize> {
        let (done, carriers, witnesses) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let settled = |request: &AuthorityEntryHash| {
                fold.owner_work_result(request).is_some()
                    || fold
                        .owner_work_request(request)
                        .is_none_or(|request| fold.custody_revoked(&request.act.target))
            };
            let done: Vec<([u8; 32], Vec<u8>)> = INPUTS
                .scan(&self.store, &txn)?
                .into_iter()
                .filter(|(_, bytes)| {
                    RelayedInput::decode(bytes).is_none_or(|input| settled(&input.request))
                })
                .collect();
            // An answered input's carrier key retires here, where its
            // recorder minted it (FIX 7402).
            let carriers: Vec<_> = done
                .iter()
                .filter_map(|(_, bytes)| carrier_seal::row_carrier(bytes))
                .collect();
            // So does every witness part kept for one (FIX 8088); a fault
            // finding them is warned, and the next settle retries.
            let witnesses = witness::settled_witnesses_in_txn(&self.store, &txn, settled)
                .unwrap_or_else(|error| {
                    tracing::warn!(kind = ?error.kind(), "settled witness parts stay owed");
                    Vec::new()
                });
            (done, carriers, witnesses)
        };
        if done.is_empty() && witnesses.is_empty() {
            return Ok(0);
        }
        let forgot = self.with_write_txn(|txn| {
            retire_input_carriers_in_txn(&self.store, txn, &carriers);
            for (key, _) in &done {
                INPUTS.delete(&self.store, txn, key)?;
            }
            if let Err(error) = witness::delete_witnesses_in_txn(self, txn, &witnesses) {
                tracing::warn!(kind = ?error.kind(), "settled witness parts stay owed");
                return Ok(done.len());
            }
            Ok(done.len() + witnesses.len())
        })?;
        if !carriers.is_empty() {
            self.finish_credential_retirements_after_commit();
        }
        Ok(forgot)
    }
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("{reason}; nothing was written"))
}

/// The vault id a test numbered input binds.
#[cfg(oneiron_test_support)]
const NUMBERED_TEST_VAULT_ID: [u8; 32] = [0x51; 32];
/// The custody revision a test numbered input binds as seen.
#[cfg(oneiron_test_support)]
const NUMBERED_TEST_SEEN: [u8; 32] = [0x53; 32];
/// The generation a test numbered input approves.
#[cfg(oneiron_test_support)]
const NUMBERED_TEST_GENERATION: u32 = 7;
/// The second a test numbered input is sealed at.
#[cfg(oneiron_test_support)]
const NUMBERED_TEST_AT: u64 = 1_780_000_000;
/// The request hash a kept test numbered input is stored under beside.
#[cfg(all(oneiron_test_support, feature = "sync"))]
const NUMBERED_TEST_REQUEST: [u8; 32] = [0x61; 32];

/// The secret id a test numbered input binds.
#[cfg(oneiron_test_support)]
fn numbered_test_id() -> EntityId {
    EntityId::from_bytes_unchecked([0x52; 16])
}

/// A portable record of `name` holding `value`, as a door seals it.
#[cfg(oneiron_test_support)]
fn numbered_test_record(name: &str, value: &[u8]) -> SecretCustodyRecord {
    SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        model_reveal_allowed: true,
        value_bytes: value.to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: NUMBERED_TEST_AT,
        rotated_at: None,
        rotation_generation: NUMBERED_TEST_GENERATION,
        bindings: Vec::new(),
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    }
}

/// The exact permit a test numbered input binds for its holder.
#[cfg(oneiron_test_support)]
fn numbered_test_permits(holder: EntityId) -> CustodyPermitSet {
    let permits = [CustodyRecipientPermit {
        machine: holder,
        profile: [0x54; 32],
        encryption_key: [0x55; 32],
    }];
    CustodyPermitSet::from(&permits[..])
}

/// The binding a test numbered register input seals and opens under.
#[cfg(oneiron_test_support)]
fn numbered_test_binding(holder: EntityId, permits: &CustodyPermitSet) -> InputBinding<'_> {
    InputBinding {
        vault_id: NUMBERED_TEST_VAULT_ID,
        id: numbered_test_id(),
        change: CustodyChange::Register,
        generation: NUMBERED_TEST_GENERATION,
        seen: NUMBERED_TEST_SEEN,
        holder,
        permits,
    }
}

/// The holder's secret: its machine with the key `seed` names.
#[cfg(oneiron_test_support)]
fn numbered_test_secret(holder: EntityId, seed: u8) -> MachineSecret {
    MachineSecret {
        machine: holder,
        secret: HybridSecretKey::from_seeds(&[seed; 64], &[seed; 32]),
    }
}

/// Seals a register of `name` holding `value`, framed with `manifest`, to
/// `holder`'s key under the test binding, as a door seals it (FIX 5521),
/// for `test_doors::custody_numbered_input` (FIX 5624). Returns the sealed
/// frame, the body length it seals and the frame's envelope count.
///
/// # Errors
/// A body that fits one envelope, so the test seals nothing numbered; a
/// seal that fails; a sealed frame that states no envelope count.
#[cfg(oneiron_test_support)]
pub(crate) fn seal_numbered_register_for_test(
    holder: EntityId,
    seed: u8,
    name: &str,
    value: &[u8],
    manifest: Option<&str>,
) -> Result<(Vec<u8>, usize, u32)> {
    let record = numbered_test_record(name, value);
    let body = encode_register_input(&record, manifest)?;
    if envelopes::fits_one(&body) {
        return Err(refused(
            "the test body fits one envelope; grow it past one envelope's bound",
        ));
    }
    let permits = numbered_test_permits(holder);
    let binding = numbered_test_binding(holder, &permits);
    let secret = HybridSecretKey::from_seeds(&[seed; 64], &[seed; 32]);
    let frame = binding.seal(secret.public_key(), &body)?;
    let count = envelopes::frame_envelope_count_for_test(&frame)
        .ok_or_else(|| refused("a sealed numbered input states no envelope count"))?;
    Ok((frame, body.len(), count))
}

/// Opens `frame` with the holder's secret under the test binding, for
/// `test_doors::custody_numbered_input` (FIX 5624): the register's value,
/// framed manifest text and name. `None` when it does not open, or not to
/// a register body: the arm the executor refuses as `InvalidInput`.
#[cfg(oneiron_test_support)]
pub(crate) fn open_numbered_as_holder_for_test(
    frame: &[u8],
    holder: EntityId,
    seed: u8,
) -> Option<(Vec<u8>, Option<String>, String)> {
    let permits = numbered_test_permits(holder);
    let binding = numbered_test_binding(holder, &permits);
    let secret = numbered_test_secret(holder, seed);
    let body = binding.open(frame, frame.len() as u64, &secret)?;
    let (record, manifest) = decode_register_input(&body)?;
    Some((record.value_bytes, manifest, record.name))
}

/// What opening a kept test numbered input found.
#[cfg(all(oneiron_test_support, feature = "sync"))]
pub(crate) enum KeptNumberedOpen {
    /// No whole row, or no complete part list, is kept: the request stays
    /// pending.
    Missing,
    /// The kept rows do not open under the holder's key and binding, or not
    /// to a register body: the arm the executor refuses as `InvalidInput`.
    Invalid,
    /// The register's value, framed manifest text and name.
    Opened(Vec<u8>, Option<String>, String),
}

/// Keeps `frame` as the test input the digest the request would name,
/// whole or in numbered parts, for `test_doors::custody_numbered_input`
/// (FIX 5624). Returns that digest and how many rows keep it.
///
/// # Errors
/// A frame past the part list's bound; storage errors.
#[cfg(all(oneiron_test_support, feature = "sync"))]
pub(crate) fn keep_numbered_input_for_test(vault: &Vault, frame: &[u8]) -> Result<([u8; 32], u32)> {
    let row = RelayedInput {
        sealed_at: NUMBERED_TEST_AT,
        request: NUMBERED_TEST_REQUEST,
        witness: vec![0x62; 64],
        part: None,
        envelope: frame.to_vec(),
    };
    vault.with_write_txn(|wtxn| keep_input_in_txn(vault, wtxn, &row))?;
    let digest = input_digest(frame);
    let txn = vault.store.env.read_txn()?;
    let mut parts = 0_u32;
    for (_, bytes) in INPUTS.scan(&vault.store, &txn)? {
        if RelayedInput::decode(&bytes).is_some_and(|kept| kept.digest() == digest) {
            parts += 1;
        }
    }
    Ok((digest, parts))
}

/// Opens the test input kept under `digest` with the holder's secret under
/// the test binding, for `test_doors::custody_numbered_input` (FIX 5624).
///
/// # Errors
/// Storage errors reading a kept row.
#[cfg(all(oneiron_test_support, feature = "sync"))]
pub(crate) fn open_kept_numbered_for_test(
    vault: &Vault,
    digest: &[u8; 32],
    holder: EntityId,
    seed: u8,
) -> Result<KeptNumberedOpen> {
    let permits = numbered_test_permits(holder);
    let binding = numbered_test_binding(holder, &permits);
    let secret = numbered_test_secret(holder, seed);
    let txn = vault.store.env.read_txn()?;
    let Some(kept) = kept_input_in_txn(&vault.store, &txn, digest)? else {
        return Ok(KeptNumberedOpen::Missing);
    };
    let Some((body, _attached)) = kept.open(&binding, &secret)? else {
        return Ok(KeptNumberedOpen::Invalid);
    };
    let Some((record, manifest)) = decode_register_input(&body) else {
        return Ok(KeptNumberedOpen::Invalid);
    };
    Ok(KeptNumberedOpen::Opened(
        record.value_bytes,
        manifest,
        record.name,
    ))
}

/// Forgets part `index` of the test input kept under `digest`, for
/// `test_doors::custody_numbered_input` (FIX 5624). Returns whether a row
/// was kept there.
///
/// # Errors
/// Storage errors.
#[cfg(all(oneiron_test_support, feature = "sync"))]
pub(crate) fn drop_kept_numbered_part_for_test(
    vault: &Vault,
    digest: &[u8; 32],
    index: u32,
) -> Result<bool> {
    vault.with_write_txn(|wtxn| {
        let key = part_key(digest, index);
        let kept = INPUTS.get(&vault.store, wtxn, &key)?.is_some();
        INPUTS.delete(&vault.store, wtxn, &key)?;
        Ok(kept)
    })
}
