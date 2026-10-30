//! The bytes of a custody transition: its strict codec, the transcript its
//! signature covers, and the value sealed to one machine and opened there.
//! Who may sign one, and what a vault does with one, stay in the parent.
//!
//! The artifact names the admitted custody request it enacts and the digest
//! of the encrypted input that request names (CALLS CUSTODY_PAYLOAD), and it
//! carries each recipient's exact permit beside the value sealed to it
//! (CALLS CUSTODY_PERMITS). Each value envelope's key id binds the record,
//! generation, status and request, and the recipient's machine, profile
//! entry and encryption key digest, so an envelope sealed for one request,
//! status or key never opens as another's.
//!
//! A carrier is one piece of its transition (CALLS `Phase2 custody pieces
//! request bound`): it signs the commitment to the request's complete
//! permitted set, its own place in the pieces and the first permit it
//! carries, under the frame floors kept here (the `u16` count, the 4 MiB
//! decode bound on the content a carrier held before pieces, the piece
//! fields beside it). No total recipient count is refused.
//!
//! A value too large for one carrier rides in numbered envelopes, each the
//! next run of the value, in pieces of their own (FIX 7953): each envelope's
//! key id is the one-envelope key id with its index and the count after it,
//! so none opens at another place, among another count or as a one-envelope
//! value. The value opens only from the whole transition, every envelope at
//! its place; a missing piece leaves the change pending.
//!
//! While the carrier wire is on, a transition whose value is sealed under
//! its own carrier key first (transition v3, FIX 7402) opens with its own
//! magic and signs that key's reference beside its piece fields; the
//! envelopes each permit opens then hold the value sealed under that key,
//! whole before it is split, never the value itself (`super::carrier_leaf`).
//! With the wire off a carrier is exactly as before, and one that names a
//! key does not decode.

use ed25519_dalek::{Signature, VerifyingKey};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, ONEV_HEADER_PREFIX_MAX, OpenKey,
    OpenPolicy, Purpose, SealKey, SealParams, SuiteId, TAG_LEN, WrapType, seal,
};
use zeroize::Zeroizing;

use super::super::carrier_custody::{
    CARRIER_REF_BYTES, CUSTODY_CARRIER_LEAF_WIRE, CUSTODY_TRANSITION_WIRE_VERSION, CarrierRef,
};
use super::super::codec::{decode_secret_custody_body, invalid_body};
use super::super::types::{SecretCustodyRecord, SecretCustodyStatus};
use super::{CustodyTransition, custody_portable};
use crate::authority::{AuthorityEntryHash, CustodyRecipientPermit, WrapRecipient};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::CustodyKind;

const MAGIC: &[u8; 4] = b"OCT2";
/// The magic of a transition whose value is sealed under its own carrier
/// key (transition v3, FIX 7402): its piece fields are followed by the
/// transition wire version and the key's reference.
const MAGIC_LEAF: &[u8; 4] = b"OCT3";
const SIGNATURE_DOMAIN: &[u8] = b"oneiron/custody-transition/v3";
const VALUE_LABEL: &[u8] = b"oneiron/custody-value/v1";
const KEY_ID_LABEL: &[u8] = b"custody/v2";
const VALUE_BINDING_DOMAIN: &[u8] = b"oneiron/custody-value-binding/v2";
const DIGEST_DOMAIN: &[u8] = b"oneiron/custody-transition-digest/v3";
const VALUE_EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The codec's frame floor on a carrier's content as it was before pieces,
/// never a recipient cap nor a value's: what a single sealed envelope may
/// fill, a larger value riding in numbered envelopes (FIX 7953).
const MAX_TRANSITION_BYTES: usize = 4 << 20;
/// What a carrier's place among its transition's pieces adds: the set
/// commitment, its piece, the piece count and its first permit. They ride
/// outside [`MAX_TRANSITION_BYTES`], so no sealed value has less room than
/// before pieces.
const PIECE_FIELD_BYTES: usize = 32 + 4 + 4 + 4;
/// The largest carrier (one piece) a door writes or a receiver decodes.
pub(super) const MAX_CARRIER_BYTES: usize = MAX_TRANSITION_BYTES + PIECE_FIELD_BYTES;
/// The most sealed values one piece carries: its count is two bytes.
pub(super) const MAX_PIECE_VALUES: usize = u16::MAX as usize;
/// The most one value envelope adds to the value bytes it seals: its
/// header, its tag and the value label (FIX 7953).
pub(super) const VALUE_ENVELOPE_BYTES: usize = ONEV_HEADER_PREFIX_MAX + TAG_LEN + VALUE_LABEL.len();

impl CustodyTransition {
    /// What the signature covers: the vault and every field but the
    /// signature itself.
    pub(super) fn transcript(&self, vault_id: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + self.body.len() + 128);
        out.extend_from_slice(SIGNATURE_DOMAIN);
        out.extend_from_slice(vault_id);
        self.encode_unsigned(&mut out);
        out
    }

    fn encode_unsigned(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(if self.carrier.is_some() {
            MAGIC_LEAF
        } else {
            MAGIC
        });
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(status_byte(self.status));
        out.extend_from_slice(&self.signed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&self.input.unwrap_or([0; 32]));
        out.extend_from_slice(&self.set);
        out.extend_from_slice(&self.piece.to_be_bytes());
        out.extend_from_slice(&self.pieces.to_be_bytes());
        out.extend_from_slice(&self.first.to_be_bytes());
        if let Some(carrier) = &self.carrier {
            out.push(CUSTODY_TRANSITION_WIRE_VERSION);
            out.extend_from_slice(&carrier.encode());
        }
        put_bytes(out, &self.body);
        // Pieces are packed to at most `MAX_PIECE_VALUES` values.
        out.extend_from_slice(&(self.sealed.len() as u16).to_be_bytes());
        for (permit, envelope) in &self.sealed {
            out.extend_from_slice(permit.machine.as_bytes());
            out.extend_from_slice(&permit.profile);
            out.extend_from_slice(&permit.encryption_key);
            put_bytes(out, envelope);
        }
        out.extend_from_slice(&self.signer);
    }

    /// The digest an executor's output binding keeps of this carrier.
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(&self.encode());
        *hasher.finalize().as_bytes()
    }

    /// The permits the value is sealed under, ascending by machine, once
    /// each: a value in numbered envelopes holds its permit beside each.
    pub(crate) fn permits(&self) -> impl Iterator<Item = &CustodyRecipientPermit> + '_ {
        let mut last = None;
        self.sealed
            .iter()
            .map(|(permit, _)| permit)
            .filter(move |permit| last.replace(*permit) != Some(*permit))
    }

    /// The carrier bytes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_unsigned(&mut out);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decodes carrier bytes strictly: every length exact, nothing after the
    /// signature; a carrier key's reference only while the carrier wire is
    /// on. Decoding proves nothing; [`Self::verify`] does.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CARRIER_BYTES {
            return Err(malformed());
        }
        let mut read = Reader(bytes);
        let magic = read.take(MAGIC.len())?;
        let leafed = if magic == MAGIC {
            false
        } else if CUSTODY_CARRIER_LEAF_WIRE && magic == MAGIC_LEAF {
            true
        } else {
            return Err(malformed());
        };
        let id = EntityId::from_bytes(read.array::<16>()?)?;
        let generation = u32::from_be_bytes(read.array()?);
        let status = status_from_byte(read.array::<1>()?[0])?;
        let signed_at = u64::from_be_bytes(read.array()?);
        let request = read.array()?;
        let input = Some(read.array::<32>()?).filter(|input| *input != [0; 32]);
        let set = read.array()?;
        let piece = u32::from_be_bytes(read.array()?);
        let pieces = u32::from_be_bytes(read.array()?);
        let first = u32::from_be_bytes(read.array()?);
        let carrier = if leafed {
            if read.array::<1>()?[0] != CUSTODY_TRANSITION_WIRE_VERSION {
                return Err(malformed());
            }
            Some(CarrierRef::decode(&read.array::<CARRIER_REF_BYTES>()?).ok_or_else(malformed)?)
        } else {
            None
        };
        let body = read.bytes()?.to_vec();
        let count = usize::from(u16::from_be_bytes(read.array()?));
        // Grown as values decode: a count is not taken on trust.
        let mut sealed = Vec::new();
        for _ in 0..count {
            let permit = CustodyRecipientPermit {
                machine: EntityId::from_bytes(read.array::<16>()?)?,
                profile: read.array()?,
                encryption_key: read.array()?,
            };
            sealed.push((permit, read.bytes()?.to_vec()));
        }
        let signer = read.array()?;
        let signature = read.array()?;
        if !read.0.is_empty() {
            return Err(malformed());
        }
        Ok(Self {
            id,
            generation,
            status,
            signed_at,
            request,
            input,
            set,
            piece,
            pieces,
            first,
            carrier,
            body,
            sealed,
            signer,
            signature,
        })
    }

    /// Whether this transition is whole: signed for `vault_id` by the key it
    /// names, over a portable record that agrees with it, its value sealed
    /// exactly when it is not revoked, under permits ascending by machine,
    /// one each, each permit's envelopes together, with no zero digest, and
    /// a carrier key, when it names one, of its own record at its
    /// generation. Who signed, and for which request, is [`Self::verify`]'s
    /// question, asked where the record is written: a window keeps relaying
    /// a transition whose request this vault has not folded yet.
    pub(crate) fn verify_signed(&self, vault_id: &[u8; 32]) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.signer).map_err(|_| unsigned())?;
        key.verify_strict(
            &self.transcript(vault_id),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| unsigned())?;
        let record = decode_secret_custody_body(&self.body)?;
        if !custody_portable(&record)
            || !record.value_bytes.is_empty()
            || record.status != self.status
            || record.rotation_generation != self.generation
        {
            return Err(malformed());
        }
        let revoked = self.status == SecretCustodyStatus::Revoked;
        if revoked != self.sealed.is_empty() || !self.place_whole() {
            return Err(malformed());
        }
        let ascending = self
            .sealed
            .windows(2)
            .all(|pair| pair[0].0 == pair[1].0 || pair[0].0.machine < pair[1].0.machine);
        let zero = self
            .permits()
            .any(|permit| permit.profile == [0; 32] || permit.encryption_key == [0; 32]);
        let foreign_key = self.carrier.is_some_and(|carrier| {
            carrier.kind != CustodyKind::CustodyTransition
                || carrier.credential != self.id
                || carrier.generation != self.generation
        });
        if !ascending || zero || foreign_key {
            return Err(malformed());
        }
        Ok(())
    }

    /// The record this transition carries, value still out.
    pub(crate) fn record(&self) -> Result<SecretCustodyRecord> {
        decode_secret_custody_body(&self.body)
    }

    /// The value sealed to `machine` across `pieces`, one whole transition's
    /// pieces in order, opened with its secret under the permit it was
    /// sealed for: its one envelope, or each numbered envelope opened at its
    /// place and the runs joined in order (FIX 7953). `None` when the pieces
    /// hold no envelope for it or one does not open; what was joined is
    /// wiped.
    pub(super) fn open_value(
        pieces: &[Self],
        vault_id: &[u8; 32],
        machine: EntityId,
        secret: &HybridSecretKey,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let binding = pieces.first()?.binding();
        let held: Vec<&(CustodyRecipientPermit, Vec<u8>)> = pieces
            .iter()
            .flat_map(|piece| &piece.sealed)
            .filter(|(to, _)| to.machine == machine)
            .collect();
        let count = u32::try_from(held.len()).ok().filter(|count| *count > 0)?;
        let recipient = WrapRecipient::Machine(machine).envelope_recipient();
        // Each run is shorter than its envelope, so the joined value never
        // moves and leaves no unwiped copy behind.
        let mut value = Zeroizing::new(Vec::with_capacity(
            held.iter().map(|(_, envelope)| envelope.len()).sum(),
        ));
        for ((permit, envelope), index) in held.into_iter().zip(0_u32..) {
            let key_id = if count == 1 {
                value_key_id(&binding, permit)
            } else {
                numbered_value_key_id(&binding, permit, index, count)
            };
            let envelope = Envelope::parse(envelope).ok()?;
            let policy = OpenPolicy {
                purpose: Purpose::SecretFile,
                vault_id,
                recipient: &recipient,
                key_id: &key_id,
                wraps: &[WrapType::HybridCapsule],
                aead_suites: &[AEAD],
                kem_suites: &[KEM],
                min_epoch: VALUE_EPOCH,
                argon2_max: Argon2Cost::RFC9106_SECOND,
            };
            let payload = envelope.open(OpenKey::Hybrid(secret), &policy).ok()?;
            value.extend_from_slice(payload.strip_prefix(VALUE_LABEL)?);
        }
        Some(value)
    }

    /// What each value envelope's key id binds beside its permit.
    pub(super) fn binding(&self) -> ValueBinding {
        ValueBinding {
            id: self.id,
            generation: self.generation,
            status: self.status,
            request: self.request,
        }
    }
}

/// What a value envelope binds beside the recipient's permit: the record, its
/// generation and status, and the request the transition enacts.
#[derive(Debug, Clone, Copy)]
pub(super) struct ValueBinding {
    pub(super) id: EntityId,
    pub(super) generation: u32,
    pub(super) status: SecretCustodyStatus,
    pub(super) request: AuthorityEntryHash,
}

/// The envelopes `value` rides in to `permit`'s machine under `binding`
/// (FIX 7953): one envelope when it is at most `room` bytes, the most one
/// piece of its own carries, else numbered envelopes of `room` bytes each
/// but the last, so each rides in a piece within the frame floors. A body
/// that leaves a piece no room keeps one envelope, which the carrier floor
/// then refuses as before.
pub(super) fn split_value_envelopes(
    vault_id: &[u8; 32],
    binding: &ValueBinding,
    permit: &CustodyRecipientPermit,
    public: &HybridPublicKey,
    value: &[u8],
    room: usize,
) -> Result<Vec<Vec<u8>>> {
    if value.len() <= room || room == 0 {
        let key_id = value_key_id(binding, permit);
        return Ok(vec![seal_value(vault_id, &key_id, permit, public, value)?]);
    }
    let count = u32::try_from(value.len().div_ceil(room))
        .map_err(|_| invalid_body("a custody value seals as more envelopes than it counts"))?;
    value
        .chunks(room)
        .zip(0_u32..)
        .map(|(run, index)| {
            let key_id = numbered_value_key_id(binding, permit, index, count);
            seal_value(vault_id, &key_id, permit, public, run)
        })
        .collect()
}

/// Seals `run` of a value to `permit`'s machine as one envelope under
/// `key_id`.
fn seal_value(
    vault_id: &[u8; 32],
    key_id: &[u8],
    permit: &CustodyRecipientPermit,
    public: &HybridPublicKey,
    run: &[u8],
) -> Result<Vec<u8>> {
    let recipient = WrapRecipient::Machine(permit.machine).envelope_recipient();
    let mut payload = Zeroizing::new(Vec::with_capacity(VALUE_LABEL.len() + run.len()));
    payload.extend_from_slice(VALUE_LABEL);
    payload.extend_from_slice(run);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::SecretFile,
        epoch: VALUE_EPOCH,
        key_id,
        recipient: &recipient,
        vault_id,
    };
    seal(
        &params,
        SealKey::Hybrid {
            recipient: public,
            kem_suite: KEM,
        },
        &payload,
        &mut SysRng,
    )
    .map(|envelope| envelope.to_bytes())
    .map_err(|_| invalid_body("sealing a custody value failed"))
}

/// The envelope key id of one record's value under one binding and permit:
/// a label, then a digest of every field they hold, within the envelope's
/// 64-byte id.
fn value_key_id(binding: &ValueBinding, permit: &CustodyRecipientPermit) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(VALUE_BINDING_DOMAIN);
    hasher.update(binding.id.as_bytes());
    hasher.update(&binding.generation.to_be_bytes());
    hasher.update(&[status_byte(binding.status)]);
    hasher.update(&binding.request);
    hasher.update(permit.machine.as_bytes());
    hasher.update(&permit.profile);
    hasher.update(&permit.encryption_key);
    let mut out = Vec::with_capacity(KEY_ID_LABEL.len() + 32);
    out.extend_from_slice(KEY_ID_LABEL);
    out.extend_from_slice(hasher.finalize().as_bytes());
    out
}

/// The key id of numbered envelope `index` of `count`: the one-envelope key
/// id, then the index and the count, within the envelope's 64-byte id.
fn numbered_value_key_id(
    binding: &ValueBinding,
    permit: &CustodyRecipientPermit,
    index: u32,
    count: u32,
) -> Vec<u8> {
    let mut key_id = value_key_id(binding, permit);
    key_id.extend_from_slice(&index.to_be_bytes());
    key_id.extend_from_slice(&count.to_be_bytes());
    key_id
}

pub(super) fn status_byte(status: SecretCustodyStatus) -> u8 {
    match status {
        SecretCustodyStatus::Active => 0,
        SecretCustodyStatus::Suspended => 1,
        SecretCustodyStatus::Revoked => 2,
    }
}

fn status_from_byte(byte: u8) -> Result<SecretCustodyStatus> {
    Ok(match byte {
        0 => SecretCustodyStatus::Active,
        1 => SecretCustodyStatus::Suspended,
        2 => SecretCustodyStatus::Revoked,
        _ => return Err(malformed()),
    })
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n).ok_or_else(malformed)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("length taken"))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = u32::from_be_bytes(self.array()?);
        self.take(usize::try_from(len).map_err(|_| malformed())?)
    }
}

fn malformed() -> Error {
    invalid_body("malformed custody transition")
}

pub(super) fn unsigned() -> Error {
    invalid_body("custody transition is not signed by the owner here")
}
