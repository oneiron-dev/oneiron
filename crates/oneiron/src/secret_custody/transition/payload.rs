//! The bytes of a custody transition: its strict codec, the transcript its
//! signature covers, and the value sealed to one machine and opened there.
//! Who may sign one, and what a vault does with one, stay in the parent.

use ed25519_dalek::{Signature, VerifyingKey};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, OpenKey, OpenPolicy, Purpose, SealKey,
    SealParams, SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use super::super::codec::{decode_secret_custody_body, invalid_body};
use super::super::types::{SecretCustodyRecord, SecretCustodyStatus};
use super::{CustodyTransition, custody_portable};
use crate::authority::WrapRecipient;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

const MAGIC: &[u8; 4] = b"OCT1";
const SIGNATURE_DOMAIN: &[u8] = b"oneiron/custody-transition/v1";
const VALUE_LABEL: &[u8] = b"oneiron/custody-value/v1";
const KEY_ID_LABEL: &[u8] = b"custody";
const VALUE_EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The largest transition a door writes or a receiver decodes.
pub(crate) const MAX_TRANSITION_BYTES: usize = 4 << 20;
/// The most machines one transition seals the value to.
pub(super) const MAX_RECIPIENTS: usize = 64;

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
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(status_byte(self.status));
        out.extend_from_slice(&self.signed_at.to_be_bytes());
        put_bytes(out, &self.body);
        out.extend_from_slice(&(self.sealed.len() as u16).to_be_bytes());
        for (machine, envelope) in &self.sealed {
            out.extend_from_slice(machine.as_bytes());
            put_bytes(out, envelope);
        }
        out.extend_from_slice(&self.signer);
    }

    /// The carrier bytes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_unsigned(&mut out);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decodes carrier bytes strictly: every length exact, nothing after the
    /// signature. Decoding proves nothing; [`Self::verify`] does.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TRANSITION_BYTES {
            return Err(malformed());
        }
        let mut read = Reader(bytes);
        if read.take(MAGIC.len())? != MAGIC {
            return Err(malformed());
        }
        let id = EntityId::from_bytes(read.array::<16>()?)?;
        let generation = u32::from_be_bytes(read.array()?);
        let status = status_from_byte(read.array::<1>()?[0])?;
        let signed_at = u64::from_be_bytes(read.array()?);
        let body = read.bytes()?.to_vec();
        let count = usize::from(u16::from_be_bytes(read.array()?));
        if count > MAX_RECIPIENTS {
            return Err(malformed());
        }
        let mut sealed = Vec::with_capacity(count);
        for _ in 0..count {
            let machine = EntityId::from_bytes(read.array::<16>()?)?;
            sealed.push((machine, read.bytes()?.to_vec()));
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
            body,
            sealed,
            signer,
            signature,
        })
    }

    /// Whether this transition is whole: signed for `vault_id` by the key it
    /// names, over a portable record that agrees with it, its value sealed to
    /// distinct machines exactly when it is not revoked. Who signed is
    /// [`Self::verify`]'s question, asked where the record is written: a
    /// window keeps relaying a transition whose signer the roster later
    /// drops.
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
        if revoked != self.sealed.is_empty() {
            return Err(malformed());
        }
        let mut machines: Vec<_> = self.sealed.iter().map(|(machine, _)| *machine).collect();
        machines.sort_unstable();
        machines.dedup();
        if machines.len() != self.sealed.len() {
            return Err(malformed());
        }
        Ok(())
    }

    /// The record this transition carries, value still out.
    pub(crate) fn record(&self) -> Result<SecretCustodyRecord> {
        decode_secret_custody_body(&self.body)
    }

    /// The value sealed to `machine`, opened with its secret. `None` when the
    /// transition holds no envelope for it or the envelope does not open.
    pub(crate) fn open_value(
        &self,
        vault_id: &[u8; 32],
        machine: EntityId,
        secret: &HybridSecretKey,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let (_, envelope) = self.sealed.iter().find(|(to, _)| *to == machine)?;
        let envelope = Envelope::parse(envelope).ok()?;
        let key_id = value_key_id(self.id, self.generation);
        let recipient = WrapRecipient::Machine(machine).envelope_recipient();
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
        let value = payload.strip_prefix(VALUE_LABEL)?;
        Some(Zeroizing::new(value.to_vec()))
    }
}

pub(super) fn seal_value(
    vault_id: &[u8; 32],
    id: EntityId,
    generation: u32,
    machine: EntityId,
    public: &HybridPublicKey,
    value: &[u8],
) -> Result<Vec<u8>> {
    let key_id = value_key_id(id, generation);
    let recipient = WrapRecipient::Machine(machine).envelope_recipient();
    let mut payload = Zeroizing::new(Vec::with_capacity(VALUE_LABEL.len() + value.len()));
    payload.extend_from_slice(VALUE_LABEL);
    payload.extend_from_slice(value);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::SecretFile,
        epoch: VALUE_EPOCH,
        key_id: &key_id,
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

/// The envelope key id of one record's value at one generation.
fn value_key_id(id: EntityId, generation: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_ID_LABEL.len() + 20);
    out.extend_from_slice(KEY_ID_LABEL);
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    out
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
