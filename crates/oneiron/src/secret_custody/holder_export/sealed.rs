//! The bytes of a sealed export secret supplement (FIX 4624(b)): the
//! archive row of one custody secret, sealed by its holder to the one
//! recipient machine the owner chose.
//!
//! A supplement is `OXS1`, the envelope count (`u32be`), then each envelope
//! as its length (`u32be`) and its bytes: one envelope, or one per chunk of a
//! row larger than one envelope seals ([`MAX_PLAINTEXT_LEN`]), never refused
//! for its size. Each envelope is an `ExportBundle` hybrid capsule to the
//! recipient machine; its key id binds the request, the export, the secret
//! and its generation, the owner and the recipient's exact permit, and its
//! extra associated data its place among the envelopes, so no envelope opens
//! for another request, recipient or position.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, MAX_PLAINTEXT_LEN, OpenKey,
    OpenPolicy, Purpose, SealKey, SealParams, SuiteId, WrapType, seal_with_aad,
};
use zeroize::Zeroizing;

use crate::authority::{
    AuthorityEntryHash, CustodyRecipientPermit, SealedWorkOutput, WrapRecipient,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

const MAGIC: &[u8; 4] = b"OXS1";
const KEY_ID_LABEL: &[u8] = b"export-secret/v1";
const BINDING_DOMAIN: &[u8] = b"oneiron/export-secret-binding/v1";
const POSITION_DOMAIN: &[u8] = b"oneiron/export-secret-position/v1";
const EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;

/// What every envelope of one supplement binds.
#[derive(Debug, Clone, Copy)]
pub(super) struct SupplementBinding {
    pub(super) request: AuthorityEntryHash,
    pub(super) export: EntityId,
    pub(super) secret: EntityId,
    pub(super) generation: u32,
    pub(super) owner: EntityId,
    pub(super) recipient: CustodyRecipientPermit,
}

impl SupplementBinding {
    /// The envelope key id: a label, then a digest of every field bound.
    fn key_id(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BINDING_DOMAIN);
        hasher.update(&self.request);
        hasher.update(self.export.as_bytes());
        hasher.update(self.secret.as_bytes());
        hasher.update(&self.generation.to_be_bytes());
        hasher.update(self.owner.as_bytes());
        hasher.update(self.recipient.machine.as_bytes());
        hasher.update(&self.recipient.profile);
        hasher.update(&self.recipient.encryption_key);
        let mut out = Vec::with_capacity(KEY_ID_LABEL.len() + 32);
        out.extend_from_slice(KEY_ID_LABEL);
        out.extend_from_slice(hasher.finalize().as_bytes());
        out
    }
}

/// The extra associated data of envelope `index` of `count`.
fn position_aad(index: u32, count: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(POSITION_DOMAIN.len() + 8);
    aad.extend_from_slice(POSITION_DOMAIN);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&count.to_be_bytes());
    aad
}

fn malformed() -> Error {
    Error::InvalidConfig("this export secret supplement is malformed".to_owned())
}

/// Seals `plaintext` to `public`, the recipient's key, under `binding` for
/// vault `vault_id`, in as many envelopes as it needs: the supplement's
/// bytes and their count.
pub(super) fn seal_supplement(
    vault_id: &[u8; 32],
    binding: &SupplementBinding,
    public: &HybridPublicKey,
    plaintext: &[u8],
) -> Result<(Vec<u8>, u32)> {
    let key_id = binding.key_id();
    let recipient = WrapRecipient::Machine(binding.recipient.machine).envelope_recipient();
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![plaintext]
    } else {
        plaintext.chunks(MAX_PLAINTEXT_LEN).collect()
    };
    let count = u32::try_from(chunks.len()).map_err(|_| malformed())?;
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::ExportBundle,
        epoch: EPOCH,
        key_id: &key_id,
        recipient: &recipient,
        vault_id,
    };
    let mut out = Vec::with_capacity(MAGIC.len() + 4 + plaintext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&count.to_be_bytes());
    for (index, chunk) in (0..count).zip(chunks) {
        let envelope = seal_with_aad(
            &params,
            SealKey::Hybrid {
                recipient: public,
                kem_suite: KEM,
            },
            chunk,
            &position_aad(index, count),
            &mut SysRng,
        )
        .map_err(|_| Error::InvalidConfig("sealing an export secret failed".to_owned()))?
        .to_bytes();
        let len = u32::try_from(envelope.len()).map_err(|_| malformed())?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&envelope);
    }
    Ok((out, count))
}

/// The envelopes of `sealed`, each as its bytes.
fn envelopes(sealed: &[u8]) -> Result<Vec<&[u8]>> {
    let rest = sealed.strip_prefix(MAGIC).ok_or_else(malformed)?;
    let (count, mut rest) = rest.split_first_chunk::<4>().ok_or_else(malformed)?;
    let count = u32::from_be_bytes(*count);
    let mut out = Vec::new();
    for _ in 0..count {
        let (len, tail) = rest.split_first_chunk::<4>().ok_or_else(malformed)?;
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| malformed())?;
        let (envelope, tail) = tail.split_at_checked(len).ok_or_else(malformed)?;
        out.push(envelope);
        rest = tail;
    }
    if !rest.is_empty() || out.is_empty() {
        return Err(malformed());
    }
    Ok(out)
}

/// What a signed result names of `sealed`: its digest, length and envelope
/// count.
pub(super) fn output_of(sealed: &[u8]) -> Result<SealedWorkOutput> {
    Ok(SealedWorkOutput {
        digest: *blake3::hash(sealed).as_bytes(),
        bytes: u64::try_from(sealed.len()).map_err(|_| malformed())?,
        envelopes: u32::try_from(envelopes(sealed)?.len()).map_err(|_| malformed())?,
    })
}

/// Opens `sealed` with `secret`, the recipient's own, under `binding` for
/// vault `vault_id`: every envelope in its place, joined.
pub(super) fn open_supplement(
    vault_id: &[u8; 32],
    binding: &SupplementBinding,
    secret: &HybridSecretKey,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key_id = binding.key_id();
    let recipient = WrapRecipient::Machine(binding.recipient.machine).envelope_recipient();
    let policy = OpenPolicy {
        purpose: Purpose::ExportBundle,
        vault_id,
        recipient: &recipient,
        key_id: &key_id,
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let envelopes = envelopes(sealed)?;
    let count = u32::try_from(envelopes.len()).map_err(|_| malformed())?;
    let mut plain = Zeroizing::new(Vec::new());
    for (index, bytes) in (0..count).zip(envelopes) {
        let chunk = Envelope::parse(bytes)
            .and_then(|envelope| {
                envelope.open_with_aad(
                    OpenKey::Hybrid(secret),
                    &policy,
                    &position_aad(index, count),
                )
            })
            .map_err(|_| {
                Error::InvalidConfig(
                    "this export secret supplement does not open here: it is sealed to another \
                     machine, request or position"
                        .to_owned(),
                )
            })?;
        plain.extend_from_slice(&chunk);
    }
    Ok(plain)
}
