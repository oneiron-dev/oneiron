//! A checkpoint's host-private member (FIX 6598): a hosted vault's
//! host-order legal-hold family, carried in its own sealed image so a cold
//! restore after the node is lost still installs it, sealed to the host's
//! recipient (the node's CUSTODY-1 hybrid key) and never to the owner, the
//! data key or a signing key. The engine seals it; the host's restore worker,
//! which alone holds the recipient's secret half, opens it with this codec.
//!
//! ```text
//! binding  "oneiron/checkpoint-host-holds/v1" ‖ engine vault id (32)
//!          ‖ snapshot id (32) ‖ recipient id (32) ‖ u64be recipient epoch
//! capsule  ONEV, hybrid X25519 + ML-KEM-1024 (0x0101) to the recipient,
//!          CheckpointHostOrderHoldsKey: binding ‖ member key (32)
//! piece*   ONEV, XChaCha20-Poly1305 under the member key,
//!          CheckpointHostOrderHolds, key id SHA-256(binding) ‖ u32be index
//!          ‖ u32be count: in order, the run binding ‖ family bytes
//! member   "ONHH" ‖ u8 1 ‖ binding ‖ u32be n ‖ capsule (n) ‖ u32be count
//!          ‖ (u32be n ‖ piece (n))*
//! ```
//!
//! The binding is sealed inside the capsule and the family both, and an
//! opener compares each with the binding it expects once it opens (an
//! envelope has no caller associated-data slot here). A piece's key id names
//! its place and the count, so no piece opens moved, dropped or added. The
//! member key is fresh per member. The recipient id is SHA-256 of the
//! recipient's public bundle exactly as it was pinned, its epoch nonzero. A
//! family of any length seals: it takes the pieces it needs.

use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::codec::Reader;
use crate::envelope::{
    Envelope, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, WrapType, seal,
};
use crate::error::{Error, Result};
use crate::keys::{Argon2Cost, HybridPublicKey, HybridSecretKey, Kek};
use crate::suite::SuiteId;

/// The binding's domain.
pub const HOST_HOLDS_DOMAIN: &[u8] = b"oneiron/checkpoint-host-holds/v1";
/// The binding's length: the domain, three ids and the epoch.
pub const HOST_HOLDS_BINDING_LEN: usize = HOST_HOLDS_DOMAIN.len() + 3 * 32 + 8;
/// The member encoding's magic.
pub const HOST_HOLDS_MAGIC: &[u8; 4] = b"ONHH";
/// The member encoding's version.
pub const HOST_HOLDS_VERSION: u8 = 1;
/// The envelope epoch a member seals and opens at.
pub const HOST_HOLDS_SEAL_EPOCH: u64 = 1;
/// The payload AEAD of the family's pieces and of the capsule.
pub const HOST_HOLDS_AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
/// The capsule's KEM.
pub const HOST_HOLDS_KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// Plaintext per piece.
const PIECE_LEN: usize = 4 << 20;

fn malformed() -> Error {
    Error::BackupMalformed("checkpoint host-holds member")
}

/// What one member is bound to: the vault, the artifact's snapshot, the
/// recipient and its epoch. A snapshot, never the image's digest, which
/// would name the member inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostHoldsBinding {
    pub engine_vault_id: [u8; 32],
    pub snapshot: [u8; 32],
    pub recipient_id: [u8; 32],
    pub recipient_epoch: u64,
}

impl HostHoldsBinding {
    /// The binding's bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HOST_HOLDS_BINDING_LEN] {
        let mut out = [0u8; HOST_HOLDS_BINDING_LEN];
        let mut at = HOST_HOLDS_DOMAIN.len();
        out[..at].copy_from_slice(HOST_HOLDS_DOMAIN);
        for id in [&self.engine_vault_id, &self.snapshot, &self.recipient_id] {
            out[at..at + 32].copy_from_slice(id);
            at += 32;
        }
        out[at..].copy_from_slice(&self.recipient_epoch.to_be_bytes());
        out
    }

    /// Reads a binding: its exact domain and length, a nonzero epoch.
    ///
    /// # Errors
    ///
    /// Any other bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.take(HOST_HOLDS_DOMAIN.len(), "host holds domain")? != HOST_HOLDS_DOMAIN {
            return Err(malformed());
        }
        let binding = Self {
            engine_vault_id: reader.array("engine vault id")?,
            snapshot: reader.array("snapshot id")?,
            recipient_id: reader.array("recipient id")?,
            recipient_epoch: reader.u64("recipient epoch")?,
        };
        reader.finish()?;
        if binding.recipient_epoch == 0 {
            return Err(malformed());
        }
        Ok(binding)
    }

    /// SHA-256 of the binding: every envelope's key id names it.
    fn digest(&self) -> [u8; 32] {
        sha256(&self.encode())
    }
}

/// A recipient's id: SHA-256 of its public bundle's exact bytes.
#[must_use]
pub fn host_holds_recipient_id(bundle: &[u8]) -> [u8; 32] {
    sha256(bundle)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// One sealed member: its binding in the clear, the member key's capsule to
/// the recipient, and the family's pieces under that key. Its `Debug` names
/// only how many pieces it has.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedHostHolds {
    binding: HostHoldsBinding,
    capsule: Vec<u8>,
    pieces: Vec<Vec<u8>>,
}

impl std::fmt::Debug for SealedHostHolds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SealedHostHolds({} pieces)", self.pieces.len())
    }
}

impl SealedHostHolds {
    /// The binding it claims, unauthenticated until it opens.
    #[must_use]
    pub fn binding(&self) -> &HostHoldsBinding {
        &self.binding
    }

    /// The member's bytes, as the image carries them.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = HOST_HOLDS_MAGIC.to_vec();
        out.push(HOST_HOLDS_VERSION);
        out.extend_from_slice(&self.binding.encode());
        put_envelope(&mut out, &self.capsule);
        out.extend_from_slice(&(self.pieces.len() as u32).to_be_bytes());
        for piece in &self.pieces {
            put_envelope(&mut out, piece);
        }
        out
    }

    /// Reads a member: its magic, version, binding and every envelope's
    /// length, nothing after the last piece. No envelope opens here.
    ///
    /// # Errors
    ///
    /// Any other bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.take(4, "host holds magic")? != HOST_HOLDS_MAGIC
            || reader.u8("host holds version")? != HOST_HOLDS_VERSION
        {
            return Err(malformed());
        }
        let binding =
            HostHoldsBinding::decode(reader.take(HOST_HOLDS_BINDING_LEN, "host holds binding")?)?;
        let capsule = take_envelope(&mut reader, "host holds capsule")?;
        let count = reader.u32("host holds pieces")?;
        let mut pieces = Vec::new();
        for _ in 0..count {
            pieces.push(take_envelope(&mut reader, "host holds piece")?);
        }
        reader.finish()?;
        if pieces.is_empty() {
            return Err(malformed());
        }
        Ok(Self {
            binding,
            capsule,
            pieces,
        })
    }
}

/// Seals `family`, the host's own serialization of its host-order family,
/// to `recipient` under `binding`: a fresh member key, its capsule, then the
/// binding and the family in ordered pieces under it. `binding.recipient_id`
/// must be the recipient's ([`host_holds_recipient_id`]); the caller checks
/// it against the bundle it was given.
///
/// # Errors
///
/// A zero epoch, a family too long to number its pieces, or a seal that
/// failed: never a weaker member.
pub fn seal_host_holds<R: TryCryptoRng + ?Sized>(
    binding: &HostHoldsBinding,
    recipient: &HybridPublicKey,
    family: &[u8],
    rng: &mut R,
) -> Result<SealedHostHolds> {
    if binding.recipient_epoch == 0 {
        return Err(malformed());
    }
    let encoded = binding.encode();
    let digest = binding.digest();
    let key = Kek::generate(rng)?;
    let mut capsule = Zeroizing::new(encoded.to_vec());
    capsule.extend_from_slice(key.expose());
    let capsule = seal(
        &params(binding, Purpose::CheckpointHostOrderHoldsKey, &digest),
        SealKey::Hybrid {
            recipient,
            kem_suite: HOST_HOLDS_KEM,
        },
        &capsule,
        rng,
    )?
    .to_bytes();
    let mut plain = Zeroizing::new(encoded.to_vec());
    plain.extend_from_slice(family);
    let count = u32::try_from(plain.len().div_ceil(PIECE_LEN)).map_err(|_| malformed())?;
    let mut pieces = Vec::with_capacity(count as usize);
    for (index, chunk) in plain.chunks(PIECE_LEN).enumerate() {
        let index = u32::try_from(index).map_err(|_| malformed())?;
        let key_id = piece_key_id(&digest, index, count);
        pieces.push(
            seal(
                &params(binding, Purpose::CheckpointHostOrderHolds, &key_id),
                SealKey::SymmetricKek(&key),
                chunk,
                rng,
            )?
            .to_bytes(),
        );
    }
    Ok(SealedHostHolds {
        binding: *binding,
        capsule,
        pieces,
    })
}

/// Opens `sealed`'s capsule with the recipient's `secret`: the member key,
/// once the binding sealed inside is `expected`, and the member's own too.
///
/// # Errors
///
/// Another binding, another recipient's capsule, or one that does not open.
pub fn open_host_holds_key(
    sealed: &SealedHostHolds,
    secret: &HybridSecretKey,
    expected: &HostHoldsBinding,
) -> Result<Kek> {
    if sealed.binding != *expected {
        return Err(malformed());
    }
    let digest = expected.digest();
    let opened = Envelope::parse(&sealed.capsule)?.open(
        OpenKey::Hybrid(secret),
        &policy(
            expected,
            Purpose::CheckpointHostOrderHoldsKey,
            &digest,
            &[WrapType::HybridCapsule],
        ),
    )?;
    let (bound, key) = opened
        .split_at_checked(HOST_HOLDS_BINDING_LEN)
        .ok_or_else(malformed)?;
    let key: &[u8; 32] = key.try_into().map_err(|_| malformed())?;
    if bound != expected.encode() {
        return Err(malformed());
    }
    Ok(Kek::from_bytes_ref(key))
}

/// Opens `sealed`'s pieces with the member `key` the capsule held: the
/// family's bytes, once every piece opened in its place and the binding
/// they carry is `expected`.
///
/// # Errors
///
/// Another binding, a piece missing, moved or added, or one that does not
/// open.
pub fn open_host_holds_family(
    sealed: &SealedHostHolds,
    key: &Kek,
    expected: &HostHoldsBinding,
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.binding != *expected {
        return Err(malformed());
    }
    let digest = expected.digest();
    let count = u32::try_from(sealed.pieces.len()).map_err(|_| malformed())?;
    let mut plain = Zeroizing::new(Vec::new());
    for (index, piece) in sealed.pieces.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| malformed())?;
        let key_id = piece_key_id(&digest, index, count);
        let opened = Envelope::parse(piece)?.open(
            OpenKey::SymmetricKek(key),
            &policy(
                expected,
                Purpose::CheckpointHostOrderHolds,
                &key_id,
                &[WrapType::SymmetricKek],
            ),
        )?;
        plain.extend_from_slice(&opened);
    }
    let bound = plain
        .get(..HOST_HOLDS_BINDING_LEN)
        .ok_or_else(malformed)?;
    if bound != expected.encode() {
        return Err(malformed());
    }
    Ok(Zeroizing::new(plain[HOST_HOLDS_BINDING_LEN..].to_vec()))
}

/// Appends `u32be len ‖ envelope`. An envelope is at most the plaintext
/// bound plus its header, well under `u32::MAX`.
fn put_envelope(out: &mut Vec<u8>, envelope: &[u8]) {
    out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    out.extend_from_slice(envelope);
}

/// Reads one `u32be len ‖ envelope`, never an empty one.
fn take_envelope(reader: &mut Reader<'_>, field: &'static str) -> Result<Vec<u8>> {
    let len = reader.u32(field)? as usize;
    if len == 0 {
        return Err(malformed());
    }
    Ok(reader.take(len, field)?.to_vec())
}

fn piece_key_id(digest: &[u8; 32], index: u32, count: u32) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..32].copy_from_slice(digest);
    out[32..36].copy_from_slice(&index.to_be_bytes());
    out[36..].copy_from_slice(&count.to_be_bytes());
    out
}

fn params<'a>(
    binding: &'a HostHoldsBinding,
    purpose: Purpose,
    key_id: &'a [u8],
) -> SealParams<'a> {
    SealParams {
        suite: HOST_HOLDS_AEAD,
        purpose,
        epoch: HOST_HOLDS_SEAL_EPOCH,
        key_id,
        recipient: &binding.recipient_id,
        vault_id: &binding.engine_vault_id,
    }
}

fn policy<'a>(
    binding: &'a HostHoldsBinding,
    purpose: Purpose,
    key_id: &'a [u8],
    wraps: &'a [WrapType],
) -> OpenPolicy<'a> {
    OpenPolicy {
        purpose,
        vault_id: &binding.engine_vault_id,
        recipient: &binding.recipient_id,
        key_id,
        wraps,
        aead_suites: &[HOST_HOLDS_AEAD],
        kem_suites: &[HOST_HOLDS_KEM],
        min_epoch: HOST_HOLDS_SEAL_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    }
}
