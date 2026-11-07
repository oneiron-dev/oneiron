//! Public-recipient encryption for host-private, per-order legal clones.
//!
//! The collector holds only the host order's public key. The host owns the
//! private seed, its separate keystore namespace and its deletion. These APIs
//! provide neither capture authority nor custody, persistence or deletion proof.
//! Sources are the gate ledger and its sidecars, or one exact live session.
//!
//! Content, encrypted descriptors and the encrypted final summary have separate
//! bindings. Raw source identities and fingerprints are not serialized in clear
//! envelope headers. The host opens descriptors from the known capture and member
//! ordinal, then uses their encrypted fields to open the content chunks. It must
//! verify the streamed component lengths, counts and whole-component digests and
//! the final descriptor commitment before it reports a complete capture.

use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::{
    Argon2Cost, Envelope, Error, HybridPublicKey, HybridSecretKey, OpenKey, OpenPolicy, Purpose,
    Result, SealKey, SealParams, SuiteId, WrapType, seal_with_aad,
};

/// Pinned derivation label for the host's 32-byte, per-order keystore seed.
/// Only the host calls `HybridSecretKey::from_seed`; the collector gets its public key.
pub const KEY_LABEL: &[u8] = b"oneiron/host-legal-clone/order-key/v1";

const DOMAIN: &[u8] = b"oneiron/host-legal-clone/binding/v1\0";
const FAMILY: u8 = 1;
const EPOCH: u64 = 1;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;

/// One immutable capture within an order generation. The source vault is the
/// actual capture store's physical identity, not an authority genesis or a
/// request body's assertion.
#[derive(Clone, Copy)]
pub struct CaptureBinding {
    pub order: [u8; 16],
    pub source_vault: [u8; 32],
    pub generation: u64,
    pub capture: [u8; 16],
    /// Digest of the whole actual accepted capture request, not a selected subset.
    pub request_digest: [u8; 32],
}

/// The closed source components. The descriptor keeps the actual
/// raw key; its digest in a content binding is made from the native family label
/// and the length-framed key by the source-owning collector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SourceComponent {
    StoredLedger = 1,
    OpenedMessagePack = 2,
    RetentionContext = 3,
    BundleRefs = 4,
    PendingScrub = 5,
    LiveSessionBody = 6,
    LiveSessionMetadata = 7,
    /// A stored MESSAGE entity's exact row.
    MessageRow = 8,
    /// One exact stored row of that message's document: its head, a slot row
    /// or one update.
    MessageDocument = 9,
    /// One exact stored outgoing edge row of that message.
    MessageEdge = 10,
    /// The exact result body that message's result attachment names and
    /// the message still holds. Its revision is the BLAKE3 of that
    /// message's full stored entity row, the revision of its `MessageRow`;
    /// its source key is the stored raw-output key of the attachment's
    /// handle; its fingerprint and length are the whole body's.
    MessageResultBody = 11,
    /// One exact stored row of that message's revision ledger: the retained
    /// history document of its earlier stored rows, its revision state, one
    /// retained frontier, or one frontier's reverse identity. Its revision
    /// is the BLAKE3 of that message's full stored entity row, the revision
    /// of its `MessageRow`.
    MessageRevision = 12,
}

impl SourceComponent {
    /// Decodes the closed component tag from an opened descriptor.
    pub fn from_wire(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::StoredLedger),
            2 => Ok(Self::OpenedMessagePack),
            3 => Ok(Self::RetentionContext),
            4 => Ok(Self::BundleRefs),
            5 => Ok(Self::PendingScrub),
            6 => Ok(Self::LiveSessionBody),
            7 => Ok(Self::LiveSessionMetadata),
            8 => Ok(Self::MessageRow),
            9 => Ok(Self::MessageDocument),
            10 => Ok(Self::MessageEdge),
            11 => Ok(Self::MessageResultBody),
            12 => Ok(Self::MessageRevision),
            _ => Err(Error::NonCanonical),
        }
    }
}

/// Exact source identity within one immutable capture. The live-session digest
/// binds the registry's exact reference string; its instance is minted once for
/// that session, not derived from a timestamp. Neither field grants authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentSource {
    GateDecision([u8; 16]),
    LiveSession {
        session_ref_digest: [u8; 32],
        instance: [u8; 16],
    },
    /// One stored on-record MESSAGE entity, by its id.
    Message([u8; 16]),
}

/// Hashes the registry's exact UTF-8 session reference without normalization.
/// The actual reference and instance remain inside the encrypted descriptor.
pub fn live_session_ref_digest(session_ref: &str) -> [u8; 32] {
    let bytes = session_ref.as_bytes();
    let mut hasher = blake3::Hasher::new_derive_key("oneiron/host-legal-clone/live-session-ref/v1");
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// One content chunk's exact source and place. `plaintext_fingerprint` covers
/// the whole component, not this chunk alone; the streaming reader checks it
/// after all the component's chunks have opened.
#[derive(Clone, Copy)]
pub struct ContentBinding {
    pub capture: CaptureBinding,
    pub member_ordinal: u64,
    pub component: SourceComponent,
    pub source: ContentSource,
    pub source_key_digest: [u8; 32],
    pub revision: [u8; 32],
    pub plaintext_fingerprint: [u8; 32],
    pub chunk_index: u64,
    pub chunk_count: u64,
}

#[derive(Clone, Copy)]
enum Role {
    Content = 1,
    Descriptor = 2,
    Summary = 3,
}

impl Role {
    fn recipient(self) -> &'static [u8] {
        match self {
            Self::Content => b"oneiron/legal-clone/content/v1",
            Self::Descriptor => b"oneiron/legal-clone/descriptor/v1",
            Self::Summary => b"oneiron/legal-clone/summary/v1",
        }
    }
}

impl CaptureBinding {
    fn scope(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(DOMAIN.to_vec());
        out.push(FAMILY);
        out.extend_from_slice(&self.order);
        out.extend_from_slice(&self.source_vault);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.capture);
        out.extend_from_slice(&self.request_digest);
        out
    }

    fn aad(&self, role: Role, member_ordinal: u64) -> Zeroizing<Vec<u8>> {
        let mut out = self.scope();
        out.push(role as u8);
        out.extend_from_slice(&member_ordinal.to_be_bytes());
        out
    }
}

impl ContentBinding {
    fn aad(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.chunk_count == 0 || self.chunk_index >= self.chunk_count {
            return Err(Error::NonCanonical);
        }
        let mut out = self.capture.aad(Role::Content, self.member_ordinal);
        out.push(self.component as u8);
        match self.source {
            ContentSource::GateDecision(decision) => {
                out.push(1);
                out.extend_from_slice(&decision);
            }
            ContentSource::LiveSession {
                session_ref_digest,
                instance,
            } => {
                out.push(2);
                out.extend_from_slice(&session_ref_digest);
                out.extend_from_slice(&instance);
            }
            ContentSource::Message(message) => {
                out.push(3);
                out.extend_from_slice(&message);
            }
        }
        out.extend_from_slice(&self.source_key_digest);
        out.extend_from_slice(&self.revision);
        out.extend_from_slice(&self.plaintext_fingerprint);
        out.extend_from_slice(&self.chunk_index.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        Ok(out)
    }
}

/// Seals one content chunk to the host order's public key. The existing envelope
/// plaintext geometry applies; there is no record-size limit here.
pub fn seal_content<R: TryCryptoRng + ?Sized>(
    public: &HybridPublicKey,
    binding: &ContentBinding,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Envelope> {
    let aad = binding.aad()?;
    seal_bound(
        public,
        &binding.capture,
        Role::Content,
        aad.as_slice(),
        plaintext,
        rng,
    )
}

/// Opens one exact content chunk using only the host order's private key.
pub fn open_content(
    secret: &HybridSecretKey,
    binding: &ContentBinding,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let aad = binding.aad()?;
    open_bound(
        secret,
        &binding.capture,
        Role::Content,
        aad.as_slice(),
        sealed,
    )
}

/// Encrypts one source descriptor before its content chunks. Its raw key,
/// revision, fingerprint and geometry belong inside `plaintext`, not the header.
pub fn seal_descriptor<R: TryCryptoRng + ?Sized>(
    public: &HybridPublicKey,
    capture: &CaptureBinding,
    member_ordinal: u64,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Envelope> {
    let aad = capture.aad(Role::Descriptor, member_ordinal);
    seal_bound(
        public,
        capture,
        Role::Descriptor,
        aad.as_slice(),
        plaintext,
        rng,
    )
}

/// Opens a descriptor using only the known capture and its member ordinal, so
/// no source fingerprint or other encrypted descriptor field is needed first.
pub fn open_descriptor(
    secret: &HybridSecretKey,
    capture: &CaptureBinding,
    member_ordinal: u64,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let aad = capture.aad(Role::Descriptor, member_ordinal);
    open_bound(secret, capture, Role::Descriptor, aad.as_slice(), sealed)
}

/// Encrypts the one final summary of the immutable capture. Counts and the
/// streamed descriptor commitment are part of its encrypted plaintext.
pub fn seal_summary<R: TryCryptoRng + ?Sized>(
    public: &HybridPublicKey,
    capture: &CaptureBinding,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Envelope> {
    let aad = capture.aad(Role::Summary, 0);
    seal_bound(
        public,
        capture,
        Role::Summary,
        aad.as_slice(),
        plaintext,
        rng,
    )
}

/// Opens the capture's final encrypted summary, never a content or descriptor
/// envelope. The consuming reader checks its counts and descriptor commitment.
pub fn open_summary(
    secret: &HybridSecretKey,
    capture: &CaptureBinding,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let aad = capture.aad(Role::Summary, 0);
    open_bound(secret, capture, Role::Summary, aad.as_slice(), sealed)
}

fn seal_bound<R: TryCryptoRng + ?Sized>(
    public: &HybridPublicKey,
    capture: &CaptureBinding,
    role: Role,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Envelope> {
    let namespace = blake3::hash(capture.scope().as_slice());
    let key_id = blake3::hash(aad);
    seal_with_aad(
        &SealParams {
            suite: AEAD,
            purpose: Purpose::LegalClone,
            epoch: EPOCH,
            key_id: key_id.as_bytes(),
            recipient: role.recipient(),
            vault_id: namespace.as_bytes(),
        },
        SealKey::Hybrid {
            recipient: public,
            kem_suite: KEM,
        },
        plaintext,
        aad,
        rng,
    )
}

fn open_bound(
    secret: &HybridSecretKey,
    capture: &CaptureBinding,
    role: Role,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let namespace = blake3::hash(capture.scope().as_slice());
    let key_id = blake3::hash(aad);
    Envelope::parse(sealed)?.open_with_aad(
        OpenKey::Hybrid(secret),
        &OpenPolicy {
            purpose: Purpose::LegalClone,
            vault_id: namespace.as_bytes(),
            recipient: role.recipient(),
            key_id: key_id.as_bytes(),
            wraps: &[WrapType::HybridCapsule],
            aead_suites: &[AEAD],
            kem_suites: &[KEM],
            min_epoch: EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        },
        aad,
    )
}
