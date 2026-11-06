//! The keyless custody log (KS-4, FIX 5685) and the local journal it is kept
//! in, beside the vault and outside its image like every custody entry.
//!
//! Every mint and every retirement of a bound custody is journaled as one
//! frame, synced before the act it records is acknowledged: a mint before a
//! row sealed under its key may commit, a retirement before its intent
//! clears. A frame binds the vault, the namespace, the writer epoch, its
//! sequence number and the hash of the frame before it; its body names the
//! id it mints or the subject it retires through a generation, with the
//! cause, or the released escrow recipient a cold managed restore retired
//! (its label and the BLAKE3 of its public key), sealed under the lineage's
//! log key. No frame, error or receipt holds a key, a key's fingerprint, a
//! value or a wrap; the frame hashes are public structure, never a
//! fingerprint of a secret.
//!
//! `<compartment>/.journal/` holds `control` (the lineage's control secret,
//! its writer epoch and the position its local log starts after), `tip` (a
//! cache of the newest frame's position) and one `f<seq hex16>` per frame.

use std::path::PathBuf;

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal,
};
use zeroize::Zeroizing;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::identity::CustodyId;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodyNamespace;
use crate::key_custody::identity::CustodySubject;
use crate::key_custody::identity::CustodyVaultId;

pub const JOURNAL: &str = ".journal";
pub const CONTROL: &str = "control";
pub const TIP: &str = "tip";
const CONTROL_VERSION: u8 = 1;
const CONTROL_LEN: usize = 1 + 32 + 8 + 8 + 32;
const FRAME_MAGIC: &[u8; 4] = b"OCLF";
const FRAME_VERSION: u8 = 1;
/// `magic | version | vault | namespace | epoch | seq | previous hash`.
const FRAME_HEADER_LEN: usize = 4 + 1 + 32 + 16 + 8 + 8 + 32;
pub const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
/// The crypto epoch every custody envelope is sealed at.
pub const CRYPTO_EPOCH: u64 = 1;
const LOG_KEY_CONTEXT: &str = "oneiron/custody-log/v1";
const ANCHOR_KEY_CONTEXT: &str = "oneiron/custody-anchor/v1";
pub const LOG_KEY_ID: &[u8] = b"oneiron/custody-log-frame/v1";
/// The derive-key context of a frame's envelope recipient
/// ([`frame_recipient`]).
const FRAME_RECIPIENT_CONTEXT: &str = "oneiron/custody-log-frame/recipient/v1";
pub const OP_MINT: u8 = 1;
pub const OP_RETIRE: u8 = 2;
/// A released escrow recipient retired (LC FIX 5384/5385): an op of its
/// own, never a custody kind's tag.
pub const OP_RETIRE_RECIPIENT: u8 = 3;
/// A change of the publication policy heads are sealed under (KS-5, FIX
/// 7191): content-free, an op of its own.
pub const OP_PUBLICATION_POLICY: u8 = 4;
/// History rows a writer is about to commit (FIX 6229): ids only, an op of
/// its own.
pub const OP_BODY_HISTORY: u8 = 5;
/// An erased credential's value-free fact (FIX 10584 item 3): its id and
/// where its erase stands, never a key; an op of its own.
pub const OP_ERASE_EVIDENCE: u8 = 6;
/// A holder debt recorded or cleared (FIX 11206): a key's ref and the
/// holder machine, never a key; an op of its own.
pub const OP_HOLDER_DEBT: u8 = 7;

pub fn log_corrupt() -> Error {
    Error::CorruptedIndex("key custody log")
}

/// A lineage's writer epoch. A disaster recovery takes the lineage over at
/// the next one and advances the anchor to it, which fences every writer
/// still at an older one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CustodyEpoch(pub u64);

impl CustodyEpoch {
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Where one lineage's log stands: its vault and namespace, the writer
/// epoch, the newest frame's sequence number and that frame's hash. An empty
/// log is sequence 0 under an all-zero tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyPosition {
    pub vault: CustodyVaultId,
    pub namespace: CustodyNamespace,
    pub epoch: CustodyEpoch,
    pub seq: u64,
    pub tip: [u8; 32],
}

/// `vault (32) | namespace (16) | epoch u64be | seq u64be | tip (32)`.
pub const POSITION_LEN: usize = 32 + 16 + 8 + 8 + 32;

impl CustodyPosition {
    /// The 96-byte wire form an anchor record and a manifest carry.
    pub fn to_bytes(self) -> [u8; POSITION_LEN] {
        let mut out = [0u8; POSITION_LEN];
        out[..32].copy_from_slice(self.vault.as_bytes());
        out[32..48].copy_from_slice(self.namespace.as_bytes());
        out[48..56].copy_from_slice(&self.epoch.0.to_be_bytes());
        out[56..64].copy_from_slice(&self.seq.to_be_bytes());
        out[64..].copy_from_slice(&self.tip);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != POSITION_LEN {
            return None;
        }
        Some(Self {
            vault: CustodyVaultId::from_bytes(bytes[..32].try_into().ok()?),
            namespace: CustodyNamespace::from_bytes(bytes[32..48].try_into().ok()?),
            epoch: CustodyEpoch(u64::from_be_bytes(bytes[48..56].try_into().ok()?)),
            seq: u64::from_be_bytes(bytes[56..64].try_into().ok()?),
            tip: bytes[64..].try_into().ok()?,
        })
    }

    /// The same lineage, vault and namespace both.
    pub fn same_lineage(&self, other: &Self) -> bool {
        self.vault == other.vault && self.namespace == other.namespace
    }
}

/// One lineage's control state: the secret its log key and anchor key come
/// from, its writer epoch here, and the position its local log starts after
/// (none for a lineage begun here; the admitted head's for one a disaster
/// recovery took over). Its secret is carried in every head's control
/// compartment, never in a frame.
pub struct Control {
    pub secret: Zeroizing<[u8; 32]>,
    pub epoch: CustodyEpoch,
    pub base_seq: u64,
    pub base_tip: [u8; 32],
}

impl Control {
    pub fn fresh() -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; 32]);
        crate::key_material::os_fill(&mut secret[..])?;
        Ok(Self {
            secret,
            epoch: CustodyEpoch(0),
            base_seq: 0,
            base_tip: [0; 32],
        })
    }

    /// The control state of a lineage a disaster recovery takes over at
    /// `from`, the admitted position, in the next writer epoch.
    pub fn taken_over(secret: Zeroizing<[u8; 32]>, from: &CustodyPosition) -> Result<Self> {
        Ok(Self {
            secret,
            epoch: CustodyEpoch(
                from.epoch
                    .0
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow("key custody writer epoch"))?,
            ),
            base_seq: from.seq,
            base_tip: from.tip,
        })
    }

    /// The control state a restore opens a lineage's frames and anchor
    /// records with: the secret its head carries. Its epoch and base are
    /// not the restore's to know.
    pub fn for_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        Self {
            secret,
            epoch: CustodyEpoch(0),
            base_seq: 0,
            base_tip: [0; 32],
        }
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// The position the local log starts after: none (0) for a lineage
    /// begun here, the admitted head's for one taken over.
    pub fn base_seq(&self) -> u64 {
        self.base_seq
    }

    /// The tip of the position the local log starts after.
    pub fn base_tip(&self) -> [u8; 32] {
        self.base_tip
    }

    pub fn derive(&self, context: &str) -> Zeroizing<[u8; 32]> {
        crate::key_material::derive_guarded(context, &[&self.secret[..]])
    }

    pub fn log_kek(&self) -> Kek {
        Kek::from_zeroizing(self.derive(LOG_KEY_CONTEXT))
    }

    /// The key the lineage's anchor records are authenticated under.
    pub fn anchor_key(&self) -> Zeroizing<[u8; 32]> {
        self.derive(ANCHOR_KEY_CONTEXT)
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(CONTROL_LEN));
        out.push(CONTROL_VERSION);
        out.extend_from_slice(&self.secret[..]);
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&self.base_seq.to_be_bytes());
        out.extend_from_slice(&self.base_tip);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CONTROL_LEN || bytes[0] != CONTROL_VERSION {
            return Err(log_corrupt());
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&bytes[1..33]);
        let word = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
        Ok(Self {
            secret,
            epoch: CustodyEpoch(word(33)),
            base_seq: word(41),
            base_tip: bytes[49..81].try_into().map_err(|_| log_corrupt())?,
        })
    }
}

/// A frame's clear header: what a shipper checks continuity by, keyless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub vault: CustodyVaultId,
    pub namespace: CustodyNamespace,
    pub epoch: CustodyEpoch,
    pub seq: u64,
    pub prev: [u8; 32],
}

impl FrameHeader {
    pub fn to_bytes(self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[..4].copy_from_slice(FRAME_MAGIC);
        out[4] = FRAME_VERSION;
        out[5..37].copy_from_slice(self.vault.as_bytes());
        out[37..53].copy_from_slice(self.namespace.as_bytes());
        out[53..61].copy_from_slice(&self.epoch.0.to_be_bytes());
        out[61..69].copy_from_slice(&self.seq.to_be_bytes());
        out[69..].copy_from_slice(&self.prev);
        out
    }

    /// The header of `frame`, with its body's envelope bytes; refused when
    /// the frame does not parse.
    pub fn parse(frame: &[u8]) -> Result<(Self, &[u8])> {
        let parsed = (|| {
            let head = frame.get(..FRAME_HEADER_LEN)?;
            if &head[..4] != FRAME_MAGIC || head[4] != FRAME_VERSION {
                return None;
            }
            let len = u32::from_be_bytes(
                frame
                    .get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + 4)?
                    .try_into()
                    .ok()?,
            );
            let body = frame.get(FRAME_HEADER_LEN + 4..)?;
            if body.len() != usize::try_from(len).ok()? {
                return None;
            }
            Some((
                Self {
                    vault: CustodyVaultId::from_bytes(head[5..37].try_into().ok()?),
                    namespace: CustodyNamespace::from_bytes(head[37..53].try_into().ok()?),
                    epoch: CustodyEpoch(u64::from_be_bytes(head[53..61].try_into().ok()?)),
                    seq: u64::from_be_bytes(head[61..69].try_into().ok()?),
                    prev: head[69..].try_into().ok()?,
                },
                body,
            ))
        })();
        parsed.ok_or_else(log_corrupt)
    }
}

/// A frame's hash: what the next frame and a position name it by.
pub fn frame_hash(frame: &[u8]) -> [u8; 32] {
    *blake3::hash(frame).as_bytes()
}

/// Seals `plaintext` under `kek` as a custody envelope of `purpose`.
pub fn seal_sym(
    purpose: Purpose,
    vault: CustodyVaultId,
    key_id: &[u8],
    recipient: &[u8],
    kek: &Kek,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let params = SealParams {
        suite: AEAD,
        purpose,
        epoch: CRYPTO_EPOCH,
        key_id,
        recipient,
        vault_id: vault.as_bytes(),
    };
    seal(&params, SealKey::SymmetricKek(kek), plaintext, &mut SysRng)
        .map(|envelope| envelope.to_bytes())
        .map_err(|error| seal_refused(&error))
}

/// Why a custody envelope did not seal, by the crypto error's kind: a fixed
/// reason, never the error's values or a key's bytes.
pub fn seal_refused(error: &oneiron_crypto::Error) -> Error {
    use oneiron_crypto::Error as Crypto;
    crate::key_material::refused(match error {
        Crypto::FieldLength {
            field: "key_id" | "recipient" | "vault_id",
            ..
        } => "sealing key custody failed: an envelope id is out of range",
        Crypto::FieldLength {
            field: "plaintext" | "ciphertext",
            ..
        } => "sealing key custody failed: the plaintext is out of range",
        Crypto::Rng => "sealing key custody failed: the random source failed",
        Crypto::UnknownSuite(_)
        | Crypto::ForbiddenSuite(_)
        | Crypto::ReservedSuite(_)
        | Crypto::WrongSuiteKind { .. }
        | Crypto::SuiteNotAccepted(_)
        | Crypto::EpochBelowSuiteMinimum { .. }
        | Crypto::EpochBelowPolicyMinimum { .. } => {
            "sealing key custody failed: the suite or epoch was refused"
        }
        Crypto::KemKeyRejected => "sealing key custody failed: the key encapsulation was refused",
        Crypto::Primitive(_) => "sealing key custody failed: a crypto primitive failed",
        _ => "sealing key custody failed",
    })
}

/// Opens a custody envelope [`seal_sym`] sealed, refused unless every bound
/// field matches.
pub fn open_sym(
    purpose: Purpose,
    vault: CustodyVaultId,
    key_id: &[u8],
    recipient: &[u8],
    kek: &Kek,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let policy = OpenPolicy {
        purpose,
        vault_id: vault.as_bytes(),
        recipient,
        key_id,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: CRYPTO_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    Envelope::parse(envelope)
        .map_err(|_| log_corrupt())?
        .open(OpenKey::SymmetricKek(kek), &policy)
        .map_err(|error| open_refused(&error))
}

/// Why a custody envelope did not open, by the crypto error's kind (FIX
/// 6780): only a failed authentication is the wrong key; every other cause
/// names itself. A fixed reason, never the error's values, a key's bytes or
/// the envelope's.
fn open_refused(error: &oneiron_crypto::Error) -> Error {
    use oneiron_crypto::Error as Crypto;
    crate::key_material::refused(match error {
        Crypto::OpenFailed => "key custody does not open with this key",
        Crypto::FieldLength { .. }
        | Crypto::Truncated { .. }
        | Crypto::TrailingBytes { .. }
        | Crypto::NonCanonical => "opening key custody failed: a field is out of range",
        Crypto::PurposeMismatch { .. }
        | Crypto::VaultMismatch
        | Crypto::RecipientMismatch
        | Crypto::KeyIdMismatch => {
            "opening key custody failed: the envelope is bound to another place"
        }
        Crypto::UnknownSuite(_)
        | Crypto::ForbiddenSuite(_)
        | Crypto::ReservedSuite(_)
        | Crypto::WrongSuiteKind { .. }
        | Crypto::SuiteNotAccepted(_)
        | Crypto::EpochBelowSuiteMinimum { .. }
        | Crypto::EpochBelowPolicyMinimum { .. } => {
            "opening key custody failed: the suite or epoch was refused"
        }
        Crypto::WrongKeyForWrap { .. } | Crypto::WrapNotAccepted(_) => {
            "opening key custody failed: the wrap type was refused"
        }
        Crypto::Primitive(_) => "opening key custody failed: a crypto primitive failed",
        _ => "opening key custody failed",
    })
}

/// A frame's envelope recipient: a 32-byte commitment to its whole clear
/// header, which the frame carries as it is, so every header byte stays
/// bound and the recipient fits an envelope (FIX 6769).
pub fn frame_recipient(clear: &[u8; FRAME_HEADER_LEN]) -> [u8; 32] {
    blake3::derive_key(FRAME_RECIPIENT_CONTEXT, clear)
}

pub fn frame_name(seq: u64) -> String {
    format!("f{seq:016x}")
}

pub fn parse_tip(bytes: &[u8]) -> Option<(u64, [u8; 32])> {
    if bytes.len() != 40 {
        return None;
    }
    Some((
        u64::from_be_bytes(bytes[..8].try_into().ok()?),
        bytes[8..].try_into().ok()?,
    ))
}
