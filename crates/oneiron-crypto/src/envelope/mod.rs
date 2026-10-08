//! The sealed envelope: its typed header, the canonical encoding and the strict
//! parser. Sealing and opening live in `seal`; the hybrid combiner in `hybrid`.

mod hybrid;
mod seal;

pub use self::seal::{OpenKey, OpenPolicy, SealKey, SealParams, seal};

use crate::codec::{Reader, check_len, put_lp8};
use crate::error::{Error, Result};
use crate::keys::{Argon2Cost, MLKEM1024_CIPHERTEXT_LEN};
use crate::suite::{Suite, SuiteId, SuiteKind};
use crate::{MAX_ID_LEN, MAX_PLAINTEXT_LEN, TAG_LEN};

const MAGIC: &[u8; 4] = b"ONEV";
/// The canonical encoding version this build writes and reads.
const VERSION: u16 = 1;
const KDF_SALT_LEN: usize = 32;
const SHARE_SET_ID_LEN: usize = 16;
/// Most shares a Shamir share set may have.
const MAX_SHARES: u8 = 16;

/// How the payload key is wrapped. Wire form: one byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WrapType {
    /// A local 256-bit key-encryption key (PQC-1 B).
    SymmetricKek = 1,
    /// A KEK derived from a user passphrase with Argon2id.
    Passphrase = 2,
    /// A KEK held by the platform keystore (Keychain, Secure Enclave, OS keystore).
    DeviceKeystore = 3,
    /// A KEK derived by the platform from a passkey (for example a WebAuthn PRF output).
    Passkey = 4,
    /// A KEK recovered from a Shamir share set (the recovery kit).
    ShamirRecovery = 5,
    /// A hybrid X25519 + ML-KEM-1024 capsule for another party's public key (PQC-3 B).
    HybridCapsule = 6,
}

impl WrapType {
    fn from_wire(byte: u8) -> Result<Self> {
        Ok(match byte {
            1 => Self::SymmetricKek,
            2 => Self::Passphrase,
            3 => Self::DeviceKeystore,
            4 => Self::Passkey,
            5 => Self::ShamirRecovery,
            6 => Self::HybridCapsule,
            other => return Err(Error::UnknownWrap(other)),
        })
    }
}

/// What the sealed payload is for. Wire form: big-endian `u16`. A reader states the
/// purpose it expects; any other purpose is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Purpose {
    VaultDek = 1,
    RecoveryKek = 2,
    CheckpointArtifact = 3,
    BackupArtifact = 4,
    ExportBundle = 5,
    SecretFile = 6,
    DeviceSigningSeed = 7,
    FederationGrant = 8,
    GuestShare = 9,
    EscrowRecipient = 10,
}

impl Purpose {
    fn from_wire(value: u16) -> Result<Self> {
        Ok(match value {
            1 => Self::VaultDek,
            2 => Self::RecoveryKek,
            3 => Self::CheckpointArtifact,
            4 => Self::BackupArtifact,
            5 => Self::ExportBundle,
            6 => Self::SecretFile,
            7 => Self::DeviceSigningSeed,
            8 => Self::FederationGrant,
            9 => Self::GuestShare,
            10 => Self::EscrowRecipient,
            other => return Err(Error::UnknownPurpose(other)),
        })
    }
}

/// The KDF that turns the wrap secret into the payload AEAD key, with its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kdf {
    /// `hkdf-sha256-v1` (id 1): HKDF-SHA256 over the wrap secret with a fresh salt.
    HkdfSha256 { salt: [u8; 32] },
    /// `argon2id-hkdf-sha256-v1` (id 2): Argon2id v0x13 (32-byte output) over the
    /// passphrase, then the same HKDF-SHA256 step with the same salt.
    Argon2idHkdfSha256 { cost: Argon2Cost, salt: [u8; 32] },
}

impl Kdf {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::HkdfSha256 { .. } => "hkdf-sha256-v1",
            Self::Argon2idHkdfSha256 { .. } => "argon2id-hkdf-sha256-v1",
        }
    }

    pub(crate) fn salt(&self) -> &[u8; 32] {
        match self {
            Self::HkdfSha256 { salt } | Self::Argon2idHkdfSha256 { salt, .. } => salt,
        }
    }

    /// The closed KDF/wrap matrix: Argon2id only for passphrases, HKDF for the rest.
    fn check_wrap(&self, wrap: WrapType) -> Result<()> {
        let passphrase = wrap == WrapType::Passphrase;
        match (self, passphrase) {
            (Self::Argon2idHkdfSha256 { cost, .. }, true) => cost.check(),
            (Self::HkdfSha256 { .. }, false) => Ok(()),
            _ => Err(Error::KdfWrapMismatch {
                wrap,
                kdf: self.name(),
            }),
        }
    }
}

/// Parameters that belong to one wrap type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WrapParams {
    /// Symmetric, passphrase, keystore and passkey wraps carry none.
    None,
    /// The share set the recovery secret came from.
    Shamir {
        threshold: u8,
        shares: u8,
        share_set_id: [u8; 16],
    },
    /// The capsule: KEM suite, X25519 ephemeral public key, ML-KEM-1024 ciphertext.
    Hybrid {
        kem_suite: SuiteId,
        x25519_ephemeral: [u8; 32],
        mlkem_ciphertext: Box<[u8; 1568]>,
    },
}

impl WrapParams {
    fn check(&self, wrap: WrapType, epoch: u64) -> Result<()> {
        match (wrap, self) {
            (
                WrapType::ShamirRecovery,
                Self::Shamir {
                    threshold, shares, ..
                },
            ) => {
                if *threshold < 2 || threshold > shares || *shares > MAX_SHARES {
                    return Err(Error::ShamirParamsInvalid {
                        threshold: *threshold,
                        shares: *shares,
                    });
                }
                Ok(())
            }
            (WrapType::HybridCapsule, Self::Hybrid { kem_suite, .. }) => {
                Suite::require(*kem_suite, &[SuiteKind::Kem], epoch).map(|_| ())
            }
            (WrapType::ShamirRecovery | WrapType::HybridCapsule, _)
            | (_, Self::Shamir { .. } | Self::Hybrid { .. }) => {
                Err(Error::WrongKeyForWrap { wrap })
            }
            (_, Self::None) => Ok(()),
        }
    }
}

/// The authenticated envelope header. Every field is bound into the AEAD associated
/// data (the exact canonical header bytes) and into the payload key derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The payload AEAD suite.
    pub suite: SuiteId,
    pub wrap: WrapType,
    pub purpose: Purpose,
    /// The crypto epoch the envelope was sealed at. Never 0.
    pub epoch: u64,
    /// The id of the wrapping key (KEK id or recipient key id), 1..=64 bytes.
    pub key_id: Vec<u8>,
    /// Who can open it, 1..=64 bytes.
    pub recipient: Vec<u8>,
    /// The vault the payload belongs to, 1..=64 bytes.
    pub vault_id: Vec<u8>,
    pub kdf: Kdf,
    pub wrap_params: WrapParams,
    /// Random, of the suite's nonce length.
    pub nonce: Vec<u8>,
    /// Plaintext length plus the 16-byte tag.
    pub ciphertext_len: u32,
}

impl Header {
    /// Every check that does not need a key: suite table, epoch, lengths, matrices.
    fn validate(&self) -> Result<()> {
        let suite = Suite::require(self.suite, &[SuiteKind::Aead], self.epoch)?;
        check_len("key_id", self.key_id.len(), 1, MAX_ID_LEN)?;
        check_len("recipient", self.recipient.len(), 1, MAX_ID_LEN)?;
        check_len("vault_id", self.vault_id.len(), 1, MAX_ID_LEN)?;
        self.kdf.check_wrap(self.wrap)?;
        self.wrap_params.check(self.wrap, self.epoch)?;
        check_len(
            "nonce",
            self.nonce.len(),
            suite.nonce_len(),
            suite.nonce_len(),
        )?;
        check_len(
            "ciphertext",
            self.ciphertext_len as usize,
            TAG_LEN,
            MAX_PLAINTEXT_LEN + TAG_LEN,
        )
    }

    /// The canonical header bytes (the AAD). Callers have validated the header.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.suite.0.to_be_bytes());
        out.push(self.wrap as u8);
        out.extend_from_slice(&(self.purpose as u16).to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        put_lp8(&mut out, &self.key_id);
        put_lp8(&mut out, &self.recipient);
        put_lp8(&mut out, &self.vault_id);
        match &self.kdf {
            Kdf::HkdfSha256 { salt } => {
                out.push(1);
                out.extend_from_slice(salt);
            }
            Kdf::Argon2idHkdfSha256 { cost, salt } => {
                out.push(2);
                out.extend_from_slice(&cost.m_kib.to_be_bytes());
                out.extend_from_slice(&cost.t.to_be_bytes());
                out.push(cost.p);
                out.extend_from_slice(salt);
            }
        }
        match &self.wrap_params {
            WrapParams::None => {}
            WrapParams::Shamir {
                threshold,
                shares,
                share_set_id,
            } => {
                out.push(*threshold);
                out.push(*shares);
                out.extend_from_slice(share_set_id);
            }
            WrapParams::Hybrid {
                kem_suite,
                x25519_ephemeral,
                mlkem_ciphertext,
            } => {
                out.extend_from_slice(&kem_suite.0.to_be_bytes());
                out.extend_from_slice(x25519_ephemeral);
                out.extend_from_slice(&mlkem_ciphertext[..]);
            }
        }
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext_len.to_be_bytes());
        out
    }

    /// Reads and validates a header, field by field, refusing at the first bad field.
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        if r.take(MAGIC.len(), "magic")? != MAGIC {
            return Err(Error::BadMagic {
                expected: "envelope",
            });
        }
        let version = r.u16("version")?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let suite_id = SuiteId(r.u16("suite")?);
        let suite = Suite::require(suite_id, &[SuiteKind::Aead], u64::MAX)?;
        let wrap = WrapType::from_wire(r.u8("wrap")?)?;
        let purpose = Purpose::from_wire(r.u16("purpose")?)?;
        let epoch = r.u64("epoch")?;
        Suite::require(suite_id, &[SuiteKind::Aead], epoch)?;
        let key_id = r.lp8("key_id", 1, MAX_ID_LEN)?.to_vec();
        let recipient = r.lp8("recipient", 1, MAX_ID_LEN)?.to_vec();
        let vault_id = r.lp8("vault_id", 1, MAX_ID_LEN)?.to_vec();
        let kdf = match r.u8("kdf")? {
            1 => Kdf::HkdfSha256 {
                salt: r.array::<KDF_SALT_LEN>("kdf salt")?,
            },
            2 => {
                let m_kib = r.u32("argon2id m_kib")?;
                let t = r.u32("argon2id t")?;
                let p = r.u8("argon2id p")?;
                let salt = r.array::<KDF_SALT_LEN>("kdf salt")?;
                Kdf::Argon2idHkdfSha256 {
                    cost: Argon2Cost { m_kib, t, p },
                    salt,
                }
            }
            other => return Err(Error::UnknownKdf(other)),
        };
        kdf.check_wrap(wrap)?;
        let wrap_params = match wrap {
            WrapType::ShamirRecovery => WrapParams::Shamir {
                threshold: r.u8("shamir threshold")?,
                shares: r.u8("shamir shares")?,
                share_set_id: r.array::<SHARE_SET_ID_LEN>("shamir share_set_id")?,
            },
            WrapType::HybridCapsule => {
                let kem_suite = SuiteId(r.u16("kem suite")?);
                Suite::require(kem_suite, &[SuiteKind::Kem], epoch)?;
                let x25519_ephemeral = r.array::<32>("x25519 ephemeral")?;
                let mut mlkem_ciphertext = Box::new([0u8; MLKEM1024_CIPHERTEXT_LEN]);
                mlkem_ciphertext
                    .copy_from_slice(r.take(MLKEM1024_CIPHERTEXT_LEN, "mlkem ciphertext")?);
                WrapParams::Hybrid {
                    kem_suite,
                    x25519_ephemeral,
                    mlkem_ciphertext,
                }
            }
            _ => WrapParams::None,
        };
        let nonce = r.take(suite.nonce_len(), "nonce")?.to_vec();
        let ciphertext_len = r.u32("ciphertext_len")?;
        let header = Self {
            suite: suite_id,
            wrap,
            purpose,
            epoch,
            key_id,
            recipient,
            vault_id,
            kdf,
            wrap_params,
            nonce,
            ciphertext_len,
        };
        header.validate()?;
        Ok(header)
    }
}

/// A parsed or freshly sealed envelope. Only [`Envelope::parse`] and [`seal`] build
/// one, so its header has passed every key-free check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    header: Header,
    header_bytes: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Envelope {
    /// Strict parse: magic, version, suite table, epoch floor, every length bound,
    /// the KDF/wrap matrix, exact consumption. Runs no KDF and no cipher.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let header = Header::decode(&mut r)?;
        let header_bytes = bytes[..r.position()].to_vec();
        let ciphertext = r
            .take(header.ciphertext_len as usize, "ciphertext")?
            .to_vec();
        r.finish()?;
        Ok(Self {
            header,
            header_bytes,
            ciphertext,
        })
    }

    /// The canonical bytes: header, then ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_bytes.len() + self.ciphertext.len());
        out.extend_from_slice(&self.header_bytes);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// The authenticated header (authentic only after a successful open).
    pub fn header(&self) -> &Header {
        &self.header
    }
}
